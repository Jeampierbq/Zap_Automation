import os
import re
import base64
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# Utilidades de texto
# ─────────────────────────────────────────────────────────────
def limpiar_html(texto):
    if not texto:
        return "N/A"
    texto = re.sub(r'<br\s*/?>', '\n', texto, flags=re.IGNORECASE)
    texto = re.sub(r'</p>', '\n', texto, flags=re.IGNORECASE)
    texto = re.sub(r'<[^>]+>', '', texto)
    texto = texto.replace('&lt;','<').replace('&gt;','>') \
                 .replace('&amp;','&').replace('&nbsp;',' ') \
                 .replace('&#39;',"'").replace('&quot;','"')
    texto = re.sub(r'\n{3,}', '\n\n', texto)
    return texto.strip() or "N/A"

# ─────────────────────────────────────────────────────────────
# Extractor de datos técnicos concretos desde instances
# ─────────────────────────────────────────────────────────────
def _tecnico_de_instancias(alerta):
    """
    Extrae datos técnicos concretos (tecnología, versión, cookie) de las
    instances. Solo agrega lo que NO está ya en otherinfo/desc. No muestra
    código crudo — solo valores limpios con etiqueta clara.
    """
    def limpiar_campo(html):
        return re.sub(r'<[^>]+>', ' ', str(html)).strip()

    # Todo lo ya cubierto por desc + otherinfo — no repetir
    ya_cubierto = (
        limpiar_campo(alerta.get('otherinfo', '')) + ' ' +
        limpiar_campo(alerta.get('desc', ''))
    ).lower()

    # Nombre de la vuln para contextualizar
    nombre_vuln = (alerta.get('name','') or alerta.get('alert','')).lower()

    tecnologia  = set()
    cookies     = set()
    lib_externa = set()

    # Params que son cabeceras HTTP (redundante con el nombre de la vuln)
    SKIP_PARAMS_HEADER = {
        'content-security-policy', 'x-content-type-options',
        'x-frame-options', 'content-security-policy-report-only',
        'v', '',
    }

    for inst in alerta.get('instances', []):
        param = limpiar_campo(inst.get('param', ''))
        ev    = limpiar_campo(inst.get('evidence', ''))

        # ── evidence: X-Powered-By → Tecnología detectada ────
        m = re.match(r'^X-Powered-By:\s*(.+)$', ev, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if val.lower() not in ya_cubierto:
                tecnologia.add(val)

        # ── evidence: Set-Cookie → Cookie afectada (solo nombre) ─
        m = re.match(r'^Set-Cookie:\s*([^=;\s]+)', ev, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if val.lower() not in ya_cubierto:
                cookies.add(val)

        # ── param: nombre de cookie (solo en vulns de cookie) ────
        if ('cookie' in nombre_vuln
                and param
                and param.lower() not in SKIP_PARAMS_HEADER
                and not param.startswith('http')
                and re.match(r'^[a-zA-Z][a-zA-Z0-9_\-\.]+$', param)
                and param.lower() not in ya_cubierto):
            cookies.add(param)

        # ── param: URL de librería JS externa → Librería externa ─
        if param.startswith('http') and re.search(r'/libs?/|/vendor/|googleapis|cdnjs', param, re.IGNORECASE):
            m = re.search(r'/([a-zA-Z][\w\-]+)/(\d+\.\d+[\.\d]*)', param)
            if m:
                val = f'{m.group(1)} {m.group(2)}'
                if val.lower() not in ya_cubierto:
                    lib_externa.add(val)

    lineas = []
    if tecnologia:
        lineas.append('Tecnología detectada: ' + ', '.join(sorted(tecnologia)))
    if cookies:
        lineas.append('Cookie afectada: ' + ', '.join(sorted(cookies)))
    if lib_externa:
        lineas.append('Librería externa: ' + ', '.join(sorted(lib_externa)))
    return '\n'.join(lineas)

# ─────────────────────────────────────────────────────────────
# Constantes de riesgo / confianza
# ─────────────────────────────────────────────────────────────
RIESGO_LABEL = {'3':'Alto','2':'Medio','1':'Bajo','0':'Informativo'}
RIESGO_COLOR = {
    '3': RGBColor(0xC0,0x00,0x00),
    '2': RGBColor(0xED,0x7D,0x31),
    '1': RGBColor(0x00,0x70,0xC0),
    '0': RGBColor(0x44,0x72,0xC4),
}
RIESGO_BG = {'3':'FFDADA','2':'FFE8CC','1':'DAEEF3','0':'DAE8FC'}
CONF_LABEL = {'4':'Confirmada','3':'Alta','2':'Media','1':'Baja','0':'Falso Positivo'}

def riesgo_label(c): return RIESGO_LABEL.get(str(c), str(c))
def riesgo_color(c): return RIESGO_COLOR.get(str(c), RGBColor(0x88,0x88,0x88))
def riesgo_bg(c):    return RIESGO_BG.get(str(c), 'FFFFFF')
def conf_label(c):   return CONF_LABEL.get(str(c), str(c))
def cwe_texto(cweid):
    if not cweid or cweid in ('-1', '0', 'N/A'):
        return "N/A"
    s = str(cweid).strip()
    # Evitar duplicar el prefijo si ya viene con "CWE-"
    if s.upper().startswith("CWE-"):
        return s
    return f"CWE-{s}"

# ─────────────────────────────────────────────────────────────
# Contador global de tablas y figuras (APA 7 — nunca se reinicia)
# ─────────────────────────────────────────────────────────────
class _Contador:
    """
    Contador global de tablas y figuras para un documento.
    Se instancia UNA sola vez por documento y se pasa a todas las funciones.
    Garantiza numeración continua independiente de secciones.
    """
    def __init__(self):
        self.tabla  = 0
        self.figura = 0

    def sig_tabla(self):
        self.tabla += 1
        return self.tabla

    def sig_figura(self):
        self.figura += 1
        return self.figura

# ─────────────────────────────────────────────────────────────
# Gráfico de barras
# ─────────────────────────────────────────────────────────────
def generar_grafico_barras(counts):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches

        categorias = ['Alto', 'Medio', 'Bajo']
        valores    = [counts['Alto'], counts['Medio'], counts['Bajo']]
        colores    = ['#C00000', '#ED7D31', '#0070C0']

        fig, ax = plt.subplots(figsize=(6, 3))
        fig.patch.set_facecolor('#ffffff')
        ax.set_facecolor('#ffffff')

        bars = ax.bar(categorias, valores, color=colores, width=0.5)
        for bar, val in zip(bars, valores):
            if val > 0:
                ax.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    bar.get_height() + 0.05,
                    str(val), ha='center', va='bottom',
                    color='black', fontsize=9, fontweight='bold'
                )

        tope = max(valores) if max(valores) > 0 else 1
        ax.set_ylim(0, tope * 1.3 + 0.5)
        ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
        for spine in ['bottom', 'left']:
            ax.spines[spine].set_color('black')
        for spine in ['top', 'right']:
            ax.spines[spine].set_visible(False)
        ax.tick_params(axis='both', colors='black', labelsize=9)

        legend_patch = mpatches.Patch(color='red', label='Alert Chart')
        ax.legend(handles=[legend_patch], facecolor='#ffffff',
                  edgecolor='#cccccc', labelcolor='black',
                  loc='upper right', fontsize=8)

        plt.tight_layout(pad=0.5)
        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=110,
                    bbox_inches='tight', facecolor='#ffffff')
        plt.close(fig)
        buf.seek(0)
        return buf
    except Exception:
        return None

def _envolver_en_bookmark(run, nombre):
    """Coloca bookmarkStart antes del run y bookmarkEnd después (mismo párrafo).

    Permite que el paso de Word (win32com) localice la imagen y la reemplace por
    un gráfico nativo editable.
    """
    bid = str(abs(hash(nombre)) % 100000)
    bs = OxmlElement('w:bookmarkStart'); bs.set(qn('w:id'), bid); bs.set(qn('w:name'), nombre)
    be = OxmlElement('w:bookmarkEnd');   be.set(qn('w:id'), bid)
    run._r.addprevious(bs)
    run._r.addnext(be)


def _insertar_figura(doc, grafico_buf, contador, titulo, ancho=Inches(4.5), bookmark=None):
    """Inserta imagen + caption 'Figura N  titulo' (APA 7: caption debajo).

    Si se indica `bookmark`, la imagen queda marcada para que Word la reemplace
    por un gráfico de barras nativo editable (ver _actualizar_toc_con_word).
    """
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(8)
    p_img.paragraph_format.space_after  = Pt(2)
    run_img = p_img.add_run()
    run_img.add_picture(grafico_buf, width=ancho)
    if bookmark:
        _envolver_en_bookmark(run_img, bookmark)

    num = contador.sig_figura() if contador else 1
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(0)
    p_cap.paragraph_format.space_after  = Pt(8)
    r = p_cap.add_run(f"Figura {num}  {titulo}")
    r.font.name = 'Century Gothic'; r.font.size = Pt(11)
    r.font.italic = True
    r.font.color.rgb = RGBColor(0x44, 0x44, 0x44)

# ─────────────────────────────────────────────────────────────
# Helpers de formato de celda
# ─────────────────────────────────────────────────────────────
def set_shading(celda, hex_color):
    tc = celda._tc
    tcPr = tc.get_or_add_tcPr()
    for shd in tcPr.findall(qn('w:shd')):
        tcPr.remove(shd)
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    tcPr.append(shd)

def set_borders(celda):
    tc = celda._tc
    tcPr = tc.get_or_add_tcPr()
    for b in tcPr.findall(qn('w:tcBorders')):
        tcPr.remove(b)
    tcBorders = OxmlElement('w:tcBorders')
    for lado in ['top','left','bottom','right']:
        borde = OxmlElement(f'w:{lado}')
        borde.set(qn('w:val'), 'single')
        borde.set(qn('w:sz'), '4')
        borde.set(qn('w:color'), 'CCCCCC')
        tcBorders.append(borde)
    tcPr.append(tcBorders)

def escribir_celda(celda, texto, bold=False, color=None,
                   size=11, bg=None, align=WD_ALIGN_PARAGRAPH.LEFT):
    if bg:
        set_shading(celda, bg)
    set_borders(celda)
    celda.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
    for p in celda.paragraphs:
        p.clear()
    p = celda.paragraphs[0]
    p.alignment = align
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after  = Pt(3)
    p.paragraph_format.left_indent  = Pt(4)
    lineas = str(texto or 'N/A').split('\n')
    primero = True
    for linea in lineas:
        linea = linea.strip()
        if not linea:
            continue
        if not primero:
            run_br = p.add_run()
            run_br.add_break()
        run = p.add_run(linea)
        run.font.name  = 'Century Gothic'
        run.font.size  = Pt(size)
        run.font.bold  = bold
        if color:
            run.font.color.rgb = color
        primero = False

def agregar_titulo_seccion(doc, texto, size=13, color=RGBColor(0,0,0)):
    if size >= 13:
        style = 'Heading 1'
    elif size == 12:
        style = 'Heading 2'
    else:
        style = 'Heading 3'
    p = doc.add_paragraph(style=style)
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after  = Pt(6)
    run = p.add_run(texto)
    run.font.name  = 'Century Gothic'
    run.font.size  = Pt(size)
    run.font.bold  = True
    run.font.color.rgb = color

def agregar_linea_separadora(doc):
    pass  # líneas horizontales eliminadas


# ─────────────────────────────────────────────────────────────
# Tabla resumen (CAMBIO 2: Arial 11 en todas las celdas)
# ─────────────────────────────────────────────────────────────
def crear_tabla_resumen(doc, alertas, contador=None):
    headers = ['#', 'Nombre del Hallazgo', 'Riesgo', 'Confianza', 'CWE']
    anchos  = [Inches(0.35), Inches(3.5), Inches(1.1), Inches(1.0), Inches(0.9)]
    tabla   = doc.add_table(rows=1, cols=5)
    tabla.style = 'Table Grid'
    for i, (h, ancho) in enumerate(zip(headers, anchos)):
        c = tabla.cell(0, i)
        c.width = ancho
        escribir_celda(c, h, bold=True, size=11,
                       color=RGBColor(0xFF,0xFF,0xFF),
                       bg='1F3864',
                       align=WD_ALIGN_PARAGRAPH.CENTER)
    for idx, alerta in enumerate(alertas):
        bg_fila = 'F5F5F5' if idx % 2 == 0 else 'FFFFFF'
        fila = tabla.add_row().cells
        for i, (dato, ancho) in enumerate(zip([
            str(idx+1),
            alerta.get('name') or alerta.get('alert',''),
            riesgo_label(alerta.get('riskcode','0')),
            conf_label(alerta.get('confidence','0')),
            cwe_texto(alerta.get('cweid','-1')),
        ], anchos)):
            fila[i].width = ancho
            if i == 2:
                escribir_celda(fila[i], dato, size=11,
                               color=riesgo_color(alerta.get('riskcode','0')),
                               bold=True,
                               bg=riesgo_bg(alerta.get('riskcode','0')),
                               align=WD_ALIGN_PARAGRAPH.CENTER)
            elif i == 0:
                escribir_celda(fila[i], dato, size=11, bg=bg_fila,
                               align=WD_ALIGN_PARAGRAPH.CENTER)
            else:
                escribir_celda(fila[i], dato, size=11, bg=bg_fila)

    # Caption global APA 7
    num_tabla = contador.sig_tabla() if contador else 1
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(2)
    p_cap.paragraph_format.space_after  = Pt(10)
    r_cap = p_cap.add_run(f"Tabla {num_tabla}  Tabla de Hallazgos")
    r_cap.font.name = 'Century Gothic'; r_cap.font.size = Pt(11)
    r_cap.font.italic = True
    r_cap.font.color.rgb = RGBColor(0x44, 0x44, 0x44)

# ─────────────────────────────────────────────────────────────
# Tabla global de hallazgos únicos (deduplicada por nombre)
# ─────────────────────────────────────────────────────────────
def _tabla_hallazgos_global(doc, lista_sitios, contador):
    """Inserta tabla con todos los hallazgos únicos de todas las URLs sin repetir."""
    # Deduplicar por nombre; en caso de duplicado, mantener el de mayor riskcode
    vistos = {}
    for _, alertas in lista_sitios:
        for a in alertas:
            nombre = (a.get('name') or a.get('alert', '')).strip()
            if not nombre:
                continue
            rc_nuevo = int(a.get('riskcode', 0))
            if nombre not in vistos or rc_nuevo > int(vistos[nombre].get('riskcode', 0)):
                vistos[nombre] = a

    alertas_unicas = sorted(vistos.values(), key=lambda x: -int(x.get('riskcode', 0)))
    if not alertas_unicas:
        return

    headers = ['#', 'Nombre del Hallazgo', 'Riesgo', 'CWE']
    anchos  = [Inches(0.4), Inches(4.1), Inches(1.15), Inches(1.15)]
    tabla   = doc.add_table(rows=1, cols=4)
    tabla.style = 'Table Grid'

    for i, (h, ancho) in enumerate(zip(headers, anchos)):
        c = tabla.cell(0, i)
        c.width = ancho
        escribir_celda(c, h, bold=True, size=11,
                       color=RGBColor(0xFF, 0xFF, 0xFF),
                       bg='1F3864',
                       align=WD_ALIGN_PARAGRAPH.CENTER)

    for idx, alerta in enumerate(alertas_unicas):
        bg_fila = 'F5F5F5' if idx % 2 == 0 else 'FFFFFF'
        fila = tabla.add_row().cells
        datos = [
            str(idx + 1),
            alerta.get('name') or alerta.get('alert', ''),
            riesgo_label(alerta.get('riskcode', '0')),
            cwe_texto(alerta.get('cweid', '-1')),
        ]
        for i, (dato, ancho) in enumerate(zip(datos, anchos)):
            fila[i].width = ancho
            if i == 2:
                escribir_celda(fila[i], dato, size=11,
                               color=riesgo_color(alerta.get('riskcode', '0')),
                               bold=True,
                               bg=riesgo_bg(alerta.get('riskcode', '0')),
                               align=WD_ALIGN_PARAGRAPH.CENTER)
            elif i == 0:
                escribir_celda(fila[i], dato, size=11, bg=bg_fila,
                               align=WD_ALIGN_PARAGRAPH.CENTER)
            else:
                escribir_celda(fila[i], dato, size=11, bg=bg_fila)

    num_tabla = contador.sig_tabla() if contador else 1
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(2)
    p_cap.paragraph_format.space_after  = Pt(10)
    r_cap = p_cap.add_run(f"Tabla {num_tabla}  Consolidado de Hallazgos Únicos")
    r_cap.font.name = 'Century Gothic'; r_cap.font.size = Pt(11)
    r_cap.font.italic = True
    r_cap.font.color.rgb = RGBColor(0x44, 0x44, 0x44)


# ─────────────────────────────────────────────────────────────
# Tabla detalle de hallazgo (Arial 11, sin Solucion)
# ─────────────────────────────────────────────────────────────
def crear_tabla_hallazgo(doc, alerta, indice, url_sitio='', contador=None):
    nombre = alerta.get('name') or alerta.get('alert','')
    urls   = '\n'.join(
        i.get('uri','') for i in alerta.get('instances',[])
        if i.get('uri','')
    )
    # Si no hay URIs en instances, usar la URL del sitio como fallback
    if not urls and url_sitio:
        urls = url_sitio

    COLOR_ETIQ = {'3': 'C00000', '2': 'ED7D31', '1': '0070C0'}.get(
        str(alerta.get('riskcode', '1')), '2E5596'
    )
    FS = 11

    tabla = doc.add_table(rows=0, cols=2)
    tabla.style = 'Table Grid'

    def _label_valor(label, valor, v_color=None, v_bold=False, v_bg='FFFFFF'):
        fila = tabla.add_row().cells
        fila[0].width = Inches(1.5)
        fila[1].width = Inches(5.4)
        escribir_celda(fila[0], label, bold=True, size=FS,
                       color=RGBColor(0xFF,0xFF,0xFF), bg=COLOR_ETIQ)
        escribir_celda(fila[1], valor, bold=v_bold, size=FS,
                       color=v_color, bg=v_bg)

    def _cabecera_full(texto):
        fila = tabla.add_row().cells
        fila[0].merge(fila[1])
        escribir_celda(fila[0], texto, bold=True, size=FS,
                       color=RGBColor(0xFF,0xFF,0xFF), bg=COLOR_ETIQ)

    def _contenido_full(texto):
        fila = tabla.add_row().cells
        fila[0].merge(fila[1])
        escribir_celda(fila[0], texto, size=FS, bg='FFFFFF')

    _label_valor('Nombre',    f"Hallazgo #{indice+1}: {nombre}")
    _label_valor('Confianza', conf_label(alerta.get('confidence','0')))
    _label_valor('CWE',       cwe_texto(alerta.get('cweid','-1')))
    _label_valor(
        'Severidad',
        riesgo_label(alerta.get('riskcode','0')),
        v_color=riesgo_color(alerta.get('riskcode','0')),
        v_bold=True,
        v_bg='FFFFFF',   # fondo blanco, solo texto coloreado (igual que la imagen)
    )
    _cabecera_full('Descripcion')
    desc_texto     = limpiar_html(alerta.get('desc', ''))
    otherinfo_texto = limpiar_html(alerta.get('otherinfo', ''))
    tecnico_texto  = _tecnico_de_instancias(alerta)
    if otherinfo_texto and otherinfo_texto != 'N/A':
        desc_texto = desc_texto + '\n\n' + otherinfo_texto if desc_texto else otherinfo_texto
    if tecnico_texto:
        desc_texto = desc_texto + '\n\n' + tecnico_texto if desc_texto else tecnico_texto
    _contenido_full(desc_texto)
    _cabecera_full('URL afectadas')
    _contenido_full(urls or 'N/A')
    evidencias = list(dict.fromkeys(
        i.get('evidence', '').strip()
        for i in alerta.get('instances', [])
        if i.get('evidence', '').strip()
    ))
    if evidencias:
        _cabecera_full('Evidencia')
        _contenido_full('\n'.join(evidencias))
    _cabecera_full('Recomendacion')
    _contenido_full(limpiar_html(alerta.get('solution','')) or 'N/A')

    # Pie de tabla — numeración global APA 7
    num_tabla = contador.sig_tabla() if contador else indice + 1
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(2)
    p_cap.paragraph_format.space_after  = Pt(10)
    r_cap = p_cap.add_run(f"Tabla {num_tabla}  Detalles de vulnerabilidad")
    r_cap.font.name    = 'Century Gothic'
    r_cap.font.size    = Pt(11)
    r_cap.font.italic  = True
    r_cap.font.color.rgb = RGBColor(0x44,0x44,0x44)



# ─────────────────────────────────────────────────────────────
# Contenido de UNA URL dentro del consolidado
# (sin portada individual, sin índice propio)
# ─────────────────────────────────────────────────────────────
def _agregar_contenido_url(doc, sitio, alertas, num_seccion, contador=None):
    dominio = urlparse(sitio).netloc + urlparse(sitio).path.rstrip('/')

    agregar_titulo_seccion(doc, f'5.{num_seccion} Hallazgos #{num_seccion}: {dominio}', size=13)
    agregar_linea_separadora(doc)

    if not alertas:
        p_v = doc.add_paragraph()
        rv = p_v.add_run('No se encontraron vulnerabilidades relevantes.')
        rv.font.name = 'Century Gothic'; rv.font.size = Pt(11); rv.font.italic = True
        rv.font.color.rgb = RGBColor(0x66,0x66,0x66)
    else:
        agregar_titulo_seccion(doc, f'5.{num_seccion}.1 Tabla de Hallazgos', size=12)
        crear_tabla_resumen(doc, alertas, contador=contador)

        agregar_titulo_seccion(doc, f'5.{num_seccion}.2 Detalle de Hallazgos', size=12)
        for i, alerta in enumerate(alertas):
            crear_tabla_hallazgo(doc, alerta, i, url_sitio=sitio, contador=contador)
            doc.add_paragraph().paragraph_format.space_after = Pt(6)

# ─────────────────────────────────────────────────────────────
# API pública
# ─────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────
# Plantilla OFIS embebida como bytes (no depende de archivo externo)
# ─────────────────────────────────────────────────────────────
_PLANTILLA_B64 = (
    "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"
)

# ─────────────────────────────────────────────────────────────
# Helpers internos para generación basada en plantilla
# ─────────────────────────────────────────────────────────────
def _activar_update_fields(doc):
    """Indica a Word que actualice todos los campos (incluido el TOC) al abrir el archivo."""
    settings = doc.settings.element
    for existing in settings.findall(qn('w:updateFields')):
        settings.remove(existing)
    uf = OxmlElement('w:updateFields')
    uf.set(qn('w:val'), '1')
    settings.append(uf)


def _rgb_office(hex_color):
    """Convierte 'C00000' al entero BGR que usa Office (.ForeColor.RGB)."""
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    return r + g * 256 + b * 65536


def _insertar_grafico_barras_nativo(doc, bookmark, counts,
                                    titulo='Distribución de Vulnerabilidad por Severidad'):
    """Reemplaza la imagen marcada por `bookmark` con un gráfico de barras NATIVO
    de Office (editable: clic derecho → Editar datos → la barra se actualiza).

    Usa 3 series separadas (Alto/Medio/Bajo) en matriz diagonal para que cada
    barra tenga su propio color y la leyenda muestre [■ Alto] [■ Medio] [■ Bajo].
    """
    if not doc.Bookmarks.Exists(bookmark):
        return False
    # Borrar la imagen PNG (fallback) que ocupa el bookmark. Al quitar la imagen,
    # Word elimina el bookmark, pero el objeto Range sobrevive como punto de
    # inserción → se REUTILIZA el mismo rng (no re-pedir doc.Bookmarks(...)).
    rng = doc.Bookmarks(bookmark).Range
    for shp in list(rng.InlineShapes):
        shp.Delete()
    XL_COLUMN_CLUSTERED = 51
    shp = doc.InlineShapes.AddChart2(-1, XL_COLUMN_CLUSTERED, rng)
    chart = shp.Chart

    filas = [('Alto', 'C00000'), ('Medio', 'ED7D31'), ('Bajo', '0070C0')]
    vals  = [int(counts.get(n, 0)) for n, _ in filas]

    # ── Datos en Excel embebido ──────────────────────────────────────────────
    # Matriz diagonal 3×3: cada columna = una serie (Alto/Medio/Bajo),
    # cada fila = una categoría (Alto/Medio/Bajo). Solo la celda diagonal
    # tiene valor; las demás son 0. Con Overlap=100 solo la barra no-cero
    # es visible en cada posición del eje X.
    #
    #         Alto  Medio  Bajo
    # Alto      3     0     0
    # Medio     0     5     0
    # Bajo      0     0     2
    import time
    cd = chart.ChartData
    cd.Activate()
    time.sleep(0.5)                          # esperar que el workbook embebido cargue
    wb = cd.Workbook
    ws = wb.Worksheets(1)
    ws.UsedRange.Clear()
    ws.Cells(1, 1).Value = ''
    for j, (nom, _) in enumerate(filas, start=2):
        ws.Cells(1, j).Value = nom          # encabezados de serie
    for i, (nom, _) in enumerate(filas, start=2):
        ws.Cells(i, 1).Value = nom          # etiqueta de categoría
        for j in range(2, 5):
            ws.Cells(i, j).Value = vals[j - 2] if j == i else 0
    wb.Close(SaveChanges=True)               # confirmar datos al Excel embebido

    # ── Formato ─────────────────────────────────────────────────────────────
    # Overlap 100 %: en cada posición del eje X las 3 barras se superponen
    # completamente; como solo una tiene valor > 0, visualmente queda una sola.
    try:
        chart.ChartGroups(1).Overlap  = 100
        chart.ChartGroups(1).GapWidth = 100
    except Exception:
        pass

    # Color, nombre y etiquetas por serie
    for i, ((nom, hexcol), val) in enumerate(zip(filas, vals), start=1):
        try:
            s = chart.SeriesCollection(i)
            s.Name = nom                            # nombre visible en la leyenda
            s.Format.Fill.ForeColor.RGB = _rgb_office(hexcol)
            s.Format.Fill.Visible       = -1   # msoTrue
            s.Format.Line.Visible       = 0    # sin borde
            s.HasDataLabels             = val > 0
        except Exception:
            pass

    # Sin título
    try:
        chart.HasTitle = False
    except Exception:
        pass

    # Leyenda abajo: [■ Alto] [■ Medio] [■ Bajo]
    try:
        chart.HasLegend       = True
        chart.Legend.Position = -4107   # xlLegendPositionBottom
    except Exception:
        pass

    return True


def _actualizar_toc_con_word(ruta_docx, graficos=None):
    """Abre el docx con Word (invisible), inserta los gráficos nativos editables,
    actualiza el índice y lo hornea en el XML.

    Devuelve True si Word procesó y guardó el documento; False si pywin32/Word no
    están disponibles (p. ej. Linux). En ese caso el flag updateFields se conserva
    para que Word actualice el índice al abrir el archivo en otra máquina, y la
    imagen del gráfico (PNG) se mantiene como respaldo.
    """
    try:
        import win32com.client
        import pythoncom
    except ImportError:
        return False
    word = None
    try:
        pythoncom.CoInitialize()
        word = win32com.client.Dispatch("Word.Application")
        word.Visible = False
        word.DisplayAlerts = False
        doc = word.Documents.Open(os.path.abspath(ruta_docx))
        # 1) Actualizar campos e índice PRIMERO
        doc.Fields.Update()
        if doc.TablesOfContents.Count > 0:
            doc.TablesOfContents(1).Update()
        # 2) Insertar los gráficos nativos AL FINAL: doc.Fields.Update() resetea a
        #    sus datos de ejemplo cualquier gráfico insertado antes, por eso van
        #    después de actualizar los campos.
        for g in (graficos or []):
            try:
                _insertar_grafico_barras_nativo(doc, g['bookmark'], g['counts'])
            except Exception as _ge:
                print(f"[WARN] Gráfico nativo falló ({g.get('bookmark')}): {_ge}")
        doc.Save()
        doc.Close()
        return True
    except Exception:
        return False
    finally:
        try:
            if word is not None:
                word.Quit()
            pythoncom.CoUninitialize()
        except Exception:
            pass


def _desactivar_update_fields(ruta_docx):
    """Quita w:updateFields del documento para suprimir el diálogo al abrir en Word."""
    try:
        from docx import Document as _Document
        d = _Document(ruta_docx)
        settings = d.settings.element
        for uf in settings.findall(qn('w:updateFields')):
            settings.remove(uf)
        d.save(ruta_docx)
    except Exception:
        pass


def _p_get_text(elem):
    if elem.tag.endswith('}p'):
        return ''.join(r.text or '' for r in elem.iter(qn('w:t'))).strip()
    return ''


def _sustituir_en_textboxes(doc, placeholder, valor, color_valor='1F1F1F', color_ph='FF0000'):
    """
    Reemplaza placeholder en cuadros de texto (w:txbxContent).
    Trabaja a nivel de párrafo completo para manejar el caso donde Word parte
    el placeholder en varios runs (ej: '(FECHA' en un run y ')' en el siguiente).
    """
    color_hex  = color_valor if valor else color_ph
    texto_final = valor if valor else placeholder

    for txbx in doc.element.body.iter(qn('w:txbxContent')):
        for p_elem in txbx.iter(qn('w:p')):
            # Recolectar todos los (r_elem, t_elem) con texto
            tokens = [
                (r, t)
                for r in p_elem.iter(qn('w:r'))
                for t in r.findall(qn('w:t'))
                if t.text
            ]
            full_text = ''.join(t.text for _, t in tokens)
            if placeholder not in full_text:
                continue

            ph_start = full_text.index(placeholder)
            ph_end   = ph_start + len(placeholder)

            pos = 0
            primer_overlap = True
            for r_elem, t_elem in tokens:
                tok_ini = pos
                tok_fin = pos + len(t_elem.text)
                pos = tok_fin

                # ¿Este token toca el placeholder?
                if tok_fin <= ph_start or tok_ini >= ph_end:
                    continue

                antes  = t_elem.text[:max(0, ph_start - tok_ini)]
                despues = t_elem.text[max(0, ph_end - tok_ini):]

                if primer_overlap:
                    # Primer run que toca el placeholder: poner el reemplazo
                    t_elem.text = antes + texto_final + despues
                    primer_overlap = False
                    # Actualizar color del run
                    rPr = r_elem.find(qn('w:rPr'))
                    if rPr is None:
                        rPr = OxmlElement('w:rPr')
                        r_elem.insert(0, rPr)
                    c = rPr.find(qn('w:color'))
                    if c is None:
                        c = OxmlElement('w:color')
                        rPr.append(c)
                    c.set(qn('w:val'), color_hex)
                else:
                    # Runs siguientes: eliminar su parte del placeholder
                    t_elem.text = antes + despues


def _fix_cliente_fecha(doc, fecha_str, cliente=""):
    """
    Reemplaza placeholders en la portada preservando el formato original de cada run.
    Cubre tanto párrafos normales como cuadros de texto (w:txbxContent).
    """
    _ROJO  = RGBColor(0xFF, 0x00, 0x00)
    _NEGRO = RGBColor(0x1F, 0x1F, 0x1F)

    # ── Cuadros de texto: (FECHA) y (CLIENTE) ────────────────
    # Los cuadros de texto de la portada no están en doc.paragraphs
    _sustituir_en_textboxes(doc, '(FECHA)',   fecha_str, '1F1F1F', 'FF0000')
    _sustituir_en_textboxes(doc, '(CLIENTE)', cliente,   '1F1F1F', 'FF0000')

    # ── Párrafos normales de la portada ──────────────────────
    paras = list(doc.paragraphs)
    idx_heading = next(
        (i for i, p in enumerate(paras)
         if p.style and ('Heading' in p.style.name or 'Ttulo' in p.style.name)),
        len(paras),
    )
    for para in paras[:idx_heading]:
        for run in para.runs:
            if '(FECHA)' in run.text:
                if fecha_str:
                    run.text = run.text.replace('(FECHA)', fecha_str)
                    run.font.color.rgb = _NEGRO
                else:
                    run.font.color.rgb = _ROJO
                    run.font.bold = True
            if '(CLIENTE)' in run.text:
                if cliente:
                    run.text = run.text.replace('(CLIENTE)', cliente)
                    run.font.color.rgb = _NEGRO
                else:
                    run.font.color.rgb = _ROJO
                    run.font.bold = True

    # ── Memo: Cliente: OFIS / Fecha: DD/MM/YYYY ───────────────
    for para in doc.paragraphs:
        txt = para.text.strip()
        if txt.startswith('Cliente:'):
            for run in para.runs:
                if 'OFIS' in run.text:
                    run.text = cliente if cliente else '[NOMBRE DEL CLIENTE]'
                    run.font.color.rgb = _NEGRO if cliente else _ROJO
                    run.font.bold = True
                    break
        elif txt.startswith('Fecha:') and re.search(r'\d{2}/\d{2}/\d{4}', txt):
            date_runs = [r for r in para.runs
                         if r.text.strip() and 'Fecha:' not in r.text]
            for i, run in enumerate(date_runs):
                if i == 0:
                    run.text = fecha_str
                    run.font.color.rgb = _NEGRO
                else:
                    run.text = ''

def _poblar_tabla_urls_plantilla(doc, lista_sitios):
    """Reemplaza las filas de la tabla URL con las URLs reales del escaneo."""
    url_tbl = None
    for tbl in doc.tables:
        if tbl.rows and len(tbl.rows[0].cells) >= 2:
            if 'URL' in tbl.rows[0].cells[1].text:
                url_tbl = tbl
                break
    if url_tbl is None:
        return

    # Eliminar todas las filas de datos (mantener cabecera)
    tbl_xml = url_tbl._tbl
    for tr in list(tbl_xml.findall(qn('w:tr')))[1:]:
        tbl_xml.remove(tr)

    # Agregar fila por cada URL
    for i, (url, _) in enumerate(lista_sitios):
        row = url_tbl.add_row()
        escribir_celda(row.cells[0], str(i + 1), size=10,
                       align=WD_ALIGN_PARAGRAPH.CENTER)
        escribir_celda(row.cells[1], url, size=10)
        escribir_celda(row.cells[2], 'Completo', size=10,
                       align=WD_ALIGN_PARAGRAPH.CENTER)

    # Actualizar párrafo de descripción de alcance con conteo real
    n = len(lista_sitios)
    for para in doc.paragraphs:
        if 'efectuar' in para.text and 'aplicaciones' in para.text:
            p = para._p
            # Limpiar runs existentes
            for r in list(p.findall(qn('w:r'))):
                p.remove(r)
            # Reconstruir con texto actualizado
            r_new = OxmlElement('w:r')
            rPr = OxmlElement('w:rPr')
            fonts = OxmlElement('w:rFonts')
            fonts.set(qn('w:ascii'), 'Century Gothic')
            fonts.set(qn('w:hAnsi'), 'Century Gothic')
            sz = OxmlElement('w:sz')
            sz.set(qn('w:val'), '22')
            szCs = OxmlElement('w:szCs')
            szCs.set(qn('w:val'), '22')
            rPr.append(fonts)
            rPr.append(sz)
            rPr.append(szCs)
            r_new.append(rPr)
            t_new = OxmlElement('w:t')
            t_new.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
            t_new.text = (
                f'Se efectuará un análisis de un total de {n} aplicaciones web, '
                'y la evaluación se realizará en aquellas accesibles mediante la '
                'herramienta de auditoría. En el siguiente cuadro se muestran las '
                'URLs, así como su estado de análisis.'
            )
            r_new.append(t_new)
            p.append(r_new)
            break

def _heading_en_plantilla(doc, nivel, texto):
    """Agrega heading usando estilos de la plantilla OFIS (Ttulo1/Ttulo2)."""
    for style_name in (f'Ttulo{nivel}', f'Heading {nivel}'):
        try:
            p = doc.add_paragraph(style=style_name)
            break
        except KeyError:
            continue
    else:
        p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after  = Pt(6)
    run = p.add_run(texto)
    run.font.name  = 'Century Gothic'
    run.font.size  = Pt(13 if nivel == 1 else 12)
    run.font.bold  = True
    run.font.color.rgb = RGBColor(0, 0, 0)
    return p

# ─────────────────────────────────────────────────────────────
# Parcheo de textos estáticos en la plantilla cargada
# ─────────────────────────────────────────────────────────────
_INTRO_PARRAFOS = [
    ('El presente informe tiene como objetivo evidenciar y detallar los resultados obtenidos '
     'durante la evaluación de seguridad web realizada sobre los activos digitales de (CLIENTE). '
     'Este servicio busca identificar las vulnerabilidades que afectan la seguridad de los '
     'elementos tecnológicos desde la perspectiva de aplicaciones web, incluyendo la revisión '
     'de configuraciones en relación con las buenas prácticas de programación, falta de '
     'actualización del software utilizado, uso de configuraciones por defecto, configuraciones '
     'débiles o erróneas, entre otras vulnerabilidades técnicas.'),
    ('El análisis fue ejecutado mediante herramientas especializadas de escaneo de '
     'vulnerabilidades OWASP ZAP, con el propósito de identificar posibles vectores de ataque, '
     'configuraciones inseguras y exposiciones de información sensible que puedan comprometer '
     'la confidencialidad, integridad y disponibilidad de los sistemas evaluados.'),
    ('Finalmente, a partir de los resultados obtenidos, se elaboran recomendaciones orientadas '
     'a corregir los problemas encontrados de manera global, fortaleciendo la postura de '
     'seguridad de la organización. Las recomendaciones específicas por cada vulnerabilidad '
     'técnica identificada se encuentran detalladas en los anexos técnicos correspondientes.'),
]

_INFORMATIVO_DESC = (
    'Expone información del sistema que no representa riesgo directo, pero podría ser '
    'utilizada por un atacante para planificar acciones maliciosas.'
)

_CONCLUSIONES_TEXTO = (
    'Completar con las recomendaciones específicas derivadas de los hallazgos identificados '
    'en el presente análisis, priorizando según el nivel de riesgo: Crítico y Alto de forma '
    'inmediata, Medio a corto plazo, y Bajo en el siguiente ciclo de mantenimiento.'
)

_LIMITACIONES_TEXTO = (
    'Las pruebas realizadas corresponden a un análisis de (TIPO DE CAJA), por lo que el '
    'alcance está limitado a los componentes accesibles públicamente. No se realizaron '
    'pruebas de intrusión manuales ni análisis de código fuente. Los resultados reflejan '
    'el estado de los sistemas al momento del escaneo y pueden variar ante cambios en '
    'la infraestructura o configuración de los servidores.'
)

_RECOMENDACIONES_TEXTO = (
    'Completar con las recomendaciones específicas derivadas de los hallazgos identificados '
    'en el presente análisis, priorizando según el nivel de riesgo: Crítico y Alto de forma '
    'inmediata, Medio a corto plazo, y Bajo en el siguiente ciclo de mantenimiento.'
)


def _aplicar_fuente_global(doc, fuente='Century Gothic'):
    """Aplica la fuente a todos los párrafos y celdas post-portada de la plantilla cargada."""
    paras = list(doc.paragraphs)
    # Portada = todo antes del primer Heading/Ttulo
    idx_inicio = next(
        (i for i, p in enumerate(paras)
         if p.style and ('Heading' in p.style.name or 'Ttulo' in p.style.name)),
        0,
    )
    for p in paras[idx_inicio:]:
        for run in p.runs:
            run.font.name = fuente
        sty = p.style.name if p.style else ''
        txt = p.text.strip()
        es_caption = txt.startswith('Tabla') or txt.startswith('Figura')
        if 'Heading' not in sty and 'Ttulo' not in sty and not es_caption:
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    for tbl in doc.tables:
        for row in tbl.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    for run in p.runs:
                        run.font.name = fuente

    # ── Índice/TOC: aplicar fuente al estilo y a párrafos ya existentes ──
    # Los estilos TOC N controlan el render cuando Word actualiza el índice.
    for style in doc.styles:
        sn = style.name or ''
        if any(k in sn for k in ('TOC', 'toc', 'ndice', 'Indice', 'contenido')):
            try:
                style.font.name = fuente
            except Exception:
                pass
    for p in paras[:idx_inicio]:
        sty_name = p.style.name if p.style else ''
        if any(k in sty_name for k in ('TOC', 'toc', 'ndice', 'contenido')):
            for run in p.runs:
                run.font.name = fuente


def _parchar_textos_plantilla(doc, cliente="", tipo_caja=""):
    """
    Actualiza en la plantilla cargada los textos estáticos neutros.
    Elimina el bloque memo De:/Asunto:, reemplaza Introducción, Limitaciones,
    Conclusiones y Recomendaciones. Si cliente/tipo_caja son provistos,
    sustituye los placeholders con los valores reales; si no, los deja en rojo.
    """
    body   = doc.element.body
    paras  = list(doc.paragraphs)

    def _es_heading(p):
        name = p.style.name if p.style else ''
        return 'Heading' in name or 'Ttulo' in name

    _COLOR_NORMAL      = RGBColor(0x33, 0x33, 0x33)
    _COLOR_PLACEHOLDER = RGBColor(0xBF, 0xBF, 0xBF)   # gris claro tipo aviso

    def _reemplazar_seccion(titulo_opciones, textos, estilo='Normal',
                            color=None, left_indent=None, first_line_indent=None):
        if color is None:
            color = _COLOR_NORMAL
        idx_h = next(
            (i for i, p in enumerate(paras)
             if _es_heading(p) and p.text.strip() in titulo_opciones),
            None,
        )
        if idx_h is None:
            return
        idx_next = next(
            (i for i, p in enumerate(paras) if i > idx_h and _es_heading(p)),
            len(paras),
        )
        for p in paras[idx_h + 1:idx_next]:
            p._element.getparent().remove(p._element)

        anchor = paras[idx_next]._element if idx_next < len(paras) else None
        for texto in textos:
            p_new = doc.add_paragraph(style=estilo)
            p_new.paragraph_format.space_after = Pt(6)
            if left_indent is not None:
                p_new.paragraph_format.left_indent = left_indent
            if first_line_indent is not None:
                p_new.paragraph_format.first_line_indent = first_line_indent
            r = p_new.add_run(texto)
            r.font.name = 'Century Gothic'
            r.font.size = Pt(11)
            r.font.color.rgb = color
            if anchor is not None:
                body.remove(p_new._element)
                body.insert(list(body).index(anchor), p_new._element)

    # ── Eliminar bloque memo De:/Asunto:/Cliente:/Fecha: ─────────
    _MEMO_PREFIJOS = ('De:', 'Asunto:', 'Cliente: ', 'Cliente:\t', 'Fecha: ', 'Fecha:\t')
    for p in list(doc.paragraphs):
        if p.text.strip().startswith(_MEMO_PREFIJOS):
            p._element.getparent().remove(p._element)

    # ── Limpiar párrafos vacíos sobrantes del memo (entre TOC e Introducción) ──
    # El TOC es un elemento <sdt> en el body (no aparece en doc.paragraphs).
    # Todos los <p> vacíos entre el sdt y el heading Introducción son sobrantes del memo.
    _ns_w = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
    body_elems_pm = list(body)
    sdt_idx_pm = next(
        (i for i, e in enumerate(body_elems_pm)
         if e.tag.split('}')[-1] == 'sdt'),
        -1,
    )
    intro_elem_pm = next(
        (p._element for p in doc.paragraphs
         if _es_heading(p) and 'Introduc' in p.text),
        None,
    )
    if sdt_idx_pm >= 0 and intro_elem_pm is not None:
        try:
            intro_idx_pm = body_elems_pm.index(intro_elem_pm)
            for elem in body_elems_pm[sdt_idx_pm + 1:intro_idx_pm]:
                if elem.tag.split('}')[-1] == 'p':
                    txt = ''.join(
                        t.text or '' for t in elem.iter('{%s}t' % _ns_w)
                    ).strip()
                    if not txt:
                        body.remove(elem)
        except ValueError:
            pass

    # ── Introducción ─────────────────────────────────────────────
    # page_break_before=True fuerza que Introducción siempre inicie en página nueva
    # (necesario tras eliminar los párrafos vacíos del memo que hacían de separador).
    for p in doc.paragraphs:
        sty = p.style.name if p.style else ''
        if ('Heading' in sty or 'Ttulo' in sty) and 'Introduc' in p.text:
            p.paragraph_format.page_break_before = True
            p.paragraph_format.space_before = Pt(0)
            break
    # El indent de los párrafos nuevos se alinea con el resto del template (228600 EMU).
    _reemplazar_seccion({'Introducción', '1. Introducción'}, _INTRO_PARRAFOS,
                        left_indent=228600, first_line_indent=220980)

    # Reemplazar (CLIENTE) solo en párrafos del cuerpo (no portada)
    # La portada ya fue procesada por _fix_cliente_fecha preservando su tamaño de fuente.
    _paras_body = list(doc.paragraphs)
    _idx_h = next(
        (i for i, p in enumerate(_paras_body)
         if p.style and ('Heading' in p.style.name or 'Ttulo' in p.style.name)),
        0,
    )
    for p in _paras_body[_idx_h:]:
        if '(CLIENTE)' not in p.text:
            continue
        txt_full = p.text
        partes = txt_full.split('(CLIENTE)')
        p.clear()
        for idx_parte, parte in enumerate(partes):
            if parte:
                r = p.add_run(parte)
                r.font.name = 'Century Gothic'; r.font.size = Pt(11)
                r.font.color.rgb = RGBColor(0x33, 0x33, 0x33)
            if idx_parte < len(partes) - 1:
                if cliente:
                    r_ph = p.add_run(cliente)
                    r_ph.font.name = 'Century Gothic'; r_ph.font.size = Pt(11)
                    r_ph.font.color.rgb = RGBColor(0x1F, 0x1F, 0x1F)
                    r_ph.font.bold = True
                else:
                    r_ph = p.add_run('(CLIENTE)')
                    r_ph.font.name = 'Century Gothic'; r_ph.font.size = Pt(11)
                    r_ph.font.color.rgb = RGBColor(0xFF, 0x00, 0x00)
                    r_ph.font.bold = True

    # ── Conclusiones ─────────────────────────────────────────────
    _reemplazar_seccion({'Conclusiones'}, [_CONCLUSIONES_TEXTO],
                        estilo='List Paragraph', color=_COLOR_PLACEHOLDER)

    # ── Recomendaciones ──────────────────────────────────────────
    _reemplazar_seccion({'Recomendaciones'}, [_RECOMENDACIONES_TEXTO],
                        estilo='List Paragraph', color=_COLOR_PLACEHOLDER)

    # ── Limitaciones ─────────────────────────────────────────────
    _reemplazar_seccion(
        {'3.1 Limitaciones', '3.1. Limitaciones', 'Limitaciones'},
        [_LIMITACIONES_TEXTO],
        estilo='List Paragraph',
    )
    # Reemplazar (TIPO DE CAJA) dentro de Limitaciones
    for p in doc.paragraphs:
        if '(TIPO DE CAJA)' not in p.text:
            continue
        txt_full = p.text
        partes = txt_full.split('(TIPO DE CAJA)')
        p.clear()
        for idx_parte, parte in enumerate(partes):
            if parte:
                r = p.add_run(parte)
                r.font.name = 'Century Gothic'; r.font.size = Pt(11)
                r.font.color.rgb = _COLOR_NORMAL
            if idx_parte < len(partes) - 1:
                if tipo_caja:
                    r_ph = p.add_run(tipo_caja)
                    r_ph.font.name = 'Century Gothic'; r_ph.font.size = Pt(11)
                    r_ph.font.color.rgb = RGBColor(0x1F, 0x1F, 0x1F)
                    r_ph.font.bold = True
                else:
                    r_ph = p.add_run('(TIPO DE CAJA)')
                    r_ph.font.name = 'Century Gothic'; r_ph.font.size = Pt(11)
                    r_ph.font.color.rgb = RGBColor(0xFF, 0x00, 0x00)
                    r_ph.font.bold = True

    # ── Bullet Informativo ────────────────────────────────────────
    for p in doc.paragraphs:
        if p.text.strip().lower().startswith('informativo'):
            p.clear()
            r1 = p.add_run('Informativo: ')
            r1.font.name = 'Century Gothic'; r1.font.size = Pt(11); r1.font.bold = True
            r2 = p.add_run(_INFORMATIVO_DESC)
            r2.font.name = 'Century Gothic'; r2.font.size = Pt(11)
            break

    # ── Limpiar bullets vacíos en "Como Leer Documento" ──────────
    # El template B64 tiene párrafos List Bullet vacíos (incluyendo '\n')
    # que generan saltos entre "Bajo" e "Informativo". Se eliminan.
    paras_frescos = list(doc.paragraphs)
    idx_como = next(
        (i for i, p in enumerate(paras_frescos)
         if _es_heading(p) and 'Como Leer' in p.text),
        None,
    )
    if idx_como is not None:
        idx_sig = next(
            (i for i, p in enumerate(paras_frescos)
             if i > idx_como and _es_heading(p)),
            len(paras_frescos),
        )
        for p in paras_frescos[idx_como + 1:idx_sig]:
            if p.style and 'Bullet' in p.style.name and not p.text.strip():
                p._element.getparent().remove(p._element)

    # ── Centrar captions de tablas estáticas de la plantilla ─────
    for p in doc.paragraphs:
        txt = p.text.strip()
        if txt.startswith('Tabla') and 'Clasificaci' in txt:
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER


# ─────────────────────────────────────────────────────────────
# Generación basada en plantilla OFIS (función pública)
# ─────────────────────────────────────────────────────────────
def generar_word_plantilla(lista_sitios, carpeta_salida,
                           cliente="", fecha=None, tipo_caja=""):
    """
    Genera el Word usando OFIS - Plantilla.docx como base.
    - Pobla la tabla de URLs con las URLs reales.
    - Inserta el contenido ZAP entre 'Resumen Ejecutivo Global' y 'Recomendaciones'.
    - No agrega un segundo índice (la plantilla ya tiene uno).
    - Si la plantilla no existe, usa generar_word_consolidado() como fallback.
    """
    doc  = Document(BytesIO(base64.b64decode(_PLANTILLA_B64)))
    body = doc.element.body
    if fecha is None:
        fecha = datetime.now().strftime('%d/%m/%Y')

    # Corregir typo en la plantilla: "VULNERABILIDADES" → "VULNERABILIDAD"
    # Usa ensamblado de runs para manejar el caso donde Word fragmenta el texto en varios runs.
    _OLD = 'ANÁLISIS DE VULNERABILIDADES'
    _NEW = 'ANÁLISIS DE VULNERABILIDAD'
    def _fix_typo_en_parrafos(contenedor):
        for p_elem in contenedor.iter(qn('w:p')):
            tokens = [
                (r, t)
                for r in p_elem.iter(qn('w:r'))
                for t in r.findall(qn('w:t'))
                if t.text
            ]
            full_text = ''.join(t.text for _, t in tokens)
            if _OLD not in full_text:
                continue
            ph_start = full_text.index(_OLD)
            ph_end   = ph_start + len(_OLD)
            pos = 0
            primer_overlap = True
            for r_elem, t_elem in tokens:
                tok_ini = pos
                tok_fin = pos + len(t_elem.text)
                pos = tok_fin
                if tok_fin <= ph_start or tok_ini >= ph_end:
                    continue
                antes   = t_elem.text[:max(0, ph_start - tok_ini)]
                despues = t_elem.text[max(0, ph_end   - tok_ini):]
                if primer_overlap:
                    t_elem.text = antes + _NEW + despues
                    primer_overlap = False
                else:
                    t_elem.text = antes + despues
    for txbx in body.iter(qn('w:txbxContent')):
        _fix_typo_en_parrafos(txbx)
    _fix_typo_en_parrafos(body)

    # Tabla 1 y Tabla 2 ya existen en la plantilla → contador empieza en 2
    contador = _Contador()
    contador.tabla  = 2
    contador.figura = 0

    # ── 1. Actualizar placeholders de portada ────────────────
    _fix_cliente_fecha(doc, fecha, cliente)

    # ── 1b. Marcar el índice para actualización (fallback si Word no horneó el TOC) ──
    # En el guardado final se intenta hornear el índice con Word y, si lo logra,
    # se quita este flag para que el documento abra sin el diálogo de actualización.
    _activar_update_fields(doc)

    # ── 1c. Actualizar textos estáticos (intro, informativo, etc.) ──
    _parchar_textos_plantilla(doc, cliente, tipo_caja)

    # ── 1d. Aplicar fuente Century Gothic a todo el contenido post-portada ──
    _aplicar_fuente_global(doc)

    # ── 2. Poblar tabla de URLs en Alcance del servicio ──────
    _poblar_tabla_urls_plantilla(doc, lista_sitios)

    # ── 3. Localizar anclas ──────────────────────────────────
    # nodo_fin: Conclusiones preferido (antes de Recomendaciones) para
    # no borrar ninguno de los dos al limpiar los placeholders de hallazgos.
    nodo_resumen = None
    nodo_fin     = None
    for elem in body:
        txt = _p_get_text(elem)
        if txt == 'Resumen Ejecutivo Global' and nodo_resumen is None:
            nodo_resumen = elem
        if txt in ('Conclusiones', 'Recomendaciones') and nodo_fin is None:
            nodo_fin = elem

    if nodo_resumen is None or nodo_fin is None:
        raise RuntimeError('[ERROR] Anclas no encontradas en la plantilla (Resumen Ejecutivo Global / Conclusiones).')

    # ── 4. Eliminar placeholders entre anclas ────────────────
    children = list(body)
    idx_ini  = children.index(nodo_resumen) + 1
    idx_fin  = children.index(nodo_fin)
    for elem in children[idx_ini:idx_fin]:
        body.remove(elem)

    # ── 5. Generar contenido ZAP (se agrega al final; luego se mueve) ──
    ids_antes = {id(e) for e in body}

    # Estadísticas globales
    total_alto  = sum(sum(1 for a in al if str(a.get('riskcode','0'))=='3') for _,al in lista_sitios)
    total_medio = sum(sum(1 for a in al if str(a.get('riskcode','0'))=='2') for _,al in lista_sitios)
    total_bajo  = sum(sum(1 for a in al if str(a.get('riskcode','0'))=='1') for _,al in lista_sitios)
    total = total_alto + total_medio + total_bajo

    p_stats = doc.add_paragraph()
    p_stats.paragraph_format.space_after = Pt(4)
    rr = p_stats.add_run(
        f"Sitios evaluados: {len(lista_sitios)}   |   Total hallazgos: {total}   |   "
        f"Alto: {total_alto}   |   Medio: {total_medio}   |   Bajo: {total_bajo}"
    )
    rr.font.name = 'Century Gothic'
    rr.font.size = Pt(11)
    rr.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

    # Gráfico global
    counts_global = {'Alto': total_alto, 'Medio': total_medio, 'Bajo': total_bajo}
    grafico_global = generar_grafico_barras(counts_global)
    graficos_nativos = []
    if grafico_global:
        _insertar_figura(doc, grafico_global, contador,
                         'Distribución global de niveles de riesgo',
                         bookmark='GRAFICO_RIESGO_GLOBAL')
        graficos_nativos.append({'bookmark': 'GRAFICO_RIESGO_GLOBAL',
                                 'counts': counts_global})

    # Heading de hallazgos
    _heading_en_plantilla(doc, 1, '5. Resumen de Hallazgos Identificados por URL')

    # Tabla consolidada de hallazgos únicos (sin repetir por URL)
    _tabla_hallazgos_global(doc, lista_sitios, contador)

    # Contenido por sitio
    for idx, (sitio, alertas) in enumerate(lista_sitios):
        doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
        _agregar_contenido_url(doc, sitio, alertas, idx + 1, contador=contador)

    # Salto de página antes de Recomendaciones
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # ── 6. Mover nuevos elementos al lugar correcto ──────────
    nuevos = [
        e for e in body
        if id(e) not in ids_antes and not e.tag.endswith('}sectPr')
    ]
    for e in nuevos:
        body.remove(e)
    idx_rec = list(body).index(nodo_fin)
    for i, e in enumerate(nuevos):
        body.insert(idx_rec + i, e)

    # ── 7. Guardar ───────────────────────────────────────────
    os.makedirs(carpeta_salida, exist_ok=True)
    import uuid
    codigo = uuid.uuid4().hex[:12].upper()
    ruta = os.path.join(carpeta_salida, f'reporte_consolidado_{codigo}.docx')
    doc.save(ruta)
    # Hornear el índice con Word (Windows). Si lo logra, quitar el flag updateFields
    # para que el documento abra sin el diálogo "¿Desea actualizar los campos?".
    # Si Word no está disponible (Linux), el flag se mantiene y el índice se
    # actualiza al abrir el archivo en una máquina con Word.
    if _actualizar_toc_con_word(ruta, graficos=graficos_nativos):
        _desactivar_update_fields(ruta)
    return ruta

