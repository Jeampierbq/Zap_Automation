import requests
import time
import json
import os
import sys
import re
from pathlib import Path
from urllib.parse import urlparse
from generador import generar_word_plantilla
import config

BASE = f"http://{config.ZAP_HOST}:{config.ZAP_PORT}"

def _key():
    return config.ZAP_API_KEY

def log(msg):       print(f"  [INFO]  {msg}")
def ok(msg):        print(f"  [OK]    {msg}")
def warn(msg):      print(f"  [AVISO] {msg}")
def error(msg):     print(f"  [ERROR] {msg}")
def titulo(msg):    print(f"\n{'='*62}\n  {msg}\n{'='*62}")
def subtitulo(msg): print(f"\n  -- {msg} --")

# Reglas ZAP no relevantes para auditorías web modernas (se deshabilitan en OWASP_Web)
_REGLAS_DESHABILITAR = ["30001", "30002", "90024", "90026", "90029"]

def zap_get(endpoint, params={}, timeout=15):
    p = {**params, "apikey": _key()}
    for intento in range(3):
        try:
            r = requests.get(f"{BASE}{endpoint}", params=p, timeout=timeout)
            return r.json()
        except Exception as e:
            if intento == 2:
                raise Exception(f"Error ZAP: {e}")
            time.sleep(2)

def zap_get_raw(endpoint, params={}, timeout=30):
    p = {**params, "apikey": _key()}
    for intento in range(3):
        try:
            r = requests.get(f"{BASE}{endpoint}", params=p, timeout=timeout)
            return r.content.decode('utf-8')
        except Exception as e:
            if intento == 2:
                raise Exception(f"Error ZAP raw: {e}")
            time.sleep(2)

def esperar_progreso(endpoint, params, tiempo_max, etiqueta):
    inicio = time.time()
    ultimo = -1
    while True:
        try:
            data     = zap_get(endpoint, params)
            progreso = int(data.get("status", 0))
            if progreso != ultimo:
                print(f"\r    {etiqueta}: {progreso}%   ", end="", flush=True)
                ultimo = progreso
            if progreso >= 100:
                print("")
                return True
        except:
            print(f"\r    Esperando {etiqueta}...   ", end="", flush=True)
        if time.time() - inicio > tiempo_max:
            print("")
            warn(f"Tiempo max alcanzado en {ultimo}%. Continuando...")
            return False
        time.sleep(4)

def esperar_ajax(tiempo_max):
    inicio = time.time()
    ultimo = ""
    while True:
        try:
            data   = zap_get("/JSON/ajaxSpider/view/status/")
            estado = data.get("status", "")
            if estado != ultimo:
                print(f"\r    Spider AJAX: {estado}   ", end="", flush=True)
                ultimo = estado
            if estado == "stopped":
                print("")
                return True
        except:
            print(f"\r    Esperando Spider AJAX...   ", end="", flush=True)
        if time.time() - inicio > tiempo_max:
            print("")
            warn("Tiempo max AJAX. Deteniendo Chrome...")
            try:
                zap_get("/JSON/ajaxSpider/action/stop/")
                time.sleep(5)
            except:
                pass
            return False
        time.sleep(5)

def dominio_de(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def nombre_limpio(url):
    n = url.replace("https://","").replace("http://","")
    n = re.sub(r'[^a-zA-Z0-9]', '_', n)
    n = re.sub(r'_+', '_', n).strip('_')
    return n

def cerrar_ajax():
    """
    Cierra el spider AJAX y espera a que Chrome se cierre completamente.
    FIX: tiempo de espera aumentado a 15s para evitar procesos Chrome colgados
    al escanear más de 3 URLs.
    """
    try:
        data = zap_get("/JSON/ajaxSpider/view/status/", timeout=8)
        if data.get("status") == "running":
            log("Deteniendo Chrome / Spider AJAX...")
            zap_get("/JSON/ajaxSpider/action/stop/")
            # Esperar a que Chrome cierre completamente antes de continuar
            for seg in range(1, 16):
                time.sleep(1)
                try:
                    st = zap_get("/JSON/ajaxSpider/view/status/", timeout=5)
                    if st.get("status") == "stopped":
                        ok(f"Chrome cerrado (en {seg}s)")
                        return
                except:
                    pass
            ok("Chrome cerrado (timeout 15s)")
        else:
            time.sleep(2)
    except:
        pass

def limpiar_sesion():
    """
    Limpia la sesion ZAP antes de cada URL.
    FIX: verifica que el AJAX spider esté detenido antes de crear nueva sesión.
    """
    log("Limpiando sesion ZAP...")
    # Asegurar que el spider AJAX esté detenido antes de nueva sesión
    try:
        data = zap_get("/JSON/ajaxSpider/view/status/", timeout=5)
        if data.get("status") == "running":
            log("Spider AJAX activo, deteniendolo antes de limpiar...")
            zap_get("/JSON/ajaxSpider/action/stop/")
            time.sleep(12)
    except:
        pass
    try:
        zap_get("/JSON/core/action/newSession/", {"name":"","overwrite":"true"})
        time.sleep(5)
        ok("Sesion limpiada")
    except:
        warn("No se pudo limpiar sesion, continuando...")

def _asegurar_politica_owasp_web():
    """Crea la política OWASP_Web en ZAP si no existe. Solo corre una vez por sesión."""
    nombre = getattr(config, 'SCAN_POLICY', '')
    if not nombre:
        return
    try:
        data = zap_get("/JSON/ascan/view/scanPolicyNames/")
        if nombre in data.get("scanPolicyNames", []):
            log(f"Política '{nombre}' ya existe en ZAP")
            return
    except Exception as e:
        warn(f"No se pudo verificar políticas: {e}")
        return
    try:
        zap_get("/JSON/ascan/action/addScanPolicy/", {
            "scanPolicyName": nombre,
            "alertThreshold": "HIGH",
            "attackStrength":  "HIGH",
        })
        zap_get("/JSON/ascan/action/enableAllScanners/", {"scanPolicyName": nombre})
        zap_get("/JSON/ascan/action/disableScanners/", {
            "ids":            ",".join(_REGLAS_DESHABILITAR),
            "scanPolicyName": nombre,
        })
        ok(f"Política '{nombre}' creada — fuerza ALTA, sin reglas no-web")
    except Exception as e:
        warn(f"No se pudo crear política '{nombre}': {e}. Se usará Default.")

def _crear_contexto(url):
    """Crea un contexto ZAP limitado exactamente al dominio del target."""
    nombre = "target_scan"
    dominio_base = dominio_de(url)
    regex = re.escape(dominio_base) + ".*"
    try:
        zap_get("/JSON/context/action/removeContext/", {"contextName": nombre})
    except:
        pass
    zap_get("/JSON/context/action/newContext/", {"contextName": nombre})
    zap_get("/JSON/context/action/includeInContext/", {
        "contextName": nombre,
        "regex":       regex,
    })
    ctx_id = ""
    try:
        data   = zap_get("/JSON/context/view/context/", {"contextName": nombre})
        ctx_id = str(data.get("context", {}).get("id", ""))
    except:
        pass
    log(f"Contexto '{nombre}' → scope: {dominio_base}")
    return nombre, ctx_id

def fase_spider_tradicional(url, ctx_nombre=""):
    subtitulo("FASE 1/3: Spider Tradicional")
    data = zap_get("/JSON/spider/action/scan/", {
        "url":         url,
        "maxChildren": "0",
        "recurse":     "true",
        "contextName": ctx_nombre,
        "subtreeOnly": "false",
    })
    spider_id = data.get("scan")
    if spider_id is None:
        raise Exception("No se pudo iniciar Spider tradicional")
    log(f"Spider ID: {spider_id}")
    completado = esperar_progreso("/JSON/spider/view/status/",
                                  {"scanId": spider_id},
                                  config.TIEMPO_SPIDER, "Spider tradicional")
    urls_encontradas = ""
    try:
        res = zap_get("/JSON/spider/view/results/", {"scanId": spider_id})
        n = len(res.get("results", []))
        urls_encontradas = f" — {n} URLs descubiertas"
    except:
        pass
    if completado:
        ok(f"Spider tradicional finalizado correctamente{urls_encontradas}")
    else:
        warn(f"Spider tradicional pausado por tiempo máximo{urls_encontradas} — continuando con lo descubierto")
    time.sleep(2)

def _intentar_ajax_con_browser(url, browser, ctx_nombre=""):
    """Intenta lanzar el spider AJAX con un browser específico. Retorna True si OK."""
    try:
        zap_get("/JSON/ajaxSpider/action/setOptionBrowserId/", {"String": browser})
        zap_get("/JSON/ajaxSpider/action/setOptionMaxDuration/",
                {"Integer": str(config.AJAX_MAX_DURATION)})
        zap_get("/JSON/ajaxSpider/action/setOptionMaxCrawlDepth/",
                {"Integer": str(config.AJAX_MAX_CRAWL_DEPTH)})
        data = zap_get("/JSON/ajaxSpider/action/scan/", {
            "url":         url,
            "inScope":     "true" if ctx_nombre else "false",
            "contextName": ctx_nombre,
            "subtreeOnly": "false",
        })
        if data.get("result") == "OK":
            return True
        # Si ZAP reporta error de browser, lanza excepción para el fallback
        if "browser" in str(data).lower() or "chrome" in str(data).lower():
            raise Exception(f"Browser error: {data}")
        return True
    except Exception as e:
        raise e

def _es_sitio_estatico(url):
    """
    Retorna True si el sitio parece HTML estático sin framework JS pesado.
    Usado para decidir si vale la pena htmlunit como último recurso de AJAX.
    """
    SPA_MARKERS = [
        'id="root"', "id='root'",       # React
        '<app-root', 'ng-version',       # Angular
        '__next_data__', '_next/static', # Next.js
        '__nuxt__', '_nuxt/',            # Nuxt
        'data-reactroot',                # React SSR
        'chunk.js', 'bundle.js',         # Webpack bundles
        'vendor.js', 'runtime.js',       # Webpack chunks
        'angular.min', 'react.min',      # Libs minificadas
        'vue.min', 'vue.runtime',        # Vue
        'ember.js', 'backbone.js',       # Otros frameworks
    ]
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read(50000).decode('utf-8', errors='ignore').lower()
        for marker in SPA_MARKERS:
            if marker in html:
                return False
        return True
    except:
        return False  # si no se puede verificar, asumir JS-heavy (más seguro)


def fase_spider_ajax(url, ctx_nombre=""):
    subtitulo("FASE 2/3: Spider AJAX")

    # Si AJAX está desactivado en config, saltar
    if not getattr(config, 'AJAX_ENABLED', True):
        warn("Spider AJAX desactivado (AJAX_ENABLED=False). Saltando fase 2...")
        return

    # Orden de browsers reales a intentar (htmlunit excluido — JS limitado, resultados pobres)
    browsers_fallback = []
    for b in [config.AJAX_BROWSER, "firefox", "chrome-headless"]:
        if b and b not in browsers_fallback and b != "htmlunit":
            browsers_fallback.append(b)

    iniciado = False
    for browser in browsers_fallback:
        try:
            log(f"Intentando Spider AJAX con browser: {browser}")
            _intentar_ajax_con_browser(url, browser, ctx_nombre)
            log(f"Spider AJAX iniciado con: {browser}")
            iniciado = True
            break
        except Exception as e:
            warn(f"Browser '{browser}' falló: {e}. Probando siguiente...")
            cerrar_ajax()
            time.sleep(3)

    if not iniciado:
        log("Firefox y Chrome no disponibles — verificando si el sitio es estático...")
        if _es_sitio_estatico(url):
            log("Sitio estático detectado — intentando htmlunit como último recurso...")
            try:
                _intentar_ajax_con_browser(url, "htmlunit", ctx_nombre)
                log("Spider AJAX iniciado con: htmlunit")
                iniciado = True
            except Exception as e:
                warn(f"htmlunit también falló: {e}")
        else:
            warn("Sitio JS-heavy detectado (React/Angular/Vue/etc.) — htmlunit no aportaría cobertura real.")

    if not iniciado:
        warn("No se encontró Firefox ni Chrome instalados.")
        warn("Spider AJAX saltado — instala Firefox o Chrome para escaneos JS completos.")
        warn("El escaneo continúa solo con Spider Tradicional (sitios JS-heavy pueden quedar incompletos).")
        return
    completado = esperar_ajax(config.TIEMPO_SPIDER_AJAX)
    cerrar_ajax()
    if completado:
        ok("Spider AJAX finalizado correctamente — exploración JS completada")
    else:
        warn("Spider AJAX pausado por tiempo máximo — continuando con lo descubierto")
    time.sleep(3)

def fase_escaneo_activo(url, ctx_id=""):
    politica = config.SCAN_POLICY or "Default"
    subtitulo(f"FASE 3/3: Escaneo Activo — política: {politica}")
    log("Iniciando escaneo activo nivel ALTO...")
    data = zap_get("/JSON/ascan/action/scan/", {
        "url":            url,
        "recurse":        "true",
        "inScopeOnly":    "true" if ctx_id else "false",
        "scanPolicyName": config.SCAN_POLICY,
        "method":         "",
        "postData":       "",
        "contextId":      ctx_id,
    })
    scan_id = data.get("scan")
    if scan_id is None:
        raise Exception("No se pudo iniciar Escaneo Activo")
    log(f"Scan ID: {scan_id} — esperando que ZAP complete al 100%...")
    completado = esperar_progreso("/JSON/ascan/view/status/",
                                  {"scanId": scan_id},
                                  config.TIEMPO_ESCANEO, "Escaneo activo")
    if completado:
        ok("Escaneo activo finalizado correctamente al 100% — todas las pruebas ejecutadas")
    else:
        warn("Escaneo activo pausado por tiempo máximo — se exportará lo encontrado hasta ahora")
    time.sleep(2)

_CODIGOS_OK    = {200, 201, 204, 301, 302, 303, 307, 308}
_cache_codigos = {}   # msg_id → status code, evita llamadas duplicadas

def _codigo_http(msg_id):
    """Retorna el HTTP status code de un mensaje ZAP. None si no se puede obtener."""
    if msg_id in _cache_codigos:
        return _cache_codigos[msg_id]
    try:
        data = zap_get("/JSON/core/view/message/", {"id": msg_id}, timeout=5)
        encabezado = data.get("message", {}).get("responseHeader", "")
        m = re.match(r'HTTP/[\d.]+\s+(\d+)', encabezado)
        codigo = int(m.group(1)) if m else None
    except:
        codigo = None
    _cache_codigos[msg_id] = codigo
    return codigo

_EXT_ESTATICAS = {
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
    '.woff', '.woff2', '.ttf', '.eot', '.otf', '.map', '.pdf',
    '.txt', '.xml', '.json',
}
_NOMBRES_EXCLUIR = {'robots.txt', 'sitemap.xml', 'favicon.ico', 'humans.txt'}

def _es_recurso_estatico(uri):
    """Retorna True si la URI apunta a un recurso estático (no a una página real)."""
    try:
        from urllib.parse import urlparse
        path = urlparse(uri).path.lower().split('?')[0]
        nombre = path.split('/')[-1]
        if nombre in _NOMBRES_EXCLUIR:
            return True
        ext = '.' + nombre.split('.')[-1] if '.' in nombre else ''
        return ext in _EXT_ESTATICAS
    except:
        return False

def _filtrar_instancias_relevantes(alertas):
    """
    Para hallazgos pasivos (sin payload de ataque): solo conserva URLs que son
    páginas reales de la aplicación, no recursos estáticos (.js, .css, imágenes...).
    Para hallazgos activos (tienen attack payload): no filtra por extensión —
    ZAP atacó algo concreto y la URL es evidencia directa.
    """
    resultado  = []
    eliminadas = 0
    for alerta in alertas:
        instancias_ok = []
        for inst in alerta.get("instances", []):
            es_activo = bool(inst.get("attack", "").strip())
            if not es_activo and _es_recurso_estatico(inst.get("uri", "")):
                eliminadas += 1
                continue
            instancias_ok.append(inst)
        if instancias_ok:
            copia = dict(alerta)
            copia["instances"] = instancias_ok
            copia["count"] = str(len(instancias_ok))
            resultado.append(copia)
        else:
            eliminadas_alertas = getattr(_filtrar_instancias_relevantes, '_alertas_eliminadas', 0) + 1
            _filtrar_instancias_relevantes._alertas_eliminadas = eliminadas_alertas
    if eliminadas:
        log(f"Instancias en recursos estáticos eliminadas: {eliminadas}")
    return resultado


def _filtrar_instancias_http_error(alertas):
    """
    Solo conserva instancias cuya URL respondió correctamente (2xx/3xx).
    URLs que no cargan, dan 404, 500 u otro error quedan fuera del reporte.
    Si una alerta queda sin instancias válidas, se elimina del reporte completo.
    """
    resultado  = []
    eliminadas = 0
    for alerta in alertas:
        instancias_ok = []
        for inst in alerta.get("instances", []):
            msg_id = str(inst.get("id", ""))
            if msg_id:
                codigo = _codigo_http(msg_id)
                if codigo is None or codigo not in _CODIGOS_OK:
                    eliminadas += 1
                    continue
            instancias_ok.append(inst)
        if instancias_ok:
            copia = dict(alerta)
            copia["instances"] = instancias_ok
            copia["count"] = str(len(instancias_ok))
            resultado.append(copia)
    if eliminadas:
        log(f"Instancias con URL que no responde correctamente eliminadas: {eliminadas}")
    return resultado


def exportar_json_y_filtrar(url):
    subtitulo("Exportando JSON (igual que manual) y filtrando")
    dominio = dominio_de(url)
    nombre  = nombre_limpio(url)
    os.makedirs(config.CARPETA_SALIDA, exist_ok=True)
    os.makedirs(config.CARPETA_JSON,   exist_ok=True)

    # ── CLAVE: usar el mismo endpoint que ZAP usa al exportar manualmente
    # Este endpoint devuelve el JSON con riskcode, instances, desc, etc.
    # exactamente igual que Traditional JSON Report
    log("Exportando reporte JSON completo via API...")
    texto_json = zap_get_raw("/OTHER/core/other/jsonreport/", timeout=60)

    try:
        reporte = json.loads(texto_json)
    except:
        raise Exception("No se pudo parsear el JSON del reporte")

    # Extraer alertas SOLO del dominio objetivo
    # Se compara incluyendo el esquema (https/http) para evitar que un site
    # http:// sea confundido con el site https:// objetivo cuando ZAP los
    # registra como entradas separadas en el reporte.
    sites     = reporte.get("site", [])
    alertas_dominio = []
    host_objetivo = dominio.replace("https://","").replace("http://","")
    for site in sites:
        site_name = site.get("@name","")
        # Coincidencia exacta de esquema+host: el site_name debe empezar con
        # el dominio completo (ej. "https://focalizacion...") y no ser solo
        # el site http:// que ZAP crea cuando hay redirecciones internas.
        if site_name.startswith(dominio) or site_name == dominio:
            alertas_dominio = site.get("alerts", [])
            log(f"Sitio encontrado: {site_name} — {len(alertas_dominio)} hallazgos")
            break
    # Fallback: si no hay match exacto de esquema, buscar por host (caso sin puerto)
    if not alertas_dominio:
        for site in sites:
            site_name = site.get("@name","")
            if host_objetivo in site_name:
                alertas_dominio = site.get("alerts", [])
                log(f"Sitio encontrado (fallback): {site_name} — {len(alertas_dominio)} hallazgos")
                break

    if not alertas_dominio:
        warn(f"No se encontro el dominio en el reporte. Sitios disponibles:")
        for site in sites:
            warn(f"  - {site.get('@name','')}")

    # Filtrar instancias por path objetivo: solo conservar alertas cuyas
    # instancias pertenezcan a la URL objetivo (ej. /ConsultaCSE/).
    # Esto evita que findings de otras apps del mismo dominio (ej. /cdatweb/)
    # que ZAP descubrió durante el crawl contaminen el informe.
    path_objetivo = urlparse(url).path  # ej. "/ConsultaCSE/"
    if path_objetivo and path_objetivo != "/":
        alertas_filtradas = []
        for alerta in alertas_dominio:
            instancias_ok = [
                inst for inst in alerta.get("instances", [])
                if path_objetivo in inst.get("uri", "")
            ]
            if instancias_ok:
                alerta_copia = dict(alerta)
                alerta_copia["instances"] = instancias_ok
                alerta_copia["count"] = str(len(instancias_ok))
                alertas_filtradas.append(alerta_copia)
        descartadas = len(alertas_dominio) - len(alertas_filtradas)
        if descartadas:
            log(f"Alertas de otros paths descartadas: {descartadas} (no pertenecen a {path_objetivo})")
        alertas_dominio = alertas_filtradas

    # Filtrar instancias en recursos estáticos (JS, CSS, imágenes, robots.txt...)
    alertas_dominio = _filtrar_instancias_relevantes(alertas_dominio)

    # Filtrar instancias cuya URL devolvió error HTTP (404, 500, etc.)
    alertas_dominio = _filtrar_instancias_http_error(alertas_dominio)

    # Excluir nivel Informativo (riskcode == "0") si está configurado
    if getattr(config, 'EXCLUIR_INFORMATIVOS', False):
        informativos = [a for a in alertas_dominio if str(a.get("riskcode","0")) == "0"]
        alertas_dominio = [a for a in alertas_dominio if str(a.get("riskcode","0")) != "0"]
        if informativos:
            log(f"Informativos excluidos: {len(informativos)} (no se incluyen en Word ni JSON)")

    # Ordenar Alto > Medio > Bajo
    orden = {"3":0,"2":1,"1":2}
    alertas_dominio.sort(
        key=lambda a: orden.get(str(a.get("riskcode","0")), 9)
    )

    externos = len(sites) - (1 if alertas_dominio else 0)
    ok(f"Hallazgos finales: {len(alertas_dominio)} | Sitios externos ignorados: {externos}")

    # Guardar JSON filtrado (con timestamp para no colisionar con runs anteriores)
    timestamp     = time.strftime('%Y%m%d_%H%M%S')
    ruta_filtrado = os.path.join(config.CARPETA_JSON, f"filtrado_{nombre}_{timestamp}.json")
    with open(ruta_filtrado, "w", encoding="utf-8") as f:
        json.dump({
            "url_objetivo":    url,
            "dominio":         dominio,
            "total_hallazgos": len(alertas_dominio),
            "alerts":          alertas_dominio
        }, f, ensure_ascii=False, indent=2)
    log(f"JSON guardado: filtrado_{nombre}_{timestamp}.json")

    return alertas_dominio

def _score_relevancia(alerta):
    """
    Puntaje de relevancia para elegir los Medio/Bajo más sólidos.
    Mayor score = más crítico y menos probable de ser falso positivo.
    """
    score = 0

    # Confianza — factor más determinante contra falsos positivos
    conf = int(alerta.get('confidence', 2))
    score += conf * 25

    # Instancias — reproducibilidad
    n_inst = len(alerta.get('instances', []))
    if n_inst >= 10:   score += 20
    elif n_inst >= 5:  score += 14
    elif n_inst >= 2:  score += 8
    else:              score += 2

    # CWE catalogado
    cweid = str(alerta.get('cweid', '-1'))
    if cweid not in ('-1', '0', ''):
        score += 12

    # Evidencia concreta — prueba directa de que la vulnerabilidad es real
    evidencias = [
        i.get('evidence', '').strip()
        for i in alerta.get('instances', [])
        if i.get('evidence', '').strip()
    ]
    ataques = [
        i.get('attack', '').strip()
        for i in alerta.get('instances', [])
        if i.get('attack', '').strip()
    ]
    if ataques:
        score += 30   # payload activo ejecutado — máxima certeza
    elif evidencias:
        score += 15   # evidencia pasiva capturada — certeza alta

    nombre = (alerta.get('name') or alerta.get('alert', '')).lower()

    # Penalizar tipos con alta tasa de falsos positivos en ZAP
    FP_PROPENSOS = [
        'timestamp disclosure',
        'private ip disclosure',
        'information disclosure - suspicious comments',
        'information disclosure - debug error',
        'server leaks information',
        'x-powered-by',
        'cacheable https response',
        'incomplete or no cache-control',
        'non-storable content',
        'storable and cacheable',
        'retrieved from cache',
        'big redirect',
        'http to https insecure transition',
        'https to http insecure transition',
        'permissions policy header not set',
        'referrer policy',
        'feature policy',
        'cross-domain javascript source file inclusion',
        'loosely scoped cookie',
        'user controllable html',
        'user controllable javascript event',
        'user controllable charset',
    ]
    for fp in FP_PROPENSOS:
        if fp in nombre:
            score -= 20

    # Bonus para tipos de alto impacto real
    ALTO_IMPACTO = [
        'sql injection',
        'cross-site scripting',
        'path traversal',
        'directory browsing', 'directory listing',
        'remote file inclusion',
        'open redirect',
        'csrf', 'cross-site request forgery',
        'anti-csrf',
        'clickjacking', 'x-frame-options',
        'http response splitting',
        'xml external entity',
        'server side include',
        'session fixation',
        'insecure direct object',
        'source code disclosure',
        'remote code execution',
        'command injection',
        'ldap injection', 'xpath injection',
        'insecure deserialization',
        'vulnerable js library', 'vulnerable javascript library',
        'cookie no httponly', 'cookie without secure',
        'content security policy',
        'subresource integrity',
        'mixed content',
    ]
    for hi in ALTO_IMPACTO:
        if hi in nombre:
            score += 20
            break

    return score


def priorizar_alertas(alertas):
    """
    Reglas de selección para el Word:
      Alto  → todos sin límite
      Medio → máximo 2, confianza >= Media, mayor score de relevancia
      Bajo  → máximo 2, confianza >= Media, mayor score de relevancia
    Primero deduplica por nombre conservando el de más instancias.
    """
    # Deduplicar por nombre, conservar el de más instancias
    por_nombre = {}
    for a in alertas:
        nombre = (a.get('name') or a.get('alert', '')).strip()
        existente = por_nombre.get(nombre)
        if not existente or len(a.get('instances', [])) > len(existente.get('instances', [])):
            por_nombre[nombre] = a
    alertas = list(por_nombre.values())

    UMBRAL_MEDIO = 50
    UMBRAL_BAJO  = 65

    altos  = [a for a in alertas if str(a.get('riskcode','0')) == '3']
    medios = [a for a in alertas
              if str(a.get('riskcode','0')) == '2'
              and int(a.get('confidence', 0)) >= 2
              and _score_relevancia(a) >= UMBRAL_MEDIO]
    bajos  = [a for a in alertas
              if str(a.get('riskcode','0')) == '1'
              and int(a.get('confidence', 0)) >= 2
              and _score_relevancia(a) >= UMBRAL_BAJO]

    medios_top = sorted(medios, key=_score_relevancia, reverse=True)[:3]
    bajos_top  = sorted(bajos,  key=_score_relevancia, reverse=True)[:2]

    return altos + medios_top + bajos_top

def escanear_url(url):
    """
    Escanea una URL en 3 fases. Cada fase es tolerante a fallos:
    si falla, se registra el aviso y se continúa con la siguiente.
    El JSON siempre se exporta al final con lo que ZAP haya encontrado.
    Solo lanza excepción si el export final falla (sin datos).
    """
    titulo(f"ESCANEANDO: {url}")
    inicio = time.time()

    # Crear contexto limitado al dominio del target
    ctx_nombre, ctx_id = "", ""
    try:
        ctx_nombre, ctx_id = _crear_contexto(url)
    except Exception as e:
        warn(f"No se pudo crear contexto ZAP: {e}. Continuando sin scope...")

    # Fase 1 — no crítica
    try:
        fase_spider_tradicional(url, ctx_nombre)
    except Exception as e:
        warn(f"Spider Tradicional falló, continuando: {e}")

    # Fase 2 — no crítica
    try:
        fase_spider_ajax(url, ctx_nombre)
    except Exception as e:
        warn(f"Spider AJAX falló, continuando: {e}")
        cerrar_ajax()

    # Fase 3 — no crítica
    try:
        fase_escaneo_activo(url, ctx_id)
    except Exception as e:
        warn(f"Escaneo Activo falló, continuando: {e}")

    # Export JSON — siempre se intenta con lo que ZAP tenga
    alertas = exportar_json_y_filtrar(url)
    minutos = int((time.time() - inicio) / 60)
    ok(f"URL finalizada en {minutos} min — {len(alertas)} hallazgos")
    return alertas

_CONFIG_USER = Path(__file__).parent / "config_user.json"

def _cargar_config_usuario():
    if not _CONFIG_USER.exists():
        return
    try:
        with open(_CONFIG_USER, encoding="utf-8") as f:
            data = json.load(f)
        if "ZAP_HOST"    in data: config.ZAP_HOST    = data["ZAP_HOST"]
        if "ZAP_PORT"    in data: config.ZAP_PORT    = data["ZAP_PORT"]
        if "ZAP_PORTS"   in data: config.ZAP_PORTS   = data["ZAP_PORTS"]
        if "ZAP_API_KEY" in data: config.ZAP_API_KEY = data["ZAP_API_KEY"]
    except Exception as e:
        warn(f"No se pudo cargar config_user.json: {e}")

def _guardar_config_usuario():
    data = {
        "ZAP_HOST":    config.ZAP_HOST,
        "ZAP_PORT":    config.ZAP_PORT,
        "ZAP_PORTS":   getattr(config, 'ZAP_PORTS', [config.ZAP_PORT]),
        "ZAP_API_KEY": config.ZAP_API_KEY,
    }
    with open(_CONFIG_USER, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _conectar_zap():
    """Intenta conectar a ZAP. Retorna True si conectó, False si el usuario cancela."""
    global BASE
    while True:
        puertos = getattr(config, 'ZAP_PORTS', [config.ZAP_PORT])
        zap_encontrado = False
        key_incorrecta = False
        puerto_activo  = None

        for i, puerto in enumerate(puertos):
            BASE = f"http://{config.ZAP_HOST}:{puerto}"
            try:
                r    = requests.get(f"{BASE}/JSON/core/view/version/",
                                    params={"apikey": _key()}, timeout=5)
                data = r.json()
                if data.get('code') == 'unauthorized':
                    key_incorrecta = True
                    puerto_activo  = puerto
                    break
                config.ZAP_PORT = puerto
                ok(f"ZAP conectado en {config.ZAP_HOST}:{puerto} — Versión: {data.get('version','?')}")
                zap_encontrado = True
                break
            except requests.exceptions.ConnectionError:
                if i < len(puertos) - 1:
                    log(f"Puerto {puerto} sin respuesta — probando {puertos[i+1]}...")
            except (ValueError, Exception):
                key_incorrecta = True
                puerto_activo  = puerto
                break

        if zap_encontrado:
            return True

        if key_incorrecta:
            print()
            error(f"ZAP responde en {config.ZAP_HOST}:{puerto_activo} pero el API key es incorrecto.")
            print("  Encuentra el API key en ZAP: Herramientas → Opciones → API")
            print("  (También puedes configurarlo en [3] Configuración del menú)\n")
            try:
                nueva_key = input("  Ingresa el API key (Enter para volver al menú): ").strip()
            except (EOFError, KeyboardInterrupt):
                return False
            if not nueva_key:
                return False
            config.ZAP_API_KEY = nueva_key
            config.ZAP_PORT    = puerto_activo
            _guardar_config_usuario()
        else:
            print()
            error(f"No se pudo conectar con ZAP en {config.ZAP_HOST} puertos {puertos}")
            print("  Asegúrate de que ZAP esté abierto y corriendo.")
            print("  (También puedes configurar host/puerto en [3] Configuración)\n")
            try:
                host = input(f"  Host ZAP [{config.ZAP_HOST}] (Enter para volver al menú): ").strip()
            except (EOFError, KeyboardInterrupt):
                return False
            if not host:
                return False
            if host.isdigit():
                warn(f"'{host}' parece un número de puerto, no un host. Usando 'localhost'.")
                config.ZAP_HOST = "localhost"
            else:
                config.ZAP_HOST = host
            try:
                p = input(f"  Puerto ZAP [{config.ZAP_PORT}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                return False
            if p.isdigit():
                config.ZAP_PORT  = int(p)
                config.ZAP_PORTS = [int(p)]
            else:
                config.ZAP_PORTS = [8080, 8081, 8082]
            _guardar_config_usuario()

def _menu_urls():
    while True:
        print("\n" + "─" * 62)
        print("  URLs a escanear:")
        print("─" * 62)
        if config.URLS:
            for i, url in enumerate(config.URLS, 1):
                print(f"  {i}. {url}")
        else:
            print("  (sin URLs configuradas — agrega al menos una)")
        print()
        print("  [A]   Agregar URL")
        print("  [E #] Eliminar URL  (ej: E 1)")
        print("  [X]   Eliminar todas")
        print("  [C]   Continuar y escanear")
        print("  [V]   Volver al menú")
        print("─" * 62)
        try:
            resp = input("  Opción: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        r = resp.lower()
        if r == 'v':
            return
        elif r == 'x':
            if not config.URLS:
                warn("No hay URLs que eliminar.")
                continue
            try:
                conf = input(f"  ¿Eliminar las {len(config.URLS)} URLs? [s/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if conf in ("s", "si", "sí", "y"):
                config.URLS.clear()
                ok("Todas las URLs eliminadas.")
        elif r == 'a':
            print("  Pega una o varias URLs separadas por coma:")
            print("  Ej: https://a.com, https://b.com, https://c.com\n")
            try:
                linea = input("  URLs: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not linea:
                continue
            candidatas = [u.strip() for u in linea.split(",") if u.strip()]
            validas, rechazadas = [], []
            for u in candidatas:
                if not u.startswith(("http://", "https://")):
                    rechazadas.append(u)
                elif u in config.URLS:
                    warn(f"Ya existe: {u}")
                else:
                    validas.append(u)
            if rechazadas:
                warn(f"Ignoradas (no son URLs): {', '.join(rechazadas)}")
            if not validas:
                continue
            print(f"\n  Se agregarán {len(validas)} URL(s):")
            for u in validas:
                print(f"    • {u}")
            try:
                conf = input("\n  ¿Confirmar? [s/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if conf in ("s", "si", "sí", "y"):
                config.URLS.extend(validas)
                _guardar_config_usuario()
                ok(f"{len(validas)} URL(s) agregadas.")
        elif r.startswith('e '):
            partes = r.split()
            if len(partes) == 2 and partes[1].isdigit():
                idx = int(partes[1]) - 1
                if 0 <= idx < len(config.URLS):
                    eliminada = config.URLS.pop(idx)
                    _guardar_config_usuario()
                    ok(f"URL eliminada: {eliminada}")
                else:
                    warn("Número fuera de rango.")
            else:
                warn("Usa: E <número>  (ej: E 2)")
        elif r == 'c':
            if not config.URLS:
                warn("No hay URLs. Agrega al menos una con [A].")
            else:
                _flujo_escaneo()
                return
        else:
            warn("Opción no válida.")

def _menu_configuracion():
    while True:
        key = config.ZAP_API_KEY
        key_display = (key[:4] + "****") if len(key) > 4 else "****"
        print("\n" + "─" * 62)
        print("  Configuración ZAP")
        print("─" * 62)
        print(f"  Host    : {config.ZAP_HOST}")
        print(f"  Puerto  : {config.ZAP_PORT}")
        print(f"  API Key : {key_display}")
        print()
        print("  [1] Cambiar host")
        print("  [2] Cambiar puerto")
        print("  [3] Cambiar API key")
        print("  [V] Volver")
        print("─" * 62)
        try:
            resp = input("  Opción: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        if resp.lower() == 'v':
            return
        elif resp == '1':
            try:
                nuevo = input(f"  Nuevo host [{config.ZAP_HOST}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if nuevo:
                config.ZAP_HOST = nuevo
                _guardar_config_usuario()
                ok("Host actualizado.")
        elif resp == '2':
            try:
                nuevo = input(f"  Nuevo puerto [{config.ZAP_PORT}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if nuevo.isdigit():
                config.ZAP_PORT  = int(nuevo)
                config.ZAP_PORTS = [int(nuevo)]
                _guardar_config_usuario()
                ok("Puerto actualizado.")
            else:
                warn("Ingresa un número válido.")
        elif resp == '3':
            try:
                nuevo = input("  Nueva API key: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if nuevo:
                config.ZAP_API_KEY = nuevo
                _guardar_config_usuario()
                ok("API key actualizada.")
        else:
            warn("Opción no válida.")

def _flujo_importar_zap_json():
    from convertir_zap_json import convertir_todos, CARPETA_ENTRADA
    print("\n" + "─" * 62)
    print("  Importar JSON de ZAP")
    print("─" * 62)
    print(f"  Carpeta de entrada : {CARPETA_ENTRADA.resolve()}")
    print(f"  Carpeta de salida  : {(Path(__file__).parent / config.CARPETA_JSON).resolve()}")
    print()
    print("  1. Exporta el informe desde ZAP: Informes → Generar informe → JSON")
    print("  2. Copia el .json resultante a la carpeta de entrada")
    print("  3. Presiona ENTER aquí para convertir\n")
    try:
        resp = input("  ENTER para convertir  (V para volver): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if resp == 'v':
        return

    resultados, carpeta = convertir_todos()

    if not resultados:
        warn("No hay archivos .json en la carpeta de entrada.")
        print(f"  Coloca los archivos aquí: {carpeta}")
        print("─" * 62)
        return

    print()
    total_sitios = 0
    for nombre, n, err in resultados:
        if err:
            warn(f"{nombre} → {err}")
        else:
            ok(f"{nombre} → {n} sitio(s) convertido(s)")
            total_sitios += n

    print()
    if total_sitios:
        ok(f"{total_sitios} sitio(s) listos en escaneos/  →  usa [2] para generar el Word")
    print("─" * 62)

def _menu_gestionar_urls():
    while True:
        print("\n" + "─" * 62)
        print("  URLs configuradas:")
        print("─" * 62)
        if config.URLS:
            for i, url in enumerate(config.URLS, 1):
                print(f"  {i:>2}. {url}")
        else:
            print("  (sin URLs configuradas)")
        print()
        print("  [A]   Agregar URLs")
        print("  [E #] Eliminar por número  (ej: E 3)")
        print("  [X]   Eliminar todas")
        print("  [V]   Volver al menú")
        print("─" * 62)
        try:
            resp = input("  Opción: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        r = resp.lower()
        if r == 'v':
            return
        elif r == 'x':
            if not config.URLS:
                warn("No hay URLs que eliminar.")
                continue
            try:
                conf = input(f"  ¿Eliminar las {len(config.URLS)} URLs? [s/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if conf in ("s", "si", "sí", "y"):
                config.URLS.clear()
                _guardar_config_usuario()
                ok("Todas las URLs eliminadas.")
        elif r == 'a':
            print("  Pega una o varias URLs separadas por coma:")
            print("  Ej: https://a.com, https://b.com\n")
            try:
                linea = input("  URLs: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not linea:
                continue
            candidatas = [u.strip() for u in linea.split(",") if u.strip()]
            validas, rechazadas = [], []
            for u in candidatas:
                if not u.startswith(("http://", "https://")):
                    rechazadas.append(u)
                elif u in config.URLS:
                    warn(f"Ya existe: {u}")
                else:
                    validas.append(u)
            if rechazadas:
                warn(f"Ignoradas (no son URLs): {', '.join(rechazadas)}")
            if not validas:
                continue
            print(f"\n  Se agregarán {len(validas)} URL(s):")
            for u in validas:
                print(f"    • {u}")
            try:
                conf = input("\n  ¿Confirmar? [s/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if conf in ("s", "si", "sí", "y"):
                config.URLS.extend(validas)
                _guardar_config_usuario()
                ok(f"{len(validas)} URL(s) agregadas.")
        elif r.startswith('e '):
            partes = r.split()
            if len(partes) == 2 and partes[1].isdigit():
                idx = int(partes[1]) - 1
                if 0 <= idx < len(config.URLS):
                    eliminada = config.URLS.pop(idx)
                    _guardar_config_usuario()
                    ok(f"Eliminada: {eliminada}")
                else:
                    warn("Número fuera de rango.")
            else:
                warn("Usa: E <número>  (ej: E 3)")
        else:
            warn("Opción no válida.")

def _menu_inicio():
    while True:
        key = config.ZAP_API_KEY
        if not key or key in ("x", "your_key_here"):
            key_display = "[NO CONFIGURADO]"
        elif len(key) > 6:
            key_display = key[:4] + "****"
        else:
            key_display = "****"
        print("\n")
        print("=" * 62)
        print("    ZAP AUTOMATION — GENERADOR DE INFORMES DE SEGURIDAD")
        print("=" * 62)
        print(f"  ZAP     : {config.ZAP_HOST}:{config.ZAP_PORT}")
        print(f"  API Key : {key_display}")
        print(f"  URLs    : {len(config.URLS)} configuradas")
        print("─" * 62)
        print("  [1] Ejecutar escaneo")
        print("  [2] Generar informe Word")
        print("  [3] Configuración")
        print("  [4] Gestionar URLs")
        print("  [5] Importar JSON de ZAP")
        print("  [0] Salir")
        print("─" * 62)
        try:
            resp = input("  Opción: ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
        if resp == '1':
            _menu_urls()
        elif resp == '2':
            _flujo_generar_word()
        elif resp == '3':
            _menu_configuracion()
        elif resp == '4':
            _menu_gestionar_urls()
        elif resp == '5':
            _flujo_importar_zap_json()
        elif resp == '0':
            print("  Hasta luego.\n")
            sys.exit(0)
        else:
            warn("Opción no válida.")

def _flujo_escaneo():
    if not _conectar_zap():
        return

    pausa_urls  = getattr(config, 'PAUSA_ENTRE_URLS',  60)
    tamano_lote = getattr(config, 'TAMANO_LOTE',       5)
    pausa_lote  = getattr(config, 'PAUSA_ENTRE_LOTES', 300)

    print(f"\n  URLs a escanear : {len(config.URLS)}")
    print(f"  JSONs escaneos  : {config.CARPETA_JSON}/")
    print(f"  ZAP en          : {config.ZAP_HOST}:{config.ZAP_PORT}")
    print(f"  Pausa entre URLs: {pausa_urls}s  |  Lote cada {tamano_lote} URLs  |  Pausa de lote: {pausa_lote}s\n")

    _asegurar_politica_owasp_web()
    cerrar_ajax()

    resultados   = []
    inicio_total = time.time()

    for i, url in enumerate(config.URLS):
        print(f"\n  Procesando URL {i+1} de {len(config.URLS)}: {url}")
        limpiar_sesion()
        try:
            alertas = escanear_url(url)
            conteo = {"3": 0, "2": 0, "1": 0, "0": 0}
            for a in alertas:
                rc = str(a.get("riskcode", "0"))
                if rc in conteo:
                    conteo[rc] += 1
            resultados.append({
                "url": url, "alertas": len(alertas), "estado": "OK", "nota": "",
                "alto": conteo["3"], "medio": conteo["2"],
                "bajo": conteo["1"], "info": conteo["0"],
            })
            ok(f"JSON guardado para: {url}")
        except Exception as e:
            error(f"No se pudo completar ni exportar JSON de: {url}")
            error(f"Motivo: {e}")
            resultados.append({"url": url, "alertas": 0, "estado": "ERROR", "nota": str(e)[:60]})
            cerrar_ajax()

        es_ultima = (i == len(config.URLS) - 1)
        if not es_ultima:
            if (i + 1) % tamano_lote == 0:
                print(f"\n  {'─'*62}")
                log(f"Lote de {tamano_lote} completado. Pausa de {pausa_lote}s para liberar recursos...")
                time.sleep(pausa_lote)
                log("Reanudando escaneo...")
                print(f"  {'─'*62}")
            else:
                log(f"Pausa {pausa_urls}s antes de siguiente URL (liberando recursos)...")
                time.sleep(pausa_urls)

    minutos_total = int((time.time() - inicio_total) / 60)
    print("\n")
    print("=" * 62)
    print("                   RESUMEN FINAL")
    print("=" * 62)
    for r in resultados:
        if r["estado"] == "OK":
            sev = f"Alto:{r['alto']}  Medio:{r['medio']}  Bajo:{r['bajo']}"
            print(f"  [OK   ] {r['url'][:40]:<40} | {sev}")
        else:
            print(f"  [ERROR] {r['url'][:40]:<40} | {r.get('nota','')}")
    print("=" * 62)
    print(f"\n  Tiempo total : {minutos_total} minutos")
    print(f"  JSONs en     : {config.CARPETA_JSON}/")
    print(f"\n  Para generar el informe Word cuando lo desee:")
    print(f"  > python main.py  →  opción [2]\n")

    print("─" * 62)
    try:
        resp = input("  ¿Generar informe Word ahora? [s/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        resp = "n"
    if resp in ("s", "si", "sí", "y", "yes"):
        _flujo_generar_word()
    else:
        print("  Informe no generado. Ejecuta 'python main.py' → opción [2] cuando quieras.\n")

def _flujo_generar_word():
    from traducir import traducir_alerta
    from datetime import datetime

    carpeta_json = Path(__file__).parent / config.CARPETA_JSON

    while True:
        disponibles = sorted(carpeta_json.glob("filtrado_*.json"), key=os.path.getmtime)

        if not disponibles:
            print("\n" + "─" * 62)
            warn("No hay escaneos disponibles.")
            print(f"\n  Carpeta: {carpeta_json.resolve()}")
            print("  → Opción [1] para escanear con ZAP")
            print("  → Opción [5] para importar un JSON de ZAP")
            print("─" * 62)
            return

        # Leer metadata de cada JSON
        entradas = []
        for ruta in disponibles:
            try:
                with open(ruta, encoding='utf-8') as f:
                    data = json.load(f)
                url    = data.get("url_objetivo") or data.get("dominio") or ruta.stem
                total  = data.get("total_hallazgos", len(data.get("alerts", [])))
                alerts = data.get("alerts", [])
                alto   = sum(1 for a in alerts if str(a.get("riskcode","0")) == "3")
                medio  = sum(1 for a in alerts if str(a.get("riskcode","0")) == "2")
                bajo   = sum(1 for a in alerts if str(a.get("riskcode","0")) == "1")
                fuente = " [manual]" if data.get("fuente") == "zap_manual" else ""
            except Exception:
                url, total, alto, medio, bajo, fuente = ruta.stem, 0, 0, 0, 0, ""
            fecha = datetime.fromtimestamp(ruta.stat().st_mtime).strftime("%d/%m %H:%M")
            entradas.append((ruta, url, alto, medio, bajo, fecha, fuente))

        print("\n" + "─" * 62)
        print("  Escaneos disponibles:")
        print("─" * 62)
        for i, (ruta, url, alto, medio, bajo, fecha, fuente) in enumerate(entradas, 1):
            sev = f"A:{alto} M:{medio} B:{bajo}"
            print(f"  {i:>2}. {url[:42]:<42} {sev:<14} {fecha}{fuente}")
        print()
        print("  [T]          : generar Word con todos los escaneos")
        print("  [#]          : generar solo algunos  (ej: 1,3)")
        print("  [D #]        : eliminar escaneo       (ej: D 2)")
        print("  [X]          : eliminar todos los escaneos")
        print("  [V]          : volver al menú")
        print("─" * 62)
        try:
            sel = input("  Opción: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        sl = sel.lower()

        if sl == 'v':
            return

        elif sl == 'x':
            try:
                conf = input(f"  ¿Eliminar los {len(entradas)} escaneos? [s/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if conf in ("s", "si", "sí", "y"):
                for ruta, *_ in entradas:
                    ruta.unlink(missing_ok=True)
                ok("Todos los escaneos eliminados.")
            continue

        elif sl.startswith('d '):
            partes = sl.split()
            if len(partes) == 2 and partes[1].isdigit():
                idx = int(partes[1]) - 1
                if 0 <= idx < len(entradas):
                    ruta = entradas[idx][0]
                    ruta.unlink(missing_ok=True)
                    ok(f"Eliminado: {entradas[idx][1]}")
                else:
                    warn("Número fuera de rango.")
            else:
                warn("Usa: D <número>  (ej: D 2)")
            continue

        elif sl in ('t', ''):
            jsons_usar = [e[0] for e in entradas]
            break

        else:
            # Generar Word con selección por números
            jsons_usar = []
            for s in sel.split(","):
                s = s.strip()
                if s.isdigit():
                    idx = int(s) - 1
                    if 0 <= idx < len(entradas):
                        jsons_usar.append(entradas[idx][0])
                    else:
                        warn(f"Número {s} fuera de rango, ignorado.")
            if not jsons_usar:
                warn("Usa T para todos, o ingresa números (ej: 1,3).")
                continue
            break

    # Deduplicar: si hay varios JSON para la misma URL, usar el más reciente
    vistos = {}
    for ruta in jsons_usar:
        with open(ruta, encoding='utf-8') as f:
            data = json.load(f)
        url = data.get("url_objetivo") or data.get("dominio", str(ruta.stem))
        vistos[url] = (ruta, data)

    lista_sitios = []
    for url, (ruta, data) in vistos.items():
        alertas = priorizar_alertas(data.get("alerts", []))
        alertas = [traducir_alerta(a) for a in alertas]
        lista_sitios.append((url, alertas))
        log(f"Cargado: {ruta.name}  ({len(alertas)} alertas)")

    # ── Datos del informe ─────────────────────────────────────
    print("\n" + "─" * 62)
    print("  DATOS DEL INFORME")
    print("─" * 62)
    try:
        cliente = input("  Nombre del cliente    : ").strip()
    except (EOFError, KeyboardInterrupt):
        cliente = ""

    hoy = datetime.now().strftime('%d/%m/%Y')
    try:
        fecha_raw = input(f"  Fecha [Enter = {hoy}] : ").strip()
    except (EOFError, KeyboardInterrupt):
        fecha_raw = ""
    fecha_informe = fecha_raw if fecha_raw else hoy

    print("  Tipo de prueba:")
    print("    [1] Caja Negra    [2] Caja Blanca    [3] Caja Gris")
    try:
        op_caja = input("  Selecciona [1-3]      : ").strip()
    except (EOFError, KeyboardInterrupt):
        op_caja = ""
    tipo_caja = {"1": "Caja Negra", "2": "Caja Blanca", "3": "Caja Gris"}.get(op_caja, "")
    print("─" * 62)

    print()
    log(f"Generando Word ({len(lista_sitios)} sitio(s))...")
    os.makedirs(config.CARPETA_SALIDA, exist_ok=True)
    ruta_word = generar_word_plantilla(lista_sitios, config.CARPETA_SALIDA,
                                       cliente=cliente, fecha=fecha_informe,
                                       tipo_caja=tipo_caja)
    ok(f"Word generado: {ruta_word}\n")

def main():
    _cargar_config_usuario()
    config.URLS = []
    if config.ZAP_API_KEY in ("x", "", "your_key_here"):
        print("\n" + "=" * 62)
        print("  CONFIGURACIÓN INICIAL — API Key de ZAP")
        print("=" * 62)
        print("  Encuéntralo en ZAP: Herramientas → Opciones → API\n")
        try:
            key = input("  Ingresa el API key de ZAP: ").strip()
        except (EOFError, KeyboardInterrupt):
            key = ""
        if key:
            config.ZAP_API_KEY = key
            _guardar_config_usuario()
            ok("API key guardado.")
    _menu_inicio()

if __name__ == "__main__":
    main()