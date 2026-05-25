"""
Regenera el Word consolidado usando los JSON filtrados existentes.
No requiere ZAP corriendo.
"""
import os, json, sys
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).parent
sys.path.insert(0, str(BASE))

from generador import generar_word_plantilla
from main import priorizar_alertas
from traducir import traducir_alerta

CARPETA_JSON = BASE / "escaneos"
CARPETA_WORD = BASE / "informes"

# ── Lee todos los JSON filtrados, ordenados por fecha de creación ──
jsons = sorted(
    CARPETA_JSON.glob("filtrado_*.json"),
    key=os.path.getmtime
)

if not jsons:
    print("No se encontraron archivos filtrado_*.json en", CARPETA_JSON)
    sys.exit(1)

# Deduplicar: si hay varios JSON para la misma URL, usar el más reciente
vistos = {}
for ruta in jsons:
    with open(ruta, encoding='utf-8') as f:
        data = json.load(f)
    url = data.get("url_objetivo") or data.get("dominio", str(ruta.stem))
    vistos[url] = (ruta, data)   # sobreescribe con el más reciente

lista_sitios = []
for url, (ruta, data) in vistos.items():
    alertas = priorizar_alertas(data.get("alerts", []))
    # Traducir y completar CWE de cada alerta
    alertas = [traducir_alerta(a) for a in alertas]
    lista_sitios.append((url, alertas))
    print(f"  Cargado: {ruta.name}  ({len(alertas)} alertas)")

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

print(f"\nGenerando Word con plantilla OFIS ({len(lista_sitios)} sitios)...")
CARPETA_WORD.mkdir(exist_ok=True)
ruta_word = generar_word_plantilla(lista_sitios, str(CARPETA_WORD),
                                   cliente=cliente, fecha=fecha_informe,
                                   tipo_caja=tipo_caja)
print(f"\nWord generado: {ruta_word}")