import json
import re
from pathlib import Path
import config

CARPETA_ENTRADA = Path(__file__).parent / "zap_exports"
CARPETA_SALIDA  = Path(__file__).parent / config.CARPETA_JSON

def _limpiar_html(texto):
    if not texto:
        return ""
    return re.sub(r"<[^>]+>", " ", texto).strip()

def convertir(ruta_json):
    with open(ruta_json, encoding="utf-8") as f:
        data = json.load(f)

    sitios = data.get("site", [])
    if not sitios:
        return 0, "No contiene sección 'site'"

    convertidos = 0
    for sitio in sitios:
        url = sitio.get("@name") or sitio.get("@host", "desconocido")
        if not url.startswith("http"):
            url = "https://" + url

        alertas_raw = sitio.get("alerts", [])
        alertas = []
        conf_min = getattr(config, 'CONFIANZA_MINIMA', 3)
        for a in alertas_raw:
            # Descartar hallazgos con confianza menor a la mínima
            # (Media/Baja = potenciales falsos positivos)
            try:
                conf = int(a.get("confidence", 0) or 0)
            except (ValueError, TypeError):
                conf = 0
            if conf < conf_min:
                continue
            instancias = [
                {
                    "uri":      inst.get("uri", ""),
                    "param":    inst.get("param", ""),
                    "evidence": inst.get("evidence", ""),
                    "attack":   inst.get("attack", ""),
                }
                for inst in a.get("instances", [])
            ]
            alertas.append({
                "name":       a.get("name") or a.get("alert", ""),
                "riskcode":   str(a.get("riskcode", "0")),
                "confidence": str(a.get("confidence", "1")),
                "cweid":      str(a.get("cweid", "0")),
                "desc":       _limpiar_html(a.get("desc", "")),
                "solution":   _limpiar_html(a.get("solution", "")),
                "instances":  instancias,
            })

        dominio = url.rstrip("/")
        slug    = re.sub(r"[^\w]", "_", dominio)[:60]
        salida  = CARPETA_SALIDA / f"filtrado_{slug}.json"

        resultado = {
            "url_objetivo":    url,
            "dominio":         dominio,
            "total_hallazgos": len(alertas),
            "fuente":          "zap_manual",
            "alerts":          alertas,
        }

        CARPETA_SALIDA.mkdir(exist_ok=True)
        with open(salida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=2, ensure_ascii=False)

        convertidos += 1

    return convertidos, None

def convertir_todos():
    CARPETA_ENTRADA.mkdir(exist_ok=True)

    archivos = list(CARPETA_ENTRADA.glob("*.json"))
    if not archivos:
        return [], str(CARPETA_ENTRADA.resolve())

    resultados = []
    for ruta in archivos:
        n, err = convertir(ruta)
        resultados.append((ruta.name, n, err))

    return resultados, str(CARPETA_ENTRADA.resolve())
