ZAP_HOST  = "localhost"
ZAP_PORT  = 8080
ZAP_PORTS = [8080, 8081, 8082]   # se prueban en orden hasta encontrar ZAP activo
ZAP_API_KEY = "x" # coloca tu key de ZAP aquí

URLS = []

CARPETA_SALIDA = "informes"
CARPETA_JSON   = "escaneos"

TIEMPO_SPIDER        = 1800   # red de seguridad: 30 min (spider suele terminar solo antes)
TIEMPO_SPIDER_AJAX   = 7200   # red de seguridad: 2 horas
TIEMPO_ESCANEO       = 14400  # red de seguridad: 4 horas

AJAX_BROWSER         = "firefox"
AJAX_ENABLED         = True    # Cambiar a False si el browser falla y no para el escaneo
AJAX_MAX_DURATION    = 0       # 0 = sin límite — ZAP para solo cuando agota los caminos
AJAX_MAX_CRAWL_DEPTH = 10

SCAN_POLICY          = "OWASP_Web"
EXCLUIR_INFORMATIVOS = True

# ── Gestión de recursos entre escaneos ──────────────────────────────
PAUSA_ENTRE_URLS  = 60    # segundos de pausa entre cada URL (permite liberar RAM y CPU)
TAMANO_LOTE       = 5     # cada cuántas URLs hacer una pausa larga
PAUSA_ENTRE_LOTES = 300   # segundos de pausa larga entre lotes (5 min)