"""
traducir.py
-----------
Traduccion de nombres/descripciones/soluciones de vulnerabilidades al español.
Usa diccionario local primero; si no hay match, intenta deep_translator (Google).
Tambien incluye mapeo de CWE por nombre de vulnerabilidad.
"""

import re

# ─────────────────────────────────────────────────────────────
# DICCIONARIO DE TRADUCCIONES CONOCIDAS
# ─────────────────────────────────────────────────────────────
NOMBRES_ES = {
    # Nessus
    "HSTS Missing From HTTPS Server-":
        "Servidor HTTPS sin cabecera HSTS configurada",
    "HSTS Missing From HTTPS Server (RFC 6797)-":
        "Servidor HTTPS sin HSTS (RFC 6797)",
    "Web Application Potentially Vulnerable to Clickjacking-":
        "Aplicación Web potencialmente vulnerable a Clickjacking",
    "Web Server Allows Password Auto-Completion-":
        "Servidor Web permite autocompletar contraseñas",
    "Backup Files Disclosure-":
        "Exposición de archivos de respaldo",
    "CGI Generic Injectable Parameter-":
        "Parámetro CGI genérico inyectable",
    "Missing or Permissive Content-Security-Policy frame-ancestors HTTP Response Header-":
        "Cabecera CSP frame-ancestors ausente o permisiva",
    "Missing or Permissive X-Frame-Options HTTP Response Header-":
        "Cabecera X-Frame-Options ausente o permisiva",
    "Web Application Cookies Not Marked HttpOnly-":
        "Cookies sin atributo HttpOnly",
    "Web Application Cookies Not Marked Secure-":
        "Cookies sin atributo Secure",
    "Web Application Potentially Sensitive CGI Parameter Detection-":
        "Detección de parámetros CGI potencialmente sensibles",
    "HTTP Cookie 'secure' Property Transport Mismatch-":
        "Cookie con propiedad 'secure' en transporte no cifrado",
    "Web Server No 404 Error Code Check-":
        "Servidor Web no retorna código 404 correcto",
    "Web Application Sitemap-":
        "Sitemap de aplicación web expuesto",
    "Web Server Directory Enumeration-":
        "Enumeración de directorios en servidor web",
    "HTTP Methods Allowed (per directory)-":
        "Métodos HTTP permitidos por directorio",
    "HTTP Server Type and Version-":
        "Tipo y versión de servidor HTTP expuestos",
    "HyperText Transfer Protocol (HTTP) Information-":
        "Información del protocolo HTTP expuesta",
    "HyperText Transfer Protocol (HTTP) Redirect Information-":
        "Información de redirección HTTP expuesta",
    "External URLs-":
        "URLs externas detectadas",
    "Web Server Office File Inventory-":
        "Inventario de archivos Office en servidor web",
    "Web Server robots.txt Information Disclosure-":
        "Divulgación de información en robots.txt",
    "HTTP/2 Cleartext Detection-":
        "Detección de HTTP/2 en texto claro",
    "Web Application Potentially Vulnerable to Clickjacking":
        "Aplicación Web potencialmente vulnerable a Clickjacking",
    "Web Server Allows Password Auto-Completion":
        "Servidor Web permite autocompletar contraseñas",
    "JQuery Detection-":
        "Detección de versión jQuery",
    "Web mirroring-":
        "Duplicación/mirror del sitio web detectada",
    "Web Server Directory Enumeration-":
        "Enumeración de directorios en servidor web",
    "Web Server Allows Password Auto-Completion-":
        "Servidor Web permite autocompletar contraseñas",
    "HSTS Missing From HTTPS Server (RFC 6797)-":
        "Servidor HTTPS sin HSTS (RFC 6797)",
    "Web Application Potentially Vulnerable to Clickjacking-":
        "Aplicación web potencialmente vulnerable a Clickjacking",
    "Backup Files Disclosure-":
        "Exposición de archivos de respaldo",

    # ZAP
    "Content Security Policy (CSP) Header Not Set":
        "Cabecera Content Security Policy (CSP) no configurada",
    "Missing Anti-clickjacking Header":
        "Cabecera anti-clickjacking ausente",
    "X-Content-Type-Options Header Missing":
        "Cabecera X-Content-Type-Options ausente",
    "Server Leaks Version Information via 'Server' HTTP Response Header Field":
        "Servidor expone versión mediante cabecera HTTP 'Server'",
    "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)":
        "Servidor expone información mediante cabecera 'X-Powered-By'",
    "Strict-Transport-Security Header Not Set":
        "Cabecera Strict-Transport-Security no configurada",
    "Cookie Without Secure Flag":
        "Cookie sin indicador Secure",
    "Cookie No HttpOnly Flag":
        "Cookie sin indicador HttpOnly",
    "Cookie without SameSite Attribute":
        "Cookie sin atributo SameSite",
    "Absence of Anti-CSRF Tokens":
        "Ausencia de tokens Anti-CSRF",
    "Cross-Domain JavaScript Source File Inclusion":
        "Inclusión de archivo JavaScript de dominio cruzado",
    "Information Disclosure - Debug Error Messages":
        "Divulgación de información - Mensajes de error de depuración",
    "Information Disclosure - Sensitive Information in URL":
        "Divulgación de información sensible en URL",
    "Vulnerable JS Library":
        "Librería JavaScript vulnerable",
    "PII Disclosure":
        "Divulgación de Información Personal Identificable (PII)",
    "Timestamp Disclosure - Unix":
        "Divulgación de timestamp Unix",
    "Hash Disclosure - MD5 Crypt":
        "Divulgación de hash MD5",
    "Application Error Disclosure":
        "Divulgación de error de aplicación",
    "SQL Injection":
        "Inyección SQL",
    "Cross Site Scripting (Reflected)":
        "Cross-Site Scripting (XSS) Reflejado",
    "Cross Site Scripting (Stored)":
        "Cross-Site Scripting (XSS) Almacenado",
    "Path Traversal":
        "Traversal de rutas (Path Traversal)",
    "Remote File Inclusion":
        "Inclusión remota de archivos",
    "Remote Code Execution - CVE-2012-1823":
        "Ejecución remota de código - CVE-2012-1823",
    "XSLT Injection":
        "Inyección XSLT",
    "Server Side Request Forgery":
        "Falsificación de solicitudes del lado del servidor (SSRF)",
    "Hidden File Found":
        "Archivo oculto encontrado",
    "Permissions Policy Header Not Set":
        "Cabecera Permissions Policy no configurada",
    "Deprecated Feature Policy Header Set":
        "Cabecera Feature Policy obsoleta configurada",
    "Loosely Scoped Cookie":
        "Cookie con alcance amplio",
    "User Agent Fuzzer":
        "Fuzzer de User-Agent",
    "A Client Error response code was returned by the server":
        "El servidor retornó un código de error de cliente",
    "A Server Error response code was returned by the server":
        "El servidor retornó un código de error del servidor",
    "In Page Banner Information Leak":
        "Fuga de información en banner de página",
    "Re-examine Cache-control Directives":
        "Revisar directivas Cache-Control",
    "Modern Web Application":
        "Aplicación Web moderna detectada",
    "Storable and Cacheable Content":
        "Contenido almacenable y cacheable",
    "Non-Storable Content":
        "Contenido no almacenable",
    "Retrieved from Cache":
        "Contenido recuperado desde caché",
}

# ─────────────────────────────────────────────────────────────
# MAPEO CWE POR NOMBRE DE VULNERABILIDAD
# ─────────────────────────────────────────────────────────────
CWE_MAP = {
    # Patrones (subcadena en minúsculas → CWE)
    "clickjacking":             "CWE-1021",
    "x-frame-options":          "CWE-1021",
    "frame-ancestors":          "CWE-1021",
    "hsts":                     "CWE-319",
    "strict-transport":         "CWE-319",
    "autocomplete":             "CWE-522",
    "password auto-completion": "CWE-522",
    "backup files":             "CWE-538",
    "information disclosure":   "CWE-200",
    "server leaks":             "CWE-200",
    "information leak":         "CWE-200",
    "injectable parameter":     "CWE-74",
    "sql injection":            "CWE-89",
    "cross site scripting":     "CWE-79",
    "xss":                      "CWE-79",
    "csrf":                     "CWE-352",
    "anti-csrf":                "CWE-352",
    "path traversal":           "CWE-22",
    "remote file inclusion":    "CWE-98",
    "remote code execution":    "CWE-94",
    "ssrf":                     "CWE-918",
    "server side request":      "CWE-918",
    "cookie.*secure":           "CWE-614",
    "cookie.*httponly":         "CWE-1004",
    "cookie.*samesite":         "CWE-1275",
    "csp":                      "CWE-693",
    "content security policy":  "CWE-693",
    "x-content-type":           "CWE-693",
    "permissions policy":       "CWE-693",
    "cache-control":            "CWE-525",
    "debug error":              "CWE-209",
    "application error":        "CWE-209",
    "version information":      "CWE-200",
    "x-powered-by":             "CWE-200",
    "javascript.*vulnerable":   "CWE-829",
    "vulnerable js":            "CWE-829",
    "directory enumeration":    "CWE-548",
    "robots.txt":               "CWE-200",
    "http methods":             "CWE-16",
    "xslt injection":           "CWE-91",
    "pii":                      "CWE-359",
    "timestamp":                "CWE-200",
    "hash disclosure":          "CWE-327",
}

def obtener_cwe(nombre_vuln):
    """Devuelve el CWE más apropiado según el nombre de la vulnerabilidad."""
    nombre_lower = nombre_vuln.lower()
    for patron, cwe in CWE_MAP.items():
        if re.search(patron, nombre_lower):
            return cwe
    return "0"

# ─────────────────────────────────────────────────────────────
# TRADUCCION
# ─────────────────────────────────────────────────────────────
_cache_traducciones = {}

def _traducir_con_api(texto):
    """Intenta traducir con deep_translator (Google). Devuelve None si falla."""
    try:
        from deep_translator import GoogleTranslator
        resultado = GoogleTranslator(source='en', target='es').translate(texto)
        return resultado
    except Exception:
        return None

def traducir(texto):
    """
    Traduce texto de inglés a español.
    1. Busca en diccionario local.
    2. Si no encuentra, intenta deep_translator.
    3. Si falla, devuelve el texto original.
    """
    if not texto or not texto.strip():
        return texto

    # Buscar coincidencia exacta en diccionario
    if texto in NOMBRES_ES:
        return NOMBRES_ES[texto]

    # Buscar sin guion al final
    texto_limpio = texto.rstrip("-").strip()
    if texto_limpio in NOMBRES_ES:
        return NOMBRES_ES[texto_limpio]

    # Cache de traducciones previas
    if texto in _cache_traducciones:
        return _cache_traducciones[texto]

    # Intentar API
    resultado = _traducir_con_api(texto)
    if resultado and resultado != texto:
        _cache_traducciones[texto] = resultado
        return resultado

    return texto

def traducir_alerta(alerta):
    """Traduce name, desc, solution de una alerta y completa CWE si falta."""
    a = dict(alerta)
    a["name"]     = traducir(a.get("name", ""))
    a["desc"]     = traducir(a.get("desc", ""))
    a["solution"] = traducir(a.get("solution", ""))

    # Completar CWE si está vacío o es "0"
    if not a.get("cweid") or a.get("cweid") == "0":
        a["cweid"] = obtener_cwe(alerta.get("name", ""))

    return a