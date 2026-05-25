# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Automated security report generation pipeline. Runs OWASP ZAP scans against a configurable list of URLs and produces a Word document based on a template. Also supports importing ZAP JSON exports.

Designed to be used by any analyst for any client — all client-specific settings live in `config.py` and the Word template.

All working scripts live in `zap-reportes/venv/`. The venv is broken (pyvenv.cfg points to a non-existent path). Use system Python instead:
```
cd zap-reportes/venv
python main.py
python regenerar_word.py
```

## Installation (new machine)

```
cd zap-reportes/venv
pip install -r requirements.txt
```

Required packages: `requests`, `python-docx`, `lxml`, `matplotlib`, `deep_translator`.

After installing, configure the ZAP API key from the `[3] Configuración` menu in `main.py`. The key is saved to `config_user.json` (excluded from git).

## Commands

**Run a full ZAP scan + generate report (ZAP must be running):**
```
cd zap-reportes/venv
python main.py
```

**Regenerate the Word report from existing JSON results (no ZAP required):**
```
cd zap-reportes/venv
python regenerar_word.py
```
Both scripts prompt for: client name, report date (free text — e.g. "MAYO 2026" or "24/05/2026"), and test type (Caja Negra / Caja Blanca / Caja Gris). If a field is left empty the placeholder remains in red in the document.

**Import a ZAP JSON export and convert it to the internal format:**
Use option `[5] Importar JSON de ZAP` in the main menu, or place the `.json` files in `zap_exports/` and run `convertir_zap_json.py`.

## Architecture

### Data flow

```
ZAP API  ──► main.py ──────────────────────► escaneos/filtrado_*.json
                                                        │
ZAP JSON ──► convertir_zap_json.py ───────────────────►│
                                                        │
                                         regenerar_word.py / main.py [2]
                                                        │
                                         ┌──────────────┼──────────────┐
                                    main.priorizar_alertas()            │
                                    traducir.traducir_alerta()          │
                                    generador.generar_word_plantilla() ─┘
                                                        │
                                         informes/reporte_consolidado_*.docx
```

### File responsibilities

| File | Role |
|------|------|
| `config.py` | ZAP connection settings, URL list, scan timeouts, AJAX browser config, scan policy |
| `config_user.json` | Machine-local overrides (ZAP host/port/key) — auto-created, excluded from git |
| `main.py` | Full scan engine (Context → Spider → AJAX Spider → Active Scan) + alert filtering/scoring + interactive menu |
| `traducir.py` | EN→ES translation dictionary + CWE mapping by vulnerability name |
| `generador.py` | Word document engine — all python-docx logic lives here |
| `regenerar_word.py` | Standalone entry point for report generation from existing JSONs (no ZAP needed) |
| `convertir_zap_json.py` | Converts ZAP-exported JSON reports to the internal `filtrado_*.json` format |

### Scan engine (`main.py`)

Each URL is scanned in 3 phases inside a ZAP Context scoped to that domain:

1. **Spider Tradicional** — crawls static HTML links recursively
2. **Spider AJAX** — browser fallback chain: Firefox → Chrome → htmlunit (static sites only) → skip with warning
3. **Active Scan** — fires real payloads (SQLi, XSS, etc.) using the `OWASP_Web` policy

**AJAX browser fallback logic:**
- Tries `AJAX_BROWSER` from config first, then Firefox, then Chrome (in that order)
- htmlunit is only used as last resort when `_es_sitio_estatico()` confirms no SPA markers (React/Angular/Vue/etc.)
- If no browser is found, AJAX phase is skipped with a clear warning — scan continues with Spider Tradicional only

**ZAP connection auto-detection:**
- Tries ports from `ZAP_PORTS` list in order (`[8080, 8081, 8082]` by default)
- Updates `BASE` and `config.ZAP_PORT` globally when a responding port is found
- Exits with clear error if no port responds

The `OWASP_Web` policy is created automatically on first run. All web-relevant rules at HIGH strength and HIGH alert threshold — only HIGH-confidence findings are reported. Non-web rules (Buffer Overflow, Padding Oracle, SOAP) are disabled.

The ZAP Context (`target_scan`) restricts all phases to the target domain only.

### Alert filtering pipeline (`exportar_json_y_filtrar`)

Alerts go through this chain before being written to JSON:

1. **Static resource filter** (`_filtrar_instancias_relevantes`): removes passive-finding instances on `.js`, `.css`, images, fonts, etc. Active findings (with `attack` field) are always kept.
2. **HTTP error filter** (`_filtrar_instancias_http_error`): removes instances whose URL returned 4xx/5xx (fetched via ZAP message API, cached). Only keeps codes in `{200,201,204,301,302,303,307,308}`.
3. **Informativo exclusion**: drops riskcode=0 alerts when `EXCLUIR_INFORMATIVOS=True`.
4. Alerts with no remaining instances after filtering are dropped entirely.

### Alert selection logic (`main.priorizar_alertas`)

- **Alto (riskcode=3)**: all findings included, no cap
- **Medio (riskcode=2)**: top 3 by score, confidence ≥ Media (2), score ≥ 50
- **Bajo (riskcode=1)**: top 2 by score, confidence ≥ Media (2), score ≥ 65
- Findings below threshold are discarded — not reported
- Informativos excluded by default (`EXCLUIR_INFORMATIVOS=True` in config)

**Relevance score formula:**
```
score = confidence×25
      + instance_count_bonus  (2/8/14/20 for 1/2-4/5-9/10+)
      + CWE_bonus             (+12 if cweid is set and non-zero)
      + evidence_bonus        (+30 active attack payload / +15 passive evidence / +0 absence)
      + high_impact_bonus     (+20 if name matches known critical vuln types)
      − FP_penalty            (−20 if name matches known false-positive patterns)
```

### Word generation (`generador.generar_word_plantilla`)

Signature: `generar_word_plantilla(lista_sitios, carpeta_salida, cliente="", fecha=None, tipo_caja="")`

- `cliente`: replaces `(CLIENTE)` placeholders throughout the document
- `fecha`: replaces `(FECHA)` — accepts any string (e.g. "MAYO 2026", "24/05/2026"); defaults to today
- `tipo_caja`: replaces `(TIPO DE CAJA)` in the Limitaciones section — must be one of "Caja Negra", "Caja Blanca", "Caja Gris"
- If any parameter is empty, the placeholder remains visible in red in the output document

**Cover page placeholder replacement:**
The template cover page uses Word text boxes (`w:txbxContent`). `doc.paragraphs` does NOT include text box content — replacement uses `doc.element.body.iter(qn('w:txbxContent'))` directly. Word sometimes splits a placeholder like `(FECHA)` across two XML runs; the replacement function assembles the full paragraph text first, finds the placeholder by position, then patches the affected runs.

Key behaviors:
- **Table counter starts at 2** — the template already has Tabla 1 (criticality) and Tabla 2 (URLs)
- **No second TOC** — the template already has a TOC field; the generator does not add another
- **Anchor-based insertion**: content is inserted between `Resumen Ejecutivo Global` and `Recomendaciones` headings
- **URL table**: dynamically replaces the Nro./URL Analizadas/Status table in "Alcance del servicio"
- **Evidence row**: included in each finding's detail table only when concrete evidence exists in instances

Per-URL section structure (inside section 5):
- `5.N Hallazgos #N: dominio`
  - `5.N.1 Tabla de Hallazgos`
  - `5.N.2 Detalle de Hallazgos`

Severity colors used throughout all tables:
- Alto: `C00000` (dark red)
- Medio: `ED7D31` (orange)
- Bajo: `0070C0` (blue)
- Informativo: dark green (excluded from reports)

### Terminal summary

After scanning all URLs, the terminal shows per-URL breakdown:
```
[OK   ] https://target.com         | Alto:0  Medio:2  Bajo:2
```
Informativos are excluded from the summary display.

After scan completes, user is prompted: `¿Generar informe Word ahora? [s/n]`

### JSON format (filtrado_*.json)

```json
{
  "url_objetivo": "https://...",
  "dominio": "https://...",
  "total_hallazgos": 5,
  "alerts": [ { "name": "...", "riskcode": "3", "confidence": "2",
                "cweid": "79", "desc": "...", "solution": "...",
                "instances": [{"uri": "...", "param": "...", "evidence": "...", "attack": "..."}] } ]
}
```
ZAP-import JSONs include `"fuente": "zap_manual"`.

## Configuration (`config.py`)

Key settings to adjust before running:
- `URLS`: list of target URLs to scan
- `ZAP_API_KEY`: must match the key configured in the running ZAP instance
- `ZAP_PORT`: default port to try first (`8080`)
- `ZAP_PORTS`: list of ports tried in order until ZAP responds (default `[8080, 8081, 8082]`)
- `SCAN_POLICY`: default `"OWASP_Web"` — created automatically on first run
- `AJAX_ENABLED`: set to `False` to skip AJAX spider entirely
- `AJAX_BROWSER`: `"firefox"` or `"chrome-headless"` — tried first; falls back to the other, then htmlunit (static only), then skip
- `EXCLUIR_INFORMATIVOS`: `True` by default — keeps informatives out of reports
- `CARPETA_SALIDA`: output folder for Word reports (default `informes/`)
- `CARPETA_JSON`: output folder for JSON scan results (default `escaneos/`)

Runtime overrides (host, port, key) are saved to `config_user.json` and loaded automatically on startup.

## Template location

```
Documento_modelo/
```

Place the Word template (.docx) in this folder. The path is resolved relative to `generador.py`. The template uses Spanish Word style names: `Ttulo1`, `Ttulo2`, `Listaconvietas`, `Prrafodelista`, `Descripcin`. The generator tries these first, then falls back to `Heading 1`/`Heading 2`.

The template must contain these heading anchors (exact text):
- `Resumen Ejecutivo Global` — content is inserted after this heading
- `Conclusiones` or `Recomendaciones` — content insertion stops before this heading

## Git / deployment notes

- The venv `Lib/`, `Scripts/`, `escaneos/`, `informes/`, `nessus/`, `config_user.json`, and `Documento_modelo/` are excluded via `.gitignore`
- Only source files are committed: `*.py`, `CLAUDE.md`, `.gitignore`, `requirements.txt`
- `ZAP_API_KEY` in `config.py` is a placeholder (`"x"`) — real key is stored in `config_user.json` on each machine
- On a new machine: `pip install -r requirements.txt`, then set the API key from the menu
