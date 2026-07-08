#!/bin/bash
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "============================================================"
echo "  ZAP AUTOMATION - Instalacion completa desde cero"
echo "============================================================"
echo

# ── Actualizar proyecto automaticamente si hay git ──
if command -v git &>/dev/null && [ -d ".git" ]; then
    echo "[INFO] Actualizando proyecto desde GitHub..."
    git fetch origin && git reset --hard origin/main
    echo
fi

# ── Buscar Python ──
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON_CMD="$cmd"
        break
    fi
done

# ── Si no hay Python, instalarlo automaticamente ──
if [ -z "$PYTHON_CMD" ]; then
    echo "[INFO] Python no encontrado. Instalando automaticamente..."
    echo
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip python3-venv
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3 python3-pip
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3 python3-pip
    elif command -v brew &>/dev/null; then
        brew install python3
    else
        echo "[ERROR] No se pudo instalar Python automaticamente."
        echo "        Instala manualmente: https://python.org"
        exit 1
    fi

    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            PYTHON_CMD="$cmd"
            break
        fi
    done
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "[ERROR] Python no disponible. Instala manualmente: https://python.org"
    exit 1
fi

echo "[OK] Python listo ($PYTHON_CMD)."
echo

# ── Crear entorno virtual si no existe ──
VENV="$ROOT/.venv"
USE_VENV=true
if [ ! -d "$VENV" ]; then
    echo "[INFO] Creando entorno virtual..."
    "$PYTHON_CMD" -m venv "$VENV" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[INFO] Instalando python3-venv..."
        sudo apt-get install -y python3-venv python3-full 2>/dev/null || \
        sudo dnf install -y python3-venv 2>/dev/null
        "$PYTHON_CMD" -m venv "$VENV"
        if [ $? -ne 0 ]; then
            echo "[AVISO] No se pudo crear entorno virtual. Usando pip del sistema..."
            USE_VENV=false
        fi
    fi
fi

if [ "$USE_VENV" = true ] && [ -f "$VENV/bin/python" ]; then
    PYTHON_VENV="$VENV/bin/python"
    PIP_VENV="$VENV/bin/pip"
else
    PYTHON_VENV="$PYTHON_CMD"
    PIP_VENV="$PYTHON_CMD -m pip"
    USE_VENV=false
fi

echo "[INFO] Actualizando pip..."
$PIP_VENV install --upgrade pip >/dev/null 2>&1

echo "[INFO] Instalando dependencias..."
# pywin32 solo se instala en Windows (marcador sys_platform en requirements.txt).
# En Linux pip lo ignora automaticamente sin error.
$PIP_VENV install -r "$ROOT/zap-reportes/venv/requirements.txt"
if [ $? -ne 0 ]; then
    echo
    echo "[AVISO] Fallo instalacion en venv. Reintentando con --break-system-packages..."
    $PIP_VENV install -r "$ROOT/zap-reportes/venv/requirements.txt" --break-system-packages
    if [ $? -ne 0 ]; then
        echo
        echo "[ERROR] Fallo la instalacion de dependencias. Intenta manualmente:"
        echo "        pip install -r zap-reportes/venv/requirements.txt --break-system-packages"
        exit 1
    fi
fi

# ── Verificar que los paquetes criticos quedaron instalados ──
echo "[INFO] Verificando instalacion..."
PAQUETES_FALTANTES=""
for pkg in requests python-docx lxml matplotlib deep_translator; do
    $PYTHON_VENV -c "import importlib; importlib.import_module('$(echo $pkg | tr - _)')" 2>/dev/null
    if [ $? -ne 0 ]; then
        PAQUETES_FALTANTES="$PAQUETES_FALTANTES $pkg"
    fi
done
if [ -n "$PAQUETES_FALTANTES" ]; then
    echo "[ERROR] Los siguientes paquetes no se instalaron correctamente:$PAQUETES_FALTANTES"
    echo "        Intenta manualmente: pip install$PAQUETES_FALTANTES --break-system-packages"
    exit 1
fi
echo "[OK] Todos los paquetes instalados correctamente."

echo
echo "============================================================"
echo "  Instalacion completada."
echo "============================================================"
echo
echo "  NOTA: El grafico de barras del informe Word sera una imagen"
echo "        estatica (PNG) en Linux/Mac porque esta maquina no"
echo "        tiene Microsoft Word instalado."
echo "        Para obtener un grafico nativo editable, genera el"
echo "        informe desde una maquina Windows con Word instalado."
echo
echo "  Iniciando programa..."
echo
cd "$ROOT/zap-reportes/venv"
"$PYTHON_VENV" main.py
