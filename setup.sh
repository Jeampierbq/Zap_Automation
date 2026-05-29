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
if [ ! -d "$VENV" ]; then
    echo "[INFO] Creando entorno virtual..."
    "$PYTHON_CMD" -m venv "$VENV" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "[INFO] Instalando python3-venv..."
        sudo apt-get install -y python3-venv python3-full 2>/dev/null || \
        sudo dnf install -y python3-venv 2>/dev/null
        "$PYTHON_CMD" -m venv "$VENV"
    fi
fi

PYTHON_VENV="$VENV/bin/python"
PIP_VENV="$VENV/bin/pip"

echo "[INFO] Actualizando pip..."
"$PIP_VENV" install --upgrade pip >/dev/null 2>&1
echo "[INFO] Instalando dependencias..."
# Nota: pywin32 (en requirements.txt) solo se instala en Windows; en Linux pip lo
# ignora por el marcador de plataforma. El indice del Word se actualizara al abrir
# el documento en una maquina con Microsoft Word.
"$PIP_VENV" install -r "$ROOT/zap-reportes/venv/requirements.txt"
if [ $? -ne 0 ]; then
    echo
    echo "[ERROR] Fallo la instalacion de dependencias."
    exit 1
fi

echo
echo "============================================================"
echo "  Instalacion completada. Iniciando programa..."
echo "============================================================"
echo
cd "$ROOT/zap-reportes/venv"
"$PYTHON_VENV" main.py
