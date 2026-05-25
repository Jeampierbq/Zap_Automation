#!/bin/bash
cd "$(dirname "$0")"

echo "============================================================"
echo "  ZAP AUTOMATION - Instalacion completa desde cero"
echo "============================================================"
echo

# ── Actualizar proyecto automaticamente si hay git ──
if command -v git &>/dev/null; then
    echo "[INFO] Actualizando proyecto desde GitHub..."
    git pull
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
        sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip
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
echo "[INFO] Instalando dependencias..."
"$PYTHON_CMD" -m pip install -r zap-reportes/venv/requirements.txt
if [ $? -ne 0 ]; then
    echo
    echo "[ERROR] Fallo la instalacion. Intenta con sudo:"
    echo "        sudo $PYTHON_CMD -m pip install -r zap-reportes/venv/requirements.txt"
    exit 1
fi

echo
echo "============================================================"
echo "  Instalacion completada. Iniciando programa..."
echo "============================================================"
echo
cd zap-reportes/venv
"$PYTHON_CMD" main.py
