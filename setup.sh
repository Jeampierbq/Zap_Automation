#!/bin/bash
echo "============================================================"
echo "  ZAP AUTOMATION - Instalacion y arranque"
echo "============================================================"
echo

if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python no encontrado."
    echo "        Instala Python: sudo apt install python3 python3-pip"
    exit 1
fi

echo "[INFO] Instalando dependencias Python..."
pip3 install -r zap-reportes/venv/requirements.txt

if [ $? -ne 0 ]; then
    echo
    echo "[ERROR] Fallo la instalacion. Intenta manualmente:"
    echo "        pip3 install requests python-docx lxml matplotlib deep_translator"
    exit 1
fi

echo
echo "============================================================"
echo "  Instalacion completada. Iniciando programa..."
echo "============================================================"
echo
cd zap-reportes/venv
python3 main.py
