#!/bin/bash
echo "================================================"
echo "  ZAP Automation - Instalacion de dependencias"
echo "================================================"
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
    echo "        pip3 install requests python-docx"
    exit 1
fi

echo
echo "[OK] Todo instalado correctamente."
echo
echo "Para ejecutar el programa:"
echo "  cd zap-reportes/venv"
echo "  python3 main.py"
