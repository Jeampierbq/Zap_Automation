@echo off
echo ============================================================
echo   ZAP AUTOMATION - Instalacion y arranque
echo ============================================================
echo.
echo Instalando dependencias...
pip install -r zap-reportes\venv\requirements.txt
echo.
echo ============================================================
echo   Instalacion completada. Iniciando programa...
echo ============================================================
echo.
cd zap-reportes\venv
python main.py
pause
