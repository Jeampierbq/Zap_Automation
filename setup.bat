@echo off
echo ================================================
echo   ZAP Automation - Instalacion de dependencias
echo ================================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python no encontrado.
    echo         Instala Python desde https://python.org
    echo         Marca "Add Python to PATH" durante la instalacion.
    echo.
    pause
    exit /b 1
)

echo [INFO] Instalando dependencias Python...
pip install -r zap-reportes\venv\requirements.txt

if errorlevel 1 (
    echo.
    echo [ERROR] Fallo la instalacion. Intenta manualmente:
    echo         pip install requests python-docx
    echo.
    pause
    exit /b 1
)

echo.
echo [OK] Todo instalado correctamente.
echo.
echo Para ejecutar el programa:
echo   cd zap-reportes\venv
echo   python main.py
echo.
pause
