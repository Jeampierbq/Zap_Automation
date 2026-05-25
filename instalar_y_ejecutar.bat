@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo   ZAP AUTOMATION - Instalacion completa desde cero
echo ============================================================
echo.

REM ── Buscar Python (python / python3 / py launcher) ──
set PYTHON_CMD=
for %%c in (python python3 py) do (
    if not defined PYTHON_CMD (
        %%c --version >nul 2>&1
        if not errorlevel 1 set PYTHON_CMD=%%c
    )
)
if defined PYTHON_CMD goto python_listo

REM ── Python no encontrado, instalar automaticamente ──
echo [INFO] Python no encontrado. Instalando automaticamente...
echo.

winget --version >nul 2>&1
if not errorlevel 1 (
    echo [INFO] Instalando Python 3.12 con winget...
    winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
    set "PATH=%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%PATH%"
    python --version >nul 2>&1
    if not errorlevel 1 ( set PYTHON_CMD=python & goto python_listo )
)

echo [INFO] Descargando instalador de Python 3.12...
powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile '%TEMP%\python_setup.exe'"
if errorlevel 1 (
    echo.
    echo [ERROR] No se pudo descargar Python. Verifica tu conexion a internet.
    echo         Descarga manualmente desde: https://python.org
    pause & exit /b 1
)
echo [INFO] Instalando Python (puede tardar un minuto)...
"%TEMP%\python_setup.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1
del "%TEMP%\python_setup.exe" >nul 2>&1
set "PATH=%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%PATH%"
python --version >nul 2>&1
if not errorlevel 1 ( set PYTHON_CMD=python & goto python_listo )

echo.
echo [ERROR] No se pudo instalar Python automaticamente.
echo         Instala manualmente desde: https://python.org
echo         (marca "Add Python to PATH" durante la instalacion)
pause & exit /b 1

:python_listo
echo [OK] Python listo.
echo.
echo [INFO] Instalando dependencias...
%PYTHON_CMD% -m pip install -r zap-reportes\venv\requirements.txt
if errorlevel 1 (
    echo.
    echo [ERROR] Fallo la instalacion de dependencias.
    pause & exit /b 1
)

echo.
echo ============================================================
echo   Instalacion completada. Iniciando programa...
echo ============================================================
echo.
cd zap-reportes\venv
%PYTHON_CMD% main.py
pause
