@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo   ZAP AUTOMATION - Instalacion completa desde cero
echo ============================================================
echo.

REM ── Actualizar proyecto automaticamente ──
if exist ".git\" (
    git --version >nul 2>&1
    if not errorlevel 1 (
        echo [INFO] Actualizando desde GitHub...
        git fetch origin && git reset --hard origin/main
        echo.
    )
) else (
    echo [INFO] Descargando ultima version desde GitHub...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='%~dp0'; $z=[IO.Path]::Combine($env:TEMP,'zap_upd.zip'); $e=[IO.Path]::Combine($env:TEMP,'zap_upd'); try { iwr 'https://github.com/Jeampierbq/Zap_Automation/archive/refs/heads/main.zip' -OutFile $z -UseBasicParsing; Expand-Archive $z $e -Force; Copy-Item (Join-Path $e 'Zap_Automation-main' '*') $p -Recurse -Force; Remove-Item $z,$e -Recurse -Force; Write-Host '[OK] Proyecto actualizado.' } catch { Write-Host '[WARN] Sin conexion. Continuando con version actual.' }"
    echo.
)

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
echo [INFO] Actualizando pip...
%PYTHON_CMD% -m pip install --upgrade pip >nul 2>&1
echo [INFO] Instalando dependencias...
echo        (incluye pywin32: actualiza el indice del Word automaticamente)
%PYTHON_CMD% -m pip install -r zap-reportes\venv\requirements.txt
if errorlevel 1 (
    echo.
    echo [ERROR] Fallo la instalacion de dependencias.
    pause & exit /b 1
)

echo.
echo ============================================================
echo   Instalacion completada.
echo ============================================================
echo.

REM ── Verificar si Microsoft Word esta instalado ──
powershell -NoProfile -Command "try { $w = New-Object -ComObject Word.Application; $w.Quit(); Write-Host '[OK] Microsoft Word detectado: el grafico del informe sera nativo y editable.' } catch { Write-Host '[AVISO] Microsoft Word NO detectado. El grafico del informe sera una imagen estatica (PNG).' ; Write-Host '        Instala Microsoft Word para obtener graficos editables.' }"
echo.

echo   Iniciando programa...
echo.
cd zap-reportes\venv
%PYTHON_CMD% main.py
pause
