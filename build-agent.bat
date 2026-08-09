@echo off
REM ============================================================
REM  Genera SENTINEL-Setup.exe : el instalador profesional del
REM  agente para el laboratorio (un solo archivo).
REM  Se corre UNA vez, en esta maquina (la que tiene Python).
REM  Resultado: un unico .exe que se copia a cada PC y con doble
REM  clic instala todo (reporte + filtro), pidiendo admin solo.
REM ============================================================
cd /d "%~dp0"

echo.
echo   == Generando SENTINEL-Setup.exe (1-2 minutos) ==
echo.
.venv\Scripts\pyinstaller --onefile --noconsole --name SENTINEL-Setup ^
  --paths . --collect-submodules sentinel --hidden-import psutil ^
  --add-data "%~dp0agente-lab\config.json;." ^
  --exclude-module PyQt6 --exclude-module PyQt6.QtWebEngineWidgets ^
  --exclude-module tkinter --exclude-module matplotlib ^
  --distpath . --workpath build-agent --specpath build-agent ^
  sentinel\field_agent.py

if not exist "SENTINEL-Setup.exe" (
  echo.
  echo   ERROR: no se genero el .exe. Revisa el mensaje de arriba y avisame.
  pause
  exit /b 1
)

echo.
echo   ==========================================================
echo    LISTO.  Se genero:  %~dp0SENTINEL-Setup.exe
echo.
echo    UN SOLO ARCHIVO. Copialo a cada PC del laboratorio
echo    (USB o red) y haz doble clic. Eso instala todo:
echo      - reporte de seguridad al panel cada 15 min
echo      - filtro de contenido (anuncios / +18 / juegos)
echo    Pide permiso de administrador solo y confirma con un aviso.
echo   ==========================================================
echo.
pause
