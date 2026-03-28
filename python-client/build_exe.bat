@echo off
setlocal
cd /d "%~dp0"

set "ROOT_DIR=%~dp0.."
set "LOCAL_PY=%ROOT_DIR%\.python312\python.exe"
set "PY_CMD=python"
set "EXE_NAME=CloudXLauncher_FEATUREPACK"
set "ICON_PATH=%~dp0assets\stremer-404.ico"

if exist "%LOCAL_PY%" (
  set "PY_CMD=%LOCAL_PY%"
) else (
  where python >nul 2>&1
  if errorlevel 1 (
    echo Python is not installed or not in PATH.
    exit /b 1
  )
)

"%PY_CMD%" -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
  echo Installing PyInstaller...
  "%PY_CMD%" -m pip install --upgrade pip >nul
  "%PY_CMD%" -m pip install pyinstaller
  if errorlevel 1 (
    echo Failed to install PyInstaller.
    exit /b 1
  )
) else (
  echo PyInstaller is already installed.
)

if not exist dist mkdir dist

if exist "%ROOT_DIR%\CloudXLauncher.exe" del /f /q "%ROOT_DIR%\CloudXLauncher.exe"
if exist "%ROOT_DIR%\CloudXLauncher_v2.exe" del /f /q "%ROOT_DIR%\CloudXLauncher_v2.exe"
if exist "%ROOT_DIR%\CloudXLauncher_NEW.exe" del /f /q "%ROOT_DIR%\CloudXLauncher_NEW.exe"
if exist "%ROOT_DIR%\CloudXLauncher_NEW_UI.exe" del /f /q "%ROOT_DIR%\CloudXLauncher_NEW_UI.exe"
if exist "%ROOT_DIR%\CloudXLauncher_FEATUREPACK.exe" del /f /q "%ROOT_DIR%\CloudXLauncher_FEATUREPACK.exe"
if exist "%~dp0dist\CloudXLauncher.exe" del /f /q "%~dp0dist\CloudXLauncher.exe"
if exist "%~dp0dist\CloudXLauncher_NEW.exe" del /f /q "%~dp0dist\CloudXLauncher_NEW.exe"
if exist "%~dp0dist\CloudXLauncher_NEW_UI.exe" del /f /q "%~dp0dist\CloudXLauncher_NEW_UI.exe"
if exist "%~dp0dist\CloudXLauncher_FEATUREPACK.exe" del /f /q "%~dp0dist\CloudXLauncher_FEATUREPACK.exe"

echo Building %EXE_NAME%.exe...
if exist "%ICON_PATH%" (
  "%PY_CMD%" -m PyInstaller --noconfirm --clean --onefile --windowed --name %EXE_NAME% --icon "%ICON_PATH%" launcher.py
) else (
  "%PY_CMD%" -m PyInstaller --noconfirm --clean --onefile --windowed --name %EXE_NAME% launcher.py
)
if errorlevel 1 (
  echo Build failed.
  exit /b 1
)

copy /y "%~dp0dist\%EXE_NAME%.exe" "%ROOT_DIR%\%EXE_NAME%.exe" >nul

echo Done.
echo EXE path: %ROOT_DIR%\%EXE_NAME%.exe
endlocal
