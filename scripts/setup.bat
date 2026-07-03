@echo off
REM One-time setup: create a virtualenv and install dependencies.
cd /d "%~dp0.."
echo Creating virtual environment in .venv ...
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo Done. Next:
echo   1) copy config.example.yaml to config.yaml and set a strong upload_token
echo   2) run scripts\run_scanner.bat and scripts\run_ingress.bat
pause
