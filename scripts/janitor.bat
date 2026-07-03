@echo off
REM Manually run the retention purge (also runs automatically inside the scanner).
cd /d "%~dp0.."
call .venv\Scripts\activate.bat
python -m airlock janitor %*
