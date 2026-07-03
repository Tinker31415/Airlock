@echo off
REM Start the quarantine scanner (watches for new uploads and screens them).
cd /d "%~dp0.."
call .venv\Scripts\activate.bat
python -m airlock.pipeline --watch
