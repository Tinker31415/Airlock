@echo off
REM Start the upload server (localhost only; expose it via the Cloudflare Tunnel).
cd /d "%~dp0.."
call .venv\Scripts\activate.bat
python -m uvicorn airlock.ingress:app --host 127.0.0.1 --port 8080
