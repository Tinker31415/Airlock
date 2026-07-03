@echo off
REM Expose the local ingress server to your other devices via Cloudflare Tunnel.
REM
REM First-time setup (run these once in a terminal, they open a browser to log in):
REM   cloudflared tunnel login
REM   cloudflared tunnel create secure-drop
REM   cloudflared tunnel route dns secure-drop drop.YOURDOMAIN.com
REM Then edit this file's TUNNEL name if different, and run it.
REM
REM No domain? For a quick temporary URL (changes each run, fine for testing):
REM   cloudflared tunnel --url http://127.0.0.1:8080
REM
cloudflared tunnel --url http://127.0.0.1:8080 run secure-drop
