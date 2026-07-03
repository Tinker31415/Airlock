"""Ingress upload server.

A tiny FastAPI app that any of your devices can reach through a Cloudflare Tunnel
(or Tailscale). Open the URL in a phone/iPad browser, enter the access token once,
pick a target subproject, and upload. No app install, no per-device account.

Security posture:
* Requires the shared upload token (constant-time comparison).
* Streams to a temp file with a hard size cap, computes sha256 on the way in.
* Writes into quarantine/incoming atomically, with a .json sidecar of metadata.
* Never executes or opens uploaded content. The scanner (separate process)
  picks it up from quarantine.

Run behind HTTPS only (the Cloudflare Tunnel terminates TLS for you). Bind to
127.0.0.1 so nothing but the tunnel can reach it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from .config import load_config
from .manifest import Manifest
from .vault import UNASSIGNED

cfg = load_config()
cfg.ensure_dirs()
manifest = Manifest(cfg.db_path)

app = FastAPI(title="secure-ingest", docs_url=None, redoc_url=None, openapi_url=None)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")
_CHUNK = 1024 * 1024


def _check_token(supplied: str) -> None:
    if not supplied or not hmac.compare_digest(supplied, cfg.upload_token):
        raise HTTPException(status_code=401, detail="Invalid or missing token.")


def _sanitize(name: str) -> str:
    name = Path(name or "upload.bin").name
    name = _SAFE_NAME.sub("_", name).strip() or "upload.bin"
    return name[:200]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    options = "\n".join(
        f'<option value="{sp}">{sp}</option>' for sp in cfg.subprojects
    )
    return PAGE.replace("{{OPTIONS}}", options)


@app.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"ok": True, "subprojects": cfg.subprojects})


@app.post("/upload")
async def upload(
    request: Request,
    token: str = Form(...),
    subproject: str = Form(UNASSIGNED),
    uploader: str = Form("device"),
    file: UploadFile = Form(...),
) -> JSONResponse:
    _check_token(token)

    if subproject and subproject != UNASSIGNED and subproject not in cfg.subprojects:
        raise HTTPException(status_code=400, detail="Unknown subproject.")

    original = _sanitize(file.filename)
    fid = uuid.uuid4().hex
    tmp = cfg.incoming_dir / f".{fid}.part"
    sha = hashlib.sha256()
    size = 0

    cfg.incoming_dir.mkdir(parents=True, exist_ok=True)
    try:
        with open(tmp, "wb") as out:
            while True:
                chunk = await file.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > cfg.max_upload_bytes:
                    raise HTTPException(status_code=413, detail="File too large.")
                sha.update(chunk)
                out.write(chunk)
    except HTTPException:
        tmp.unlink(missing_ok=True)
        raise
    except Exception:
        tmp.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Upload failed.")

    digest = sha.hexdigest()
    record_id = manifest.create(
        original_name=original,
        uploader=_sanitize(uploader),
        subproject=(None if subproject == UNASSIGNED else subproject),
        size_bytes=size,
    )
    manifest.update(record_id, sha256=digest)

    # Move into place + write metadata sidecar. Use record_id as the on-disk name.
    final = cfg.incoming_dir / f"{record_id}.bin"
    tmp.rename(final)
    sidecar = cfg.incoming_dir / f"{record_id}.json"
    sidecar.write_text(json.dumps({
        "id": record_id,
        "original_name": original,
        "sha256": digest,
        "size_bytes": size,
        "uploader": _sanitize(uploader),
        "subproject": None if subproject == UNASSIGNED else subproject,
        "received_at": time.time(),
        "remote_ip": request.client.host if request.client else None,
    }, indent=2), encoding="utf-8")

    return JSONResponse({"ok": True, "id": record_id, "sha256": digest,
                         "status": "quarantined"})


PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Secure Drop</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; margin: 0;
         background: #0f1420; color: #e7ecf3; }
  .wrap { max-width: 520px; margin: 0 auto; padding: 28px 20px 60px; }
  h1 { font-size: 20px; margin: 8px 0 4px; }
  p.sub { color: #93a1b5; margin: 0 0 22px; font-size: 14px; }
  label { display:block; font-size:13px; color:#b6c2d4; margin: 16px 0 6px; }
  input, select, button { width:100%; font-size:16px; padding:13px 14px;
    border-radius:12px; border:1px solid #2a3446; background:#161d2b; color:#e7ecf3; }
  .drop { border:2px dashed #33405a; border-radius:16px; padding:26px 16px;
    text-align:center; color:#93a1b5; margin-top:6px; }
  button { margin-top:22px; background:#3b82f6; border:none; font-weight:600;
    color:#fff; }
  button:disabled { opacity:.5; }
  .status { margin-top:18px; font-size:14px; white-space:pre-wrap; }
  .ok { color:#4ade80; } .err { color:#f87171; }
  .row { display:flex; gap:8px; align-items:center; justify-content:space-between; }
  small { color:#6b7a90; }
</style></head><body>
<div class="wrap">
  <h1>Secure Drop</h1>
  <p class="sub">Files are quarantined and malware-scanned before release. Nothing is
  made available until it clears.</p>

  <label for="token">Access token</label>
  <input id="token" type="password" autocomplete="current-password" placeholder="Paste your token"/>

  <label for="subproject">Deliver to</label>
  <select id="subproject">
    <option value="_unassigned">(unassigned — hold in vault)</option>
    {{OPTIONS}}
  </select>

  <label for="file">File</label>
  <div class="drop">
    <input id="file" type="file" multiple/>
  </div>

  <button id="go">Upload</button>
  <div class="status" id="status"></div>
  <p style="margin-top:26px"><small>Tip: bookmark this page. Your token is remembered on this device only.</small></p>
</div>
<script>
const $ = id => document.getElementById(id);
try { const t = localStorage.getItem('drop_token'); if (t) $('token').value = t; } catch(e){}
$('go').onclick = async () => {
  const token = $('token').value.trim();
  const sp = $('subproject').value;
  const files = $('file').files;
  const s = $('status');
  if (!token) { s.className='status err'; s.textContent='Enter your access token.'; return; }
  if (!files.length) { s.className='status err'; s.textContent='Pick at least one file.'; return; }
  try { localStorage.setItem('drop_token', token); } catch(e){}
  $('go').disabled = true; s.className='status'; s.textContent='';
  let done = 0, lines = [];
  for (const f of files) {
    const fd = new FormData();
    fd.append('token', token); fd.append('subproject', sp);
    fd.append('uploader', navigator.userAgent.slice(0,60)); fd.append('file', f);
    try {
      const r = await fetch('/upload', { method:'POST', body: fd });
      const j = await r.json();
      if (r.ok) { done++; lines.push('OK  ' + f.name + '  (' + j.status + ')'); }
      else lines.push('ERR ' + f.name + '  ' + (j.detail || r.status));
    } catch(e) { lines.push('ERR ' + f.name + '  ' + e); }
    s.className = 'status'; s.textContent = lines.join('\\n');
  }
  s.className = 'status ' + (done===files.length ? 'ok':'err');
  s.textContent = lines.join('\\n') + '\\n\\n' + done + '/' + files.length + ' quarantined.';
  $('go').disabled = false;
};
</script>
</body></html>"""
