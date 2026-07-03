# Usage & operations

## 1. Install ClamAV (the scanner)

**Windows:** install ClamAV (e.g. the official build or `winget install ClamAV.ClamAV`).
Then fetch signatures once and note the path to `clamscan.exe`:
```
freshclam
```
Set `clamav.clamscan_path` in `config.yaml` to the full path if it isn't on PATH.
For higher throughput run the `clamd` daemon and set `clamav.mode: clamd`.

## 2. Install Airlock deps
```
scripts\setup.bat
copy config.example.yaml config.yaml
```
Edit `config.yaml`:
- `upload_token`: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- `subprojects`: the folders that may receive files
- `held_retention_days`: default 15

## 3. Choose how devices reach the upload page

**Cloudflare Tunnel (recommended, no app on devices):**
```
cloudflared tunnel login
cloudflared tunnel create secure-drop
cloudflared tunnel route dns secure-drop drop.YOURDOMAIN.com
scripts\run_tunnel.bat
```
No domain? Quick temporary URL for testing:
```
cloudflared tunnel --url http://127.0.0.1:8080
```

**Tailscale (private VPN):** install Tailscale on the PC and each device, then
browse to `http://<pc-tailscale-ip>:8080`.

## 4. Run the services

Two long-running windows:
```
scripts\run_scanner.bat     :: screens uploads, auto-purges expired held files
scripts\run_ingress.bat     :: upload server on 127.0.0.1:8080
```
Plus the tunnel from step 3. To survive reboots, register `run_scanner.bat`,
`run_ingress.bat` and the tunnel as **Windows Task Scheduler** tasks set to run
at logon (or install cloudflared as a service).

## 5. Consume files from a subproject

Library (preferred):
```python
from airlock import Airlock
drop = Airlock("BLR - open data mining")
for path in drop.pull_new(dest="./data"):   # only new since last run
    process(path)
```
CLI:
```
python -m airlock list     "BLR - open data mining"
python -m airlock pull-new  "BLR - open data mining" --dest .\data
python -m airlock pull      "BLR - open data mining" --dest .\data --all
```

### Scheduling "get data every day/week/month"

Point Windows Task Scheduler at a one-line script per subproject, e.g. daily:
```
scripts\pull.bat pull-new "BLR - open data mining" --dest "C:\...\BLR - open data mining\data"
```
Because `pull-new` advances a per-subproject cursor, each run only fetches what
arrived since the previous run — daily, weekly, or monthly all just work.

## 6. Review queue
```
python -m airlock review list
python -m airlock review show <id>
python -m airlock review approve <id>     :: release to its subproject
python -m airlock review delete <id> --reason "malware"   :: permanent
```

## 7. Status & retention
```
python -m airlock status         :: counts, oldest-held age, disk, per-subproject
python -m airlock janitor         :: purge held-past-retention now (also automatic)
```

## Known-bad hashes

Add SHA-256 hashes (one per line) to `storage/keys/badhashes.txt` to always
reject matching files.
