# Airlock

**A quarantined, malware-scanned, encrypted file drop for your subprojects.**

Airlock is a small always-on service that lets any of your devices — phones,
iPads, laptops that are *not* on your home network — drop files onto your
machine safely. Every file is quarantined, screened for malware, and only
*cleared* files are released. Cleared files are encrypted per-subproject and
made available to background tasks by name.

```
  phone / iPad                 your always-on PC
  ┌──────────┐   HTTPS    ┌──────────────────────────────────────────────┐
  │  browser  │──tunnel──▶│  ingress → quarantine → scan → vault          │
  │  upload   │           │                              │                │
  └──────────┘           │        held (review) ◀───────┤ not clean       │
                          │            │ >15d → purge     │ clean          │
                          │            ▼                  ▼                │
                          │      secure delete     per-subproject vault    │
                          └──────────────────────────────┬────────────────┘
                                                          │  by name
                                          from airlock import Airlock
                                          Airlock("Project A").pull_new(...)
```

---

## Why it exists

You want to move a file from a device that isn't on your LAN onto your hard
disk, but you don't want unscreened content landing directly in a project
folder. Airlock gives you a single front door with decontamination built in:

- **One drop point** reachable from anywhere (Cloudflare Tunnel / Tailscale).
- **Quarantine + malware scan** (ClamAV) before anything is usable.
- **Fail-closed**: if the scanner can't run, files are held, never released.
- **Per-subproject isolation**: cleared files are encrypted with a key derived
  for that subproject; only that subproject can decrypt them.
- **Human review** for anything not auto-cleared, with **permanent secure
  deletion** for malicious / unwanted content.
- **Automatic retention purge**: anything stuck awaiting clearance for more
  than 15 days (configurable) is securely destroyed.
- **By-name access** for subprojects, including **cursor-based pulls** so a
  scheduled "get new data daily/weekly/monthly" job only fetches what's new.

## An honest note on "illegal content"

Airlock reliably scans for **malware**. It does **not** pretend to automatically
detect illegal imagery — that cannot be done responsibly or accurately, and a
false decision there has serious consequences. Instead, everything that is not
proven clean is routed to a **human review queue**, and the secure-delete path
lets you permanently destroy anything that must not be kept. The 15-day
retention purge bounds how long unreviewed content can sit on disk.

---

## Quick start (Windows)

1. **Install ClamAV** (the scanner) and make sure `clamscan` is on your PATH,
   or set its full path in `config.yaml`. Run `freshclam` once to fetch
   signatures. See `docs/USAGE.md`.
2. **Install dependencies**
   ```
   scripts\setup.bat
   ```
3. **Configure**
   ```
   copy config.example.yaml config.yaml
   ```
   Edit `config.yaml`: set a strong `upload_token`
   (`python -c "import secrets; print(secrets.token_urlsafe(32))"`) and list
   your `subprojects`.
4. **Run the two background services** (each in its own window):
   ```
   scripts\run_scanner.bat      :: quarantine + scan + auto-purge
   scripts\run_ingress.bat      :: the upload web server (localhost)
   ```
5. **Expose the upload page to your devices**
   ```
   scripts\run_tunnel.bat       :: Cloudflare Tunnel -> your private URL
   ```
   Open that URL on your phone/iPad, paste the token once, pick a subproject,
   upload. Bookmark it.

## Using it from a subproject

```python
from airlock import Airlock

drop = Airlock("BLR - open data mining")

# Scheduled daily/weekly/monthly job: only newly-cleared files.
for path in drop.pull_new(dest="./data"):
    process(path)
```

Or from the command line:

```
python -m airlock list     "BLR - open data mining"
python -m airlock pull-new  "BLR - open data mining" --dest .\data
python -m airlock status
```

See `examples/subproject_daily_pull.py` and `docs/USAGE.md` for scheduling.

## Reviewing held files

```
python -m airlock review list            # what's waiting
python -m airlock review show <id>        # details + verdict
python -m airlock review approve <id>     # release to its subproject
python -m airlock review delete <id>      # PERMANENT secure deletion
```

## Documentation

- `docs/ARCHITECTURE.md` — components, data flow, file states.
- `docs/SECURITY.md` — threat model, encryption, trust boundaries, hardening.
- `docs/USAGE.md` — install, transport setup, scheduling, operations.

## Status

Verified end-to-end (see `tests/test_pipeline.py`): crypto round-trip,
per-subproject isolation, manifest lifecycle, secure delete, all scan-decision
layers (EICAR), quarantine→vault→release, cursor pulls, and the retention purge.

## License

MIT — see `LICENSE`.
