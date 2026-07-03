# Architecture

## Components

| Module | Role |
|---|---|
| `airlock/ingress.py` | FastAPI upload server + mobile web page. Token auth, size cap, streams to quarantine with a metadata sidecar. Never opens content. |
| `airlock/pipeline.py` | The scanner loop. Picks up quarantined files, screens them, routes clean→vault / not-clean→held. Runs the janitor hourly. |
| `airlock/scanner.py` | Screening layers: known-bad hash list, file-type/extension policy, ClamAV (clamd or clamscan). Fail-closed. |
| `airlock/vault.py` | Encrypts cleared files into the per-subproject vault; decrypts on request. |
| `airlock/crypto.py` | Master key + HKDF-derived per-subproject keys; Fernet encrypt/decrypt; permission lock-down. |
| `airlock/manifest.py` | SQLite source of truth: every file's lifecycle, audit log, per-subproject consumption cursors. |
| `airlock/janitor.py` | Retention purge: securely deletes anything held past the retention limit. |
| `airlock/review.py` | Human review console: list / show / approve / permanently delete. |
| `airlock/client.py` | The `Airlock` class — how subprojects consume their files by name. |
| `airlock/status.py` | Operational snapshot. |
| `airlock/__main__.py` | Unified `python -m airlock <cmd>` CLI. |

## Data flow

```
device ──HTTPS(tunnel)──▶ ingress ──▶ quarantine/incoming/<id>.bin + <id>.json
                                            │
                              pipeline picks it up, moves to quarantine/working/
                                            │
                                   scanner.scan_file()
                         ┌──────────────────┴───────────────────┐
                     clean                                   not clean
                         │                                       │
             vault/<subproject>/<id>.enc              quarantine/held/<id>.enc
             (encrypted with subproject key)          (encrypted with _held key)
             manifest status = released               manifest status = held
                         │                                       │
             subproject pull_new()                    review approve → vault
             decrypt with subproject key              review delete  → secure_delete
                                                       janitor >15d   → secure_delete
```

## File states (manifest)

`received → scanning → released | held`, then `held → released (approved)` or
`held → deleted | purged` (secure delete). Every transition is written to the
append-only `audit` table.

## Path convention

Every `vault_path` stored in the manifest is **relative to `storage_dir`**
(e.g. `vault/Project A/<id>.enc`, `quarantine/held/<id>.enc`). The janitor,
review console and clients all resolve paths the same way against
`storage_dir`.

## Per-subproject isolation

`derive_subproject_key(master, name) = HKDF-SHA256(master, info="subproject:<name>")`.
Each subproject's files are encrypted under its own key. A process holding only
one subproject's key — or someone who copies another subproject's vault file —
cannot decrypt data that isn't theirs (wrong key → authentication failure).

## Consumption cursors

The `cursors` table stores a per-subproject high-water mark. `pull_new()` returns
only files released after the cursor and advances it, so a scheduled job fetches
exactly what arrived since it last ran. `pull()` ignores the cursor and returns
everything; `reset_cursor()` rewinds it.
