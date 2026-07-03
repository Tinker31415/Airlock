# Security model

## Goals

1. Nothing uploaded is usable until it has been screened.
2. Malware is caught; if the scanner can't run, files are **held, not released**.
3. Content that must not be kept can be **permanently destroyed**.
4. A subproject can only read files addressed to it.
5. Data is encrypted at rest.

## Transport

- The ingress server binds to `127.0.0.1` only. It is exposed to your devices
  through a **Cloudflare Tunnel** (TLS terminated by Cloudflare) or **Tailscale**
  (WireGuard mesh). Nothing on the public internet can reach the server directly.
- Uploads require a shared `upload_token`, compared in constant time.
- Uploads are size-capped and streamed; filenames are sanitized; content is
  never executed or opened by the server.

## Screening (fail-closed)

Order: known-bad SHA-256 → file-type/extension policy (executables, scripts,
type/extension mismatches held) → ClamAV signatures. If ClamAV cannot be
reached and `fail_closed: true`, the file is **held**. A scanner that did not
run is treated as "not proven clean".

**Illegal content:** deliberately not auto-classified. Not-clean files go to a
human review queue; the reviewer approves or permanently deletes.

## Encryption at rest

- Fernet (AES-128-CBC + HMAC-SHA256, authenticated) for every stored file.
- One 32-byte master key in `keys/master.key` (0600 where the OS allows).
- Per-subproject keys are HKDF-derived from the master key.

### Trust boundary (be honest)

The master key lives on the same always-on machine that runs Airlock. So
per-subproject isolation is **defence-in-depth**, not protection against an
attacker who already has your OS account / root. It *does* protect against:
a leaked single-subproject key, a stolen individual vault file, a compromised
subproject process reading another subproject's data, and casual disk access.

To raise the bar: keep `storage_dir` on an OS-encrypted volume (BitLocker /
FileVault / LUKS), restrict the folder's ACLs to your user, and consider moving
`master.key` to a hardware token or OS keystore.

## Secure deletion

`securedelete.py` overwrites file bytes (random/zero passes) before unlinking.
On SSDs with wear-levelling this is not absolute — which is why sensitive bytes
are only ever written as ciphertext, so a purge removes the only decryptable copy.

## Retention

Files left in the held state longer than `held_retention_days` (default 15) are
securely purged automatically by the janitor (hourly inside the scanner, and on
demand via `python -m airlock janitor`).

## What to keep out of git

`config.yaml`, `storage/`, `keys/`, `*.key`, and `badhashes.txt` are
`.gitignore`d. Never commit your `upload_token` or the master key.
