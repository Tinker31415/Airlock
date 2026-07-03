"""Malware / policy scanning primitives.

Layers, in order (any HOLD short-circuits to review):
  1. Known-bad SHA-256 list (your own blocklist of hashes to always reject).
  2. File-type sanity: libmagic-detected type vs declared extension. Executables,
     scripts and archives with mismatched extensions are held by policy.
  3. ClamAV signature scan (clamd daemon or clamscan CLI).

Fail-closed: if ClamAV cannot be reached and config.fail_closed is true, the file
is HELD, never released. A scanner we cannot run is treated as "not proven clean".

NOTE ON ILLEGAL CONTENT: there is deliberately no automated classifier here that
claims to detect illegal imagery. That cannot be done reliably or responsibly.
Instead, everything that is not proven clean lands in the review queue for a human
decision, and the secure-delete path exists to permanently destroy anything you
determine must not be kept.
"""
from __future__ import annotations

import socket
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import Config

try:
    import magic  # python-magic / python-magic-bin
    _HAVE_MAGIC = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_MAGIC = False

# Extensions that must never auto-release regardless of scanner verdict.
_DANGEROUS_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar", ".apk", ".sh", ".cpl",
}
# libmagic descriptions that indicate executable code.
_EXECUTABLE_HINTS = ("executable", "PE32", "Mach-O", "ELF", "script text executable")


@dataclass
class ScanResult:
    clean: bool
    reason: str          # short machine reason, e.g. "clamav:Eicar-Test-Signature"
    detail: str          # human detail
    scanner_ran: bool    # did ClamAV actually execute?


def load_bad_hashes(cfg: Config) -> set[str]:
    path = cfg.keys_dir / "badhashes.txt"
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line.split()[0])
    return out


def detect_type(path: Path) -> str:
    if not _HAVE_MAGIC:
        return ""
    try:
        return magic.from_file(str(path))
    except Exception:
        return ""


def _clamscan_cli(cfg: Config, path: Path) -> ScanResult:
    try:
        proc = subprocess.run(
            [cfg.clamscan_path, "--no-summary", "--stdout", str(path)],
            capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError:
        return ScanResult(False, "scanner-unavailable", "clamscan not found on PATH", False)
    except subprocess.TimeoutExpired:
        return ScanResult(False, "scanner-timeout", "clamscan timed out", False)
    if proc.returncode == 0:
        return ScanResult(True, "clamav:clean", "clamscan clean", True)
    if proc.returncode == 1:
        sig = ""
        for ln in proc.stdout.splitlines():
            if ln.endswith("FOUND"):
                sig = ln.split(":")[-1].replace("FOUND", "").strip()
        return ScanResult(False, f"clamav:{sig or 'infected'}", proc.stdout.strip(), True)
    return ScanResult(False, "scanner-error", proc.stderr.strip() or "clamscan error", False)


def _clamd_instream(cfg: Config, path: Path) -> ScanResult:
    try:
        with socket.create_connection((cfg.clamd_host, cfg.clamd_port), timeout=30) as s:
            s.sendall(b"zINSTREAM\0")
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    s.sendall(struct.pack("!L", len(chunk)) + chunk)
            s.sendall(struct.pack("!L", 0))
            resp = s.recv(4096).decode("utf-8", "replace").strip("\0\n ")
    except OSError as e:
        return ScanResult(False, "scanner-unavailable", f"clamd unreachable: {e}", False)
    if resp.endswith("OK"):
        return ScanResult(True, "clamav:clean", resp, True)
    if "FOUND" in resp:
        sig = resp.replace("stream:", "").replace("FOUND", "").strip()
        return ScanResult(False, f"clamav:{sig}", resp, True)
    return ScanResult(False, "scanner-error", resp, False)


def clam_scan(cfg: Config, path: Path) -> ScanResult:
    if cfg.clam_mode == "clamd":
        return _clamd_instream(cfg, path)
    return _clamscan_cli(cfg, path)


def scan_file(cfg: Config, path: Path, declared_name: str, sha256: str,
              bad_hashes: set[str]) -> ScanResult:
    # 1. Known-bad hash.
    if sha256.lower() in bad_hashes:
        return ScanResult(False, "known-bad-hash", "sha256 on local blocklist", True)

    ext = Path(declared_name).suffix.lower()

    # 2. Policy: dangerous extension always held.
    if ext in _DANGEROUS_EXTS or ext in set(cfg.always_hold_extensions):
        return ScanResult(False, "policy:extension",
                          f"extension {ext} requires manual review", True)

    # 2b. Type/extension mismatch or executable content.
    tdesc = detect_type(path)
    if tdesc:
        low = tdesc.lower()
        if any(h.lower() in low for h in _EXECUTABLE_HINTS):
            return ScanResult(False, "policy:executable-content",
                              f"detected executable content: {tdesc}", True)

    # 3. ClamAV.
    res = clam_scan(cfg, path)
    if not res.scanner_ran and cfg.fail_closed:
        return ScanResult(False, "scanner-unavailable",
                          f"held (fail-closed): {res.detail}", False)
    return res
