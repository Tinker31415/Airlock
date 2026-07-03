"""Permanent, non-recoverable deletion for malicious / illegal content.

Overwrites the file's bytes before unlinking so the contents cannot be trivially
recovered from the same disk sectors. On SSDs with wear-levelling this is not an
absolute guarantee (the controller may remap blocks), which is why the vault and
quarantine live on encrypted-at-rest storage — the safest posture is: sensitive
bytes are only ever written in ciphertext, and secure_delete removes both the
ciphertext and any plaintext working copy.
"""
from __future__ import annotations

import os
from pathlib import Path


def secure_delete(path: Path, passes: int = 3) -> None:
    p = Path(path)
    if not p.exists():
        return
    if p.is_dir():
        for child in p.iterdir():
            secure_delete(child, passes)
        p.rmdir()
        return
    try:
        length = p.stat().st_size
        with open(p, "r+b", buffering=0) as fh:
            for i in range(passes):
                fh.seek(0)
                # Pass 0/2 = random, pass 1 = zeros. Cheap defence in depth.
                pattern = os.urandom(length) if i % 2 == 0 else b"\x00" * length
                fh.write(pattern)
                fh.flush()
                os.fsync(fh.fileno())
    except OSError:
        # If we cannot overwrite (locked/errored), still attempt to unlink.
        pass
    finally:
        try:
            os.remove(p)
        except OSError:
            pass
