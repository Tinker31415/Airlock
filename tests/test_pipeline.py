"""End-to-end checks. Run from the project root:  python -m tests.test_pipeline

Covers: crypto round-trip, per-subproject key isolation, manifest lifecycle,
secure delete, scan decision layers, and the full quarantine->vault->release flow
using the industry-standard EICAR antivirus test file.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from cryptography.fernet import InvalidToken

from airlock import crypto, vault
from airlock.config import Config
from airlock.manifest import Manifest
from airlock.pipeline import run_pass
from airlock.scanner import scan_file
from airlock.securedelete import secure_delete

# The official EICAR test string. Harmless; every AV flags it.
EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

PASS, FAIL = "\033[92mPASS\033[0m", "\033[91mFAIL\033[0m"
_results = []


def check(name: str, cond: bool) -> None:
    _results.append(cond)
    print(f"  [{PASS if cond else FAIL}] {name}")


def make_cfg(root: Path) -> Config:
    cfg = Config(
        storage_dir=root / "storage",
        upload_token="test-token-strong",
        host="127.0.0.1", port=8080,
        max_upload_bytes=512 * 1024 * 1024,
        subprojects=["Project A", "Project B"],
        clam_mode="clamscan", clamd_host="127.0.0.1", clamd_port=3310,
        clamscan_path="clamscan", fail_closed=True,
        always_hold_extensions=[],
    )
    cfg.ensure_dirs()
    return cfg


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="ingest-test-"))
    try:
        cfg = make_cfg(root)
        master = crypto.load_or_create_master_key(cfg.master_key_path)

        print("\n1. Crypto round-trip + per-subproject isolation")
        ka = crypto.derive_subproject_key(master, "Project A")
        kb = crypto.derive_subproject_key(master, "Project B")
        secret = b"top secret bytes"
        token = crypto.encrypt_bytes(ka, secret)
        check("decrypt with correct key returns plaintext",
              crypto.decrypt_bytes(ka, token) == secret)
        check("derived keys differ per subproject", ka != kb)
        wrong_key_failed = False
        try:
            crypto.decrypt_bytes(kb, token)
        except InvalidToken:
            wrong_key_failed = True
        check("decrypt with another subproject's key FAILS", wrong_key_failed)

        print("\n2. Manifest lifecycle")
        m = Manifest(cfg.db_path)
        fid = m.create("doc.pdf", "phone", "Project A", 123)
        m.update(fid, sha256="abc", status="released")
        row = m.get(fid)
        check("row persists with updated fields",
              row is not None and row["status"] == "released" and row["sha256"] == "abc")

        print("\n3. Secure delete")
        victim = root / "victim.bin"
        victim.write_bytes(b"delete me" * 1000)
        secure_delete(victim)
        check("file is gone after secure_delete", not victim.exists())

        print("\n4. Scan decision layers")
        exe = root / "thing.exe"
        exe.write_bytes(b"MZ fake")
        r_exe = scan_file(cfg, exe, "thing.exe", "0" * 64, set())
        check("dangerous extension is held", not r_exe.clean and r_exe.reason == "policy:extension")

        badhash_file = root / "known.dat"
        badhash_file.write_bytes(b"whatever")
        import hashlib
        h = hashlib.sha256(b"whatever").hexdigest()
        r_bad = scan_file(cfg, badhash_file, "known.dat", h, {h})
        check("known-bad hash is held", not r_bad.clean and r_bad.reason == "known-bad-hash")

        eicar = root / "eicar.txt"
        eicar.write_text(EICAR)
        eh = hashlib.sha256(eicar.read_bytes()).hexdigest()
        r_eicar = scan_file(cfg, eicar, "eicar.txt", eh, set())
        clam_available = shutil.which(cfg.clamscan_path) is not None
        if clam_available:
            check("EICAR flagged by ClamAV", not r_eicar.clean and "clamav" in r_eicar.reason)
        else:
            check("no ClamAV -> EICAR held fail-closed (not released)",
                  not r_eicar.clean and r_eicar.reason == "scanner-unavailable")

        print("\n5. Full pipeline: clean file -> vault -> subproject release")
        # A benign file, clean per policy. If ClamAV is absent, fail-closed will
        # hold it; we assert accordingly so the test is valid either way.
        m2 = Manifest(cfg.db_path)
        good_id = m2.create("notes.txt", "ipad", "Project A", 5)
        (cfg.incoming_dir / f"{good_id}.bin").write_text("hello")
        import json
        (cfg.incoming_dir / f"{good_id}.json").write_text(json.dumps({
            "id": good_id, "original_name": "notes.txt", "sha256":
            hashlib.sha256(b"hello").hexdigest(), "subproject": "Project A"}))
        run_pass(cfg, master, m2)
        row = m2.get(good_id)
        if clam_available:
            check("clean file auto-released", row["status"] == "released")
            check("vault ciphertext exists",
                  (cfg.storage_dir / row["vault_path"]).exists())
            # Project A can decrypt; Project B cannot.
            out = root / "out.bin"
            vault.decrypt_from_vault(cfg, master, "Project A", row["vault_path"], out)
            check("Project A decrypts its file", out.read_bytes() == b"hello")
            iso = False
            try:
                vault.decrypt_from_vault(cfg, master, "Project B", row["vault_path"], root / "x")
            except InvalidToken:
                iso = True
            check("Project B CANNOT decrypt Project A's file", iso)
        else:
            check("clean file held fail-closed (no ClamAV in this env)",
                  row["status"] == "held")
            print("      (install ClamAV to exercise the release + isolation path)")

        print("\n6. Cursor-based pulls (scheduled 'get new data' use case)")
        mc = Manifest(cfg.db_path)
        import time as _t
        f1 = mc.create("a.txt", "dev", "Project A", 1)
        mc.update(f1, status="released", vault_path="Project A/x1.enc",
                  received_at=_t.time() - 100)

        def new_ids(m=mc):
            return [r["id"] for r in m.released_since("Project A", m.get_cursor("Project A"))]

        check("new file visible before first pull", f1 in new_ids())
        rows = mc.released_since("Project A", mc.get_cursor("Project A"))
        mc.set_cursor("Project A", max(r["received_at"] for r in rows))
        check("cursor consumes existing", new_ids() == [])
        f2 = mc.create("b.txt", "dev", "Project A", 1)
        mc.update(f2, status="released", vault_path="Project A/x2.enc")
        check("only the newer file is 'new' after cursor", new_ids() == [f2])

        print("\n7. Retention janitor purges held > limit")
        from airlock.janitor import purge_expired
        mj = Manifest(cfg.db_path)
        old_id = mj.create("stale.bin", "dev", "Project A", 3)
        held_enc = cfg.held_dir / f"{old_id}.enc"
        held_enc.write_bytes(b"ciphertext")
        held_rel = str(held_enc.relative_to(cfg.storage_dir)).replace("\\", "/")
        mj.update(old_id, status="held", vault_path=held_rel,
                  received_at=_t.time() - 20 * 86400)
        purged = purge_expired(cfg, mj, retention_days=15, log=lambda *_: None)
        check("expired held file purged", old_id in purged)
        check("purged ciphertext securely deleted", not held_enc.exists())
        check("status marked purged", mj.get(old_id)["status"] == "purged")
        fresh = mj.create("fresh.bin", "dev", "Project A", 3)
        mj.update(fresh, status="held")
        purged2 = purge_expired(cfg, mj, retention_days=15, log=lambda *_: None)
        check("recent held file NOT purged", fresh not in purged2)

        print("\n" + ("=" * 48))
        ok = all(_results)
        print(f"  {sum(_results)}/{len(_results)} checks passed  "
              f"({'ALL GOOD' if ok else 'FAILURES PRESENT'})")
        return 0 if ok else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
