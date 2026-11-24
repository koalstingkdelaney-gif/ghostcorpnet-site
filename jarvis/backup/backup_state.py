#!/usr/bin/env python3
"""Encrypted, allowlist-oriented Jarvis state backup; excludes credentials and model weights."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

EXCLUDED_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".ollama", "models", "model_cache", "cache", "backups"}
SENSITIVE_PARTS = {"secret", "token", "credential", "password", "private", "id_ed25519", "id_rsa"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".age"}
DB_SUFFIXES = {".db", ".sqlite", ".sqlite3"}


def is_sensitive_path(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith(".env") or name in {".netrc", "credentials"}:
        return True
    if any(part in name for part in SENSITIVE_PARTS):
        return True
    if path.suffix.lower() in SENSITIVE_SUFFIXES:
        return True
    return False


def sqlite_snapshot(source: Path, destination: Path) -> None:
    src = sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True)
    dst = sqlite3.connect(str(destination))
    try:
        src.backup(dst)
        dst.commit()
    finally:
        dst.close()
        src.close()
    con = sqlite3.connect(f"file:{destination.resolve()}?mode=ro", uri=True)
    try:
        result = con.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise RuntimeError(f"SQLite integrity check failed for {source}: {result}")
    finally:
        con.close()


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create_backup(state_root: Path, backup_dir: Path, recipient: str, keep: int = 3) -> Path:
    age = shutil.which("age")
    if not age:
        raise RuntimeError("age is required; no plaintext backup will be retained.")
    if not recipient.strip():
        raise RuntimeError("AGE_RECIPIENT must contain an owner-controlled public recipient.")
    if not state_root.is_dir():
        raise FileNotFoundError(f"Jarvis state directory not found: {state_root}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = backup_dir / f"jarvis-state-{stamp}.zip.age"

    with tempfile.TemporaryDirectory(prefix="jarvis-backup-") as temp:
        work = Path(temp)
        stage = work / "state"
        stage.mkdir()
        for source in state_root.rglob("*"):
            if not source.is_file() or source.is_symlink():
                continue
            rel = source.relative_to(state_root)
            if any(part in EXCLUDED_DIRS for part in rel.parts):
                continue
            if is_sensitive_path(source):
                continue
            target = stage / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.suffix.lower() in DB_SUFFIXES:
                sqlite_snapshot(source, target)
            else:
                shutil.copy2(source, target)

        manifest = {
            "created_at": stamp,
            "source": "Jarvis state directory",
            "secret_files_excluded": True,
            "model_weights_excluded": True,
            "encrypted": True,
        }
        (stage / "BACKUP_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
        archive = work / "state.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for item in stage.rglob("*"):
                if item.is_file():
                    z.write(item, item.relative_to(stage).as_posix())
        with zipfile.ZipFile(archive, "r") as z:
            bad = z.testzip()
            if bad:
                raise RuntimeError(f"Backup archive verification failed at {bad}")

        encrypted = work / "state.zip.age"
        restored = work / "restored.zip"
        subprocess.run([age, "-r", recipient.strip(), "-o", str(encrypted), str(archive)],
                       check=True, capture_output=True, text=True)
        subprocess.run([age, "-d", "-o", str(restored), str(encrypted)],
                       check=True, capture_output=True, text=True)
        if digest(archive) != digest(restored):
            raise RuntimeError("Encrypted backup round-trip hash mismatch.")
        with zipfile.ZipFile(restored, "r") as z:
            bad = z.testzip()
            if bad:
                raise RuntimeError(f"Decrypted archive failed verification at {bad}")
            for member in z.namelist():
                if Path(member).suffix.lower() in DB_SUFFIXES:
                    extracted = work / "db-check.sqlite"
                    extracted.write_bytes(z.read(member))
                    con = sqlite3.connect(f"file:{extracted.resolve()}?mode=ro", uri=True)
                    try:
                        check = con.execute("PRAGMA integrity_check").fetchone()[0]
                        if check != "ok":
                            raise RuntimeError(f"Restored database integrity failed: {member}")
                    finally:
                        con.close()
                    extracted.unlink(missing_ok=True)
        shutil.copyfile(encrypted, output)

    manifest = {"file": output.name, "sha256": digest(output), "encrypted_bytes": output.stat().st_size,
                "restore_round_trip_verified": True, "secret_files_excluded": True}
    (backup_dir / (output.name + ".json")).write_text(json.dumps(manifest, indent=2) + "\n")
    old = sorted(backup_dir.glob("jarvis-state-*.zip.age"), key=lambda p: p.stat().st_mtime, reverse=True)
    for item in old[keep:]:
        item.unlink(missing_ok=True)
        item.with_name(item.name + ".json").unlink(missing_ok=True)
    return output


def main() -> int:
    root = Path(os.environ.get("JARVIS_STATE_DIR", "state"))
    backup_dir = Path(os.environ.get("JARVIS_BACKUP_DIR", "backups"))
    recipient = os.environ.get("AGE_RECIPIENT", "")
    try:
        result = create_backup(root, backup_dir, recipient)
        print(json.dumps({"status": "encrypted_backup_verified", "path": str(result), "sha256": digest(result)}))
        return 0
    except Exception as exc:
        print(f"BACKUP FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
