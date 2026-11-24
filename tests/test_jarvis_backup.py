import sqlite3
from pathlib import Path

from jarvis.backup.backup_state import is_sensitive_path, sqlite_snapshot


def test_sensitive_paths_are_excluded():
    assert is_sensitive_path(Path("/state/.env"))
    assert is_sensitive_path(Path("/state/owner_private.key"))
    assert is_sensitive_path(Path("/state/id_ed25519"))
    assert not is_sensitive_path(Path("/state/mission-queue.json"))


def test_sqlite_snapshot_integrity(tmp_path: Path):
    source = tmp_path / "source.db"
    target = tmp_path / "snapshot.db"
    con = sqlite3.connect(source)
    con.execute("CREATE TABLE jobs (id INTEGER PRIMARY KEY, state TEXT)")
    con.execute("INSERT INTO jobs(state) VALUES ('checkpointed')")
    con.commit()
    con.close()

    sqlite_snapshot(source, target)
    con = sqlite3.connect(target)
    try:
        assert con.execute("SELECT state FROM jobs").fetchone()[0] == "checkpointed"
    finally:
        con.close()
