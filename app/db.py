"""SQLite storage. Mapping values and configuration bodies are ciphertext."""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from app.crypto import Vault
from app.engine.mapper import Mapper

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    job_code TEXT NOT NULL UNIQUE,
    vendor TEXT NOT NULL,
    keywords_enc BLOB,
    description_enc BLOB,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mappings (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    type TEXT NOT NULL,
    real_enc BLOB NOT NULL,
    placeholder_enc BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS configs (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL,
    original_enc BLOB NOT NULL,
    sanitized_enc BLOB NOT NULL,
    byte_size INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS restores (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    compare_config_id INTEGER,
    edited_enc BLOB NOT NULL,
    restored_enc BLOB NOT NULL,
    byte_size INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mappings_session ON mappings(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_configs_session ON configs(session_id);
CREATE INDEX IF NOT EXISTS idx_restores_session ON restores(session_id);
"""


_JOB_CODE = re.compile(r"^JOB-(\d+)$")


def _next_job_code(conn: sqlite3.Connection) -> str:
    highest = 0
    for row in conn.execute("SELECT job_code FROM sessions"):
        match = _JOB_CODE.fullmatch(row["job_code"])
        if match:
            highest = max(highest, int(match.group(1)))
    return f"JOB-{highest + 1:04d}"


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@contextmanager
def connect(path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: str) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}
        if "description_enc" not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN description_enc BLOB")


def create_session(path: str, vault: Vault, description: str, vendor: str = "cisco_ios") -> tuple[int, str]:
    for _attempt in range(8):
        try:
            with connect(path) as conn:
                job_code = _next_job_code(conn)
                cur = conn.execute(
                    """
                    INSERT INTO sessions
                        (job_code, vendor, keywords_enc, description_enc, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (job_code, vendor, vault.encrypt("[]"), vault.encrypt(description), utcnow()),
                )
                return int(cur.lastrowid), job_code
        except sqlite3.IntegrityError:
            continue
    raise sqlite3.IntegrityError("could not allocate a job code")


def update_description(path: str, vault: Vault, session_id: int, description: str) -> bool:
    payload = vault.encrypt(description)
    with connect(path) as conn:
        cur = conn.execute(
            "UPDATE sessions SET description_enc = ? WHERE id = ?",
            (payload, session_id),
        )
        return cur.rowcount > 0


def read_description(vault: Vault, row: dict | None) -> str:
    if not row:
        return ""
    blob = row.get("description_enc")
    if not blob:
        return ""
    return vault.decrypt(blob)


def list_sessions(path: str, vault: Vault) -> list[dict]:
    with connect(path) as conn:
        rows = conn.execute(
            """
            SELECT s.id, s.job_code, s.vendor, s.description_enc, s.created_at,
                   (SELECT COUNT(*) FROM mappings m WHERE m.session_id = s.id) AS mapping_count,
                   (SELECT COUNT(*) FROM configs c WHERE c.session_id = s.id) AS config_count
            FROM sessions s
            ORDER BY s.id DESC
            """
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["description"] = read_description(vault, item)
        item.pop("description_enc", None)
        result.append(item)
    return result


def get_session_row(path: str, session_id: int) -> dict | None:
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    return dict(row) if row else None


def load_keywords(vault: Vault, row: dict) -> list[str]:
    blob = row.get("keywords_enc")
    if not blob:
        return []
    data = json.loads(vault.decrypt(blob))
    if not isinstance(data, list):
        return []
    return [str(item) for item in data]


def save_keywords(path: str, vault: Vault, session_id: int, keywords: list[str]) -> None:
    payload = vault.encrypt(json.dumps(keywords))
    with connect(path) as conn:
        conn.execute("UPDATE sessions SET keywords_enc = ? WHERE id = ?", (payload, session_id))


def delete_session(path: str, session_id: int) -> bool:
    with connect(path) as conn:
        conn.execute("DELETE FROM restores WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM configs WHERE session_id = ?", (session_id,))
        conn.execute("DELETE FROM mappings WHERE session_id = ?", (session_id,))
        cur = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        return cur.rowcount > 0


def counts_for_session(path: str, session_id: int) -> dict[str, int]:
    with connect(path) as conn:
        mappings = conn.execute(
            "SELECT COUNT(*) AS n FROM mappings WHERE session_id = ?", (session_id,)
        ).fetchone()["n"]
        configs = conn.execute(
            "SELECT COUNT(*) AS n FROM configs WHERE session_id = ?", (session_id,)
        ).fetchone()["n"]
        restores = conn.execute(
            "SELECT COUNT(*) AS n FROM restores WHERE session_id = ?", (session_id,)
        ).fetchone()["n"]
    return {"mappings": int(mappings), "configs": int(configs), "restores": int(restores)}


def load_mapper(path: str, vault: Vault, session_id: int, keywords: list[str]) -> Mapper:
    mapper = Mapper(keywords=list(keywords))
    with connect(path) as conn:
        rows = conn.execute(
            "SELECT seq, type, real_enc, placeholder_enc FROM mappings WHERE session_id = ? ORDER BY seq",
            (session_id,),
        ).fetchall()
    for row in rows:
        mapper.load_entry(
            row["type"],
            vault.decrypt(row["real_enc"]),
            vault.decrypt(row["placeholder_enc"]),
            int(row["seq"]),
        )
    return mapper


def save_mapper_entries(path: str, vault: Vault, session_id: int, mapper: Mapper) -> int:
    fresh = mapper.new_entries()
    if not fresh:
        return 0
    with connect(path) as conn:
        conn.executemany(
            """
            INSERT INTO mappings (session_id, seq, type, real_enc, placeholder_enc)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    session_id,
                    entry.seq,
                    entry.type,
                    vault.encrypt(entry.real),
                    vault.encrypt(entry.placeholder),
                )
                for entry in fresh
            ],
        )
    for entry in fresh:
        entry.dirty = False
    return len(fresh)


def add_config(
    path: str,
    vault: Vault,
    session_id: int,
    *,
    label: str,
    filename: str,
    original: str,
    sanitized: str,
) -> int:
    with connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO configs (session_id, label, filename, original_enc, sanitized_enc, byte_size, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                label,
                filename,
                vault.encrypt(original),
                vault.encrypt(sanitized),
                len(original.encode("utf-8")),
                utcnow(),
            ),
        )
        return int(cur.lastrowid)


def list_configs(path: str, session_id: int) -> list[dict]:
    with connect(path) as conn:
        rows = conn.execute(
            """
            SELECT id, label, filename, byte_size, created_at
            FROM configs WHERE session_id = ? ORDER BY id DESC
            """,
            (session_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_config(path: str, vault: Vault, session_id: int, config_id: int) -> dict | None:
    with connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM configs WHERE id = ? AND session_id = ?",
            (config_id, session_id),
        ).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["original"] = vault.decrypt(data.pop("original_enc"))
    data["sanitized"] = vault.decrypt(data.pop("sanitized_enc"))
    return data


def list_mapping_rows(path: str, vault: Vault, session_id: int) -> list[dict]:
    with connect(path) as conn:
        rows = conn.execute(
            "SELECT seq, type, real_enc, placeholder_enc FROM mappings WHERE session_id = ? ORDER BY seq",
            (session_id,),
        ).fetchall()
    result = []
    for row in rows:
        result.append(
            {
                "seq": row["seq"],
                "type": row["type"],
                "real": vault.decrypt(row["real_enc"]),
                "placeholder": vault.decrypt(row["placeholder_enc"]),
            }
        )
    return result


def add_restore(
    path: str,
    vault: Vault,
    session_id: int,
    *,
    compare_config_id: int | None,
    edited: str,
    restored: str,
) -> int:
    with connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO restores (session_id, compare_config_id, edited_enc, restored_enc, byte_size, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                compare_config_id,
                vault.encrypt(edited),
                vault.encrypt(restored),
                len(restored.encode("utf-8")),
                utcnow(),
            ),
        )
        return int(cur.lastrowid)


def get_restore(path: str, vault: Vault, session_id: int, restore_id: int) -> dict | None:
    with connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM restores WHERE id = ? AND session_id = ?",
            (restore_id, session_id),
        ).fetchone()
    if row is None:
        return None
    data = dict(row)
    data["edited"] = vault.decrypt(data.pop("edited_enc"))
    data["restored"] = vault.decrypt(data.pop("restored_enc"))
    return data


def list_restores(path: str, session_id: int) -> list[dict]:
    with connect(path) as conn:
        rows = conn.execute(
            """
            SELECT id, compare_config_id, byte_size, created_at
            FROM restores WHERE session_id = ? ORDER BY id DESC LIMIT 10
            """,
            (session_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def checkpoint(path: str) -> None:
    with connect(path) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
