"""Tiny SQLite-backed persistence for per-container rules + last scan cache.

Stored in a mapped volume (default /data) so settings survive container
recreation. stdlib only — no ORM, no migrations needed.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Optional

DEFAULT_RULE = "auto"


def _data_dir() -> str:
    d = os.environ.get("LEAKWATCH_DATA", "/data")
    try:
        os.makedirs(d, exist_ok=True)
        # writability probe
        test = os.path.join(d, ".write_test")
        with open(test, "w") as fh:
            fh.write("ok")
        os.remove(test)
        return d
    except OSError:
        # Fall back to a local dir (dev / non-container runs).
        fallback = os.path.join(os.getcwd(), "data")
        os.makedirs(fallback, exist_ok=True)
        return fallback


class SettingsStore:
    def __init__(self, db_path: Optional[str] = None):
        self.path = db_path or os.path.join(_data_dir(), "leakwatch.sqlite")
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS rules (
                    name       TEXT PRIMARY KEY,
                    rule       TEXT NOT NULL,
                    updated_at REAL
                );
                CREATE TABLE IF NOT EXISTS cache (
                    name       TEXT PRIMARY KEY,
                    payload    TEXT,
                    scanned_at REAL
                );
                CREATE TABLE IF NOT EXISTS meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                );
                """
            )
            self._conn.commit()

    # ----- rules ----- #
    def get_rule(self, name: str) -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT rule FROM rules WHERE name = ?", (name,)
            ).fetchone()
        return row["rule"] if row else DEFAULT_RULE

    def get_all_rules(self) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute("SELECT name, rule FROM rules").fetchall()
        return {r["name"]: r["rule"] for r in rows}

    def set_rule(self, name: str, rule: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO rules(name, rule, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET rule=excluded.rule, "
                "updated_at=excluded.updated_at",
                (name, rule, time.time()),
            )
            self._conn.commit()

    # ----- scan cache ----- #
    def cache_set(self, name: str, payload: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO cache(name, payload, scanned_at) VALUES(?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET payload=excluded.payload, "
                "scanned_at=excluded.scanned_at",
                (name, json.dumps(payload), time.time()),
            )
            self._conn.commit()

    def cache_get(self, name: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, scanned_at FROM cache WHERE name = ?", (name,)
            ).fetchone()
        if not row:
            return None
        data = json.loads(row["payload"])
        data["scanned_at"] = row["scanned_at"]
        return data

    def cache_all(self) -> dict[str, dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, payload, scanned_at FROM cache"
            ).fetchall()
        out = {}
        for r in rows:
            data = json.loads(r["payload"])
            data["scanned_at"] = r["scanned_at"]
            out[r["name"]] = data
        return out

    # ----- meta (host info, last scan time) ----- #
    def meta_set(self, key: str, value) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )
            self._conn.commit()

    def meta_get(self, key: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row["value"]) if row else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
