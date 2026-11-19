"""Estado persistente do sidecar em SQLite (especificacao, secao 14).

Tabelas: anti-replay, fixacoes de KEL, sessoes (estado cifrado com a chave de dados) e
mapeamentos de push. O esquema e versionado em `meta.schema_version`.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any

from .crypto.primitives import aead_open, aead_seal
from .errors import SeloError

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replay (sender TEXT NOT NULL, msg TEXT NOT NULL, exp INTEGER NOT NULL,
                                   PRIMARY KEY (sender, msg));
CREATE TABLE IF NOT EXISTS pins (agent_id TEXT PRIMARY KEY, seq INTEGER NOT NULL, head TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, peer_id TEXT NOT NULL, peer_url TEXT NOT NULL,
                                     role TEXT NOT NULL, exp INTEGER NOT NULL, blob BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS push_out (ref TEXT PRIMARY KEY, webhook TEXT NOT NULL, server_id TEXT NOT NULL,
                                     created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS push_in (id TEXT PRIMARY KEY, dest_url TEXT NOT NULL, dest_id TEXT NOT NULL,
                                    ref TEXT NOT NULL, token TEXT NOT NULL, peer_id TEXT NOT NULL,
                                    created INTEGER NOT NULL);
"""


class Store:
    def __init__(
        self, path: str = ":memory:", data_key: bytes | None = None
    ) -> None:
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self._data_key = data_key or os.urandom(32)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute(
            "PRAGMA journal_mode=WAL"
            if path != ":memory:"
            else "PRAGMA journal_mode=MEMORY"
        )
        self._db.execute("PRAGMA synchronous=FULL")
        with self._lock:
            self._db.executescript(_SCHEMA)
            row = self._db.execute(
                "SELECT v FROM meta WHERE k='schema_version'"
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO meta VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
            elif int(row[0]) != SCHEMA_VERSION:
                raise SeloError(
                    "schema_version",
                    f"banco na versao {row[0]}, esperado {SCHEMA_VERSION}",
                )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def schema_version(self) -> int:
        return int(
            self._db.execute("SELECT v FROM meta WHERE k='schema_version'").fetchone()[
                0
            ]
        )

    # -- anti-replay ----------------------------------------------------------------------
    def check_replay(self, sender: str, msg: str, exp: int, now: float) -> None:
        with self._lock:
            self._db.execute("DELETE FROM replay WHERE exp < ?", (int(now) - 1,))
            try:
                self._db.execute(
                    "INSERT INTO replay VALUES (?, ?, ?)", (sender, msg, int(exp))
                )
            except sqlite3.IntegrityError:
                raise SeloError("replay", f"{sender}/{msg}") from None

    # -- fixacoes -------------------------------------------------------------------------
    def get_pin(self, agent_id: str) -> tuple[int, str] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT seq, head FROM pins WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return (row[0], row[1]) if row else None

    def set_pin(self, agent_id: str, seq: int, head: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO pins VALUES (?, ?, ?) ON CONFLICT(agent_id) DO UPDATE "
                "SET seq=excluded.seq, head=excluded.head WHERE excluded.seq >= pins.seq",
                (agent_id, seq, head),
            )

    # -- sessoes (estado cifrado) ---------------------------------------------------------
    def _seal(self, sid: str, data: dict[str, Any]) -> bytes:
        nonce = os.urandom(12)
        return nonce + aead_seal(
            self._data_key,
            nonce,
            b"selo/1/state\x00" + sid.encode(),
            json.dumps(data).encode(),
        )

    def _open(self, sid: str, blob: bytes) -> dict[str, Any]:
        return json.loads(
            aead_open(
                self._data_key, blob[:12], b"selo/1/state\x00" + sid.encode(), blob[12:]
            )
        )

    def save_session(
        self,
        sid: str,
        peer_id: str,
        peer_url: str,
        role: str,
        exp: int,
        data: dict[str, Any],
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(sid) DO UPDATE "
                "SET blob=excluded.blob, exp=excluded.exp",
                (sid, peer_id, peer_url, role, int(exp), self._seal(sid, data)),
            )

    def load_session(
        self, sid: str
    ) -> tuple[str, str, str, int, dict[str, Any]] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT peer_id, peer_url, role, exp, blob FROM sessions WHERE sid=?",
                (sid,),
            ).fetchone()
        if row is None:
            return None
        return row[0], row[1], row[2], row[3], self._open(sid, row[4])

    def find_initiator_session(self, peer_id: str, now: float) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT sid FROM sessions WHERE peer_id=? AND role='i' AND exp>? "
                "ORDER BY exp DESC LIMIT 1",
                (peer_id, int(now)),
            ).fetchone()
        return row[0] if row else None

    def delete_session(self, sid: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE sid=?", (sid,))

    def purge_sessions(self, now: float) -> None:
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE exp<=?", (int(now),))

    def raw_session_blobs(self) -> list[bytes]:
        with self._lock:
            return [r[0] for r in self._db.execute("SELECT blob FROM sessions")]

    # -- push -----------------------------------------------------------------------------
    def add_push_out(self, ref: str, webhook: str, server_id: str, now: float) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO push_out VALUES (?, ?, ?, ?)",
                (ref, webhook, server_id, int(now)),
            )

    def get_push_out(self, ref: str) -> tuple[str, str] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT webhook, server_id FROM push_out WHERE ref=?", (ref,)
            ).fetchone()
        return (row[0], row[1]) if row else None

    def add_push_in(
        self,
        pid: str,
        dest_url: str,
        dest_id: str,
        ref: str,
        token: str,
        peer_id: str,
        now: float,
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO push_in VALUES (?, ?, ?, ?, ?, ?, ?)",
                (pid, dest_url, dest_id, ref, token, peer_id, int(now)),
            )

    def get_push_in(self, pid: str) -> dict[str, str] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT dest_url, dest_id, ref, token, peer_id FROM push_in WHERE id=?",
                (pid,),
            ).fetchone()
        if row is None:
            return None
        return dict(zip(("dest_url", "dest_id", "ref", "token", "peer_id"), row))
