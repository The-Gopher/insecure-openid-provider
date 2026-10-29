"""Server-side state (Flask sessions, authorization codes) persisted to SQLite.

The session cookie carries only an opaque random id; the session contents
live in a ``sessions`` table and pending authorization codes in an
``auth_codes`` table, so both survive server restarts and are shared between
gunicorn workers.
"""

import json
import logging
import os
import secrets
import sqlite3
import threading
import time

from flask.sessions import SessionInterface, SessionMixin, session_json_serializer
from werkzeug.datastructures import CallbackDict

_DB_DEFAULT = "/data/oidc.db"


class SQLiteDB:
    """Lazily-opened SQLite connection shared by the stores in this module."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn

        db_path = self._db_path or os.environ.get("SQLITE_DB", _DB_DEFAULT)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None, timeout=10)
        except (OSError, sqlite3.Error) as exc:
            logging.warning(
                "Could not open database at %s (%s); state will not persist.",
                db_path,
                exc,
            )
            conn = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions ("
            " sid TEXT PRIMARY KEY,"
            " data TEXT NOT NULL,"
            " expires INTEGER NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_codes ("
            " code TEXT PRIMARY KEY,"
            " data TEXT NOT NULL,"
            " expires INTEGER NOT NULL)"
        )
        self._conn = conn
        return conn

    def execute(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            return self._connect().execute(sql, params).fetchall()


class AuthCodeStore:
    """Dict-like store of one-time authorization codes: code -> {..., "exp": int}."""

    def __init__(self, db: SQLiteDB):
        self._db = db

    def __setitem__(self, code: str, data: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO auth_codes (code, data, expires) VALUES (?, ?, ?)",
            (code, json.dumps(data), data["exp"]),
        )

    def pop(self, code: str, default=None):
        # DELETE ... RETURNING is atomic, so a code can only be redeemed once
        # even when two workers race on it.
        rows = self._db.execute("DELETE FROM auth_codes WHERE code = ? RETURNING data", (code,))
        return json.loads(rows[0][0]) if rows else default

    def purge_expired(self, now: int) -> None:
        self._db.execute("DELETE FROM auth_codes WHERE expires < ?", (now,))

    def clear(self) -> None:
        self._db.execute("DELETE FROM auth_codes")


class SQLiteSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid: str | None = None, new: bool = False):
        def on_update(self):
            self.modified = True

        super().__init__(initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False


class SQLiteSessionInterface(SessionInterface):
    serializer = session_json_serializer

    def __init__(self, db: SQLiteDB):
        self._db = db

    def open_session(self, app, request):
        sid = request.cookies.get(self.get_cookie_name(app))
        if sid:
            rows = self._db.execute(
                "SELECT data FROM sessions WHERE sid = ? AND expires >= ?",
                (sid, int(time.time())),
            )
            if rows:
                try:
                    return SQLiteSession(self.serializer.loads(rows[0][0]), sid=sid)
                except ValueError:
                    pass
        return SQLiteSession(sid=secrets.token_urlsafe(32), new=True)

    def save_session(self, app, session, response):
        name = self.get_cookie_name(app)
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        httponly = self.get_cookie_httponly(app)

        if session.accessed:
            response.vary.add("Cookie")

        if not session:
            if session.modified:
                self._db.execute("DELETE FROM sessions WHERE sid = ?", (session.sid,))
                response.delete_cookie(
                    name, domain=domain, path=path, secure=secure, samesite=samesite, httponly=httponly
                )
            return

        if not self.should_set_cookie(app, session):
            return

        now = int(time.time())
        db_expires = now + int(app.permanent_session_lifetime.total_seconds())
        self._db.execute("DELETE FROM sessions WHERE expires < ?", (now,))
        self._db.execute(
            "INSERT INTO sessions (sid, data, expires) VALUES (?, ?, ?)"
            " ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires = excluded.expires",
            (session.sid, self.serializer.dumps(dict(session)), db_expires),
        )

        response.set_cookie(
            name,
            session.sid,
            expires=self.get_expiration_time(app, session),
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite,
        )
