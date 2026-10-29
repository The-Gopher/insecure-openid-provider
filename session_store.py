"""Server-side Flask sessions persisted to a SQLite database.

The session cookie carries only an opaque random id; the session contents
live in a ``sessions`` table so logins survive server restarts and are shared
between gunicorn workers.
"""

import logging
import os
import secrets
import sqlite3
import threading
import time

from flask.sessions import SessionInterface, SessionMixin, session_json_serializer
from werkzeug.datastructures import CallbackDict

_SESSION_DB_DEFAULT = "/data/sessions.db"


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

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn

        db_path = self._db_path or os.environ.get("SESSION_DB", _SESSION_DB_DEFAULT)
        try:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), mode=0o700, exist_ok=True)
            conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None, timeout=10)
        except (OSError, sqlite3.Error) as exc:
            logging.warning(
                "Could not open session database at %s (%s); sessions will not persist.",
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
        self._conn = conn
        return conn

    def open_session(self, app, request):
        sid = request.cookies.get(self.get_cookie_name(app))
        if sid:
            with self._lock:
                row = self._connect().execute(
                    "SELECT data FROM sessions WHERE sid = ? AND expires >= ?",
                    (sid, int(time.time())),
                ).fetchone()
            if row is not None:
                try:
                    return SQLiteSession(self.serializer.loads(row[0]), sid=sid)
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
                with self._lock:
                    self._connect().execute("DELETE FROM sessions WHERE sid = ?", (session.sid,))
                response.delete_cookie(
                    name, domain=domain, path=path, secure=secure, samesite=samesite, httponly=httponly
                )
            return

        if not self.should_set_cookie(app, session):
            return

        now = int(time.time())
        db_expires = now + int(app.permanent_session_lifetime.total_seconds())
        with self._lock:
            conn = self._connect()
            conn.execute("DELETE FROM sessions WHERE expires < ?", (now,))
            conn.execute(
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
