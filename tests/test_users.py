"""Tests for the users package (User model and UserSource implementations)."""

import csv
import io
import json
import os
import tempfile
import urllib.error

import pytest

from users.base import User, UserSource
from users.composite_source import CompositeUserSource
from users.csv_source import CSVUserSource
from users.http_source import HTTPUserSource


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------

class TestUser:
    def test_claims_contains_required_fields(self):
        user = User(sub="alice", name="Alice Smith", email="alice@example.com")
        claims = user.claims()
        assert claims["sub"] == "alice"
        assert claims["name"] == "Alice Smith"
        assert claims["email"] == "alice@example.com"

    def test_claims_includes_extra_fields(self):
        user = User(sub="bob", name="Bob", email="bob@example.com", extra={"department": "eng"})
        claims = user.claims()
        assert claims["department"] == "eng"

    def test_extra_defaults_to_empty_dict(self):
        user = User(sub="x", name="X", email="x@x.com")
        assert user.extra == {}


# ---------------------------------------------------------------------------
# UserSource abstract interface
# ---------------------------------------------------------------------------

class TestUserSourceInterface:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            UserSource()  # type: ignore[abstract]

    def test_get_user_returns_matching_user(self):
        class InMemorySource(UserSource):
            def get_users(self):
                return [
                    User("alice", "Alice", "alice@example.com"),
                    User("bob", "Bob", "bob@example.com"),
                ]

        source = InMemorySource()
        user = source.get_user("bob")
        assert user is not None
        assert user.sub == "bob"

    def test_get_user_returns_none_for_unknown_sub(self):
        class EmptySource(UserSource):
            def get_users(self):
                return []

        assert EmptySource().get_user("nobody") is None


# ---------------------------------------------------------------------------
# CSVUserSource
# ---------------------------------------------------------------------------

def _write_csv(rows: list[dict]) -> str:
    """Write *rows* to a temp CSV file and return its path."""
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, newline="", encoding="utf-8"
    )
    if rows:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    fh.close()
    return fh.name


class TestCSVUserSource:
    def test_reads_standard_columns(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("sub,name,email\nalice,Alice Smith,alice@example.com\n")
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert len(users) == 1
        assert users[0].sub == "alice"
        assert users[0].name == "Alice Smith"
        assert users[0].email == "alice@example.com"

    def test_accepts_id_column_as_sub(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("id,name,email\nbob,Bob Jones,bob@example.com\n")
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert users[0].sub == "bob"

    def test_accepts_username_column_as_sub(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("username,name,email\ncharlie,Charlie,charlie@example.com\n")
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert users[0].sub == "charlie"

    def test_extra_columns_stored_in_extra(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("sub,name,email,department\nalice,Alice,alice@example.com,engineering\n")
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert users[0].extra.get("department") == "engineering"

    def test_reserved_columns_not_in_extra(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("sub,name,email\nalice,Alice,alice@example.com\n")
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert "sub" not in users[0].extra
        assert "name" not in users[0].extra
        assert "email" not in users[0].extra

    def test_skips_rows_without_sub(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("sub,name,email\n,Missing Sub,missing@example.com\nalice,Alice,alice@example.com\n")
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert len(users) == 1
        assert users[0].sub == "alice"

    def test_multiple_users(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text(
            "sub,name,email\nalice,Alice,alice@example.com\nbob,Bob,bob@example.com\n"
        )
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert len(users) == 2

    def test_get_user_by_sub(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("sub,name,email\nalice,Alice,alice@example.com\nbob,Bob,bob@example.com\n")
        source = CSVUserSource(str(csv_file))
        user = source.get_user("bob")
        assert user is not None
        assert user.name == "Bob"

    def test_get_user_returns_none_for_unknown(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("sub,name,email\nalice,Alice,alice@example.com\n")
        source = CSVUserSource(str(csv_file))
        assert source.get_user("nobody") is None

    def test_case_insensitive_column_names(self, tmp_path):
        csv_file = tmp_path / "users.csv"
        csv_file.write_text("SUB,NAME,EMAIL\nalice,Alice,alice@example.com\n")
        source = CSVUserSource(str(csv_file))
        users = source.get_users()
        assert users[0].sub == "alice"
        assert users[0].name == "Alice"


# ---------------------------------------------------------------------------
# HTTPUserSource
# ---------------------------------------------------------------------------


def _fake_urlopen(payload_bytes: bytes):
    """Return a callable that mimics urllib.request.urlopen returning *payload_bytes*."""

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.close()
            return False

    def _call(url, timeout=None):
        return _Resp(payload_bytes)

    return _call


class TestHTTPUserSource:
    def test_parses_wrapped_users_payload(self, monkeypatch):
        body = json.dumps({"users": [{"sub": "alice", "name": "Alice", "email": "a@x.com"}]}).encode()
        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(body))
        users = HTTPUserSource("http://stub/users").get_users()
        assert len(users) == 1
        assert users[0].sub == "alice"
        assert users[0].name == "Alice"
        assert users[0].email == "a@x.com"

    def test_extra_fields_go_in_extra(self, monkeypatch):
        body = json.dumps({"users": [{"sub": "alice", "name": "Alice", "email": "a@x.com", "department": "eng"}]}).encode()
        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(body))
        users = HTTPUserSource("http://stub/users").get_users()
        assert users[0].extra.get("department") == "eng"

    def test_skips_entries_without_sub(self, monkeypatch):
        body = json.dumps({"users": [{"name": "no sub"}, {"sub": "ok", "name": "OK", "email": "o@x.com"}]}).encode()
        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(body))
        users = HTTPUserSource("http://stub/users").get_users()
        assert [u.sub for u in users] == ["ok"]

    def test_accepts_id_and_username_aliases(self, monkeypatch):
        body = json.dumps({"users": [{"id": "bob", "email": "b@x.com"}, {"username": "carol", "email": "c@x.com"}]}).encode()
        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(body))
        users = HTTPUserSource("http://stub/users").get_users()
        subs = sorted(u.sub for u in users)
        assert subs == ["bob", "carol"]

    def test_returns_empty_on_http_error(self, monkeypatch):
        def boom(url, timeout=None):
            raise urllib.error.URLError("connection refused")
        monkeypatch.setattr("urllib.request.urlopen", boom)
        assert HTTPUserSource("http://stub/users").get_users() == []

    def test_returns_empty_on_invalid_json(self, monkeypatch):
        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(b"not json at all"))
        assert HTTPUserSource("http://stub/users").get_users() == []

    def test_returns_empty_when_payload_is_not_object(self, monkeypatch):
        monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen(b"[1, 2, 3]"))
        assert HTTPUserSource("http://stub/users").get_users() == []


# ---------------------------------------------------------------------------
# CompositeUserSource
# ---------------------------------------------------------------------------


class _StaticSource(UserSource):
    def __init__(self, users):
        self._users = users

    def get_users(self):
        return list(self._users)


class TestCompositeUserSource:
    def test_concatenates_users_from_all_sources(self):
        a = _StaticSource([User("alice", "Alice", "a@x.com")])
        b = _StaticSource([User("bob", "Bob", "b@x.com")])
        users = CompositeUserSource(a, b).get_users()
        subs = sorted(u.sub for u in users)
        assert subs == ["alice", "bob"]

    def test_later_source_wins_on_duplicate_sub(self):
        a = _StaticSource([User("alice", "Old Alice", "old@x.com")])
        b = _StaticSource([User("alice", "New Alice", "new@x.com")])
        users = CompositeUserSource(a, b).get_users()
        assert len(users) == 1
        assert users[0].name == "New Alice"
        assert users[0].email == "new@x.com"

    def test_empty_sources(self):
        assert CompositeUserSource().get_users() == []
