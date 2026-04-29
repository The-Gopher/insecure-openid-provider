"""Tests for the users package (User model and UserSource implementations)."""

import csv
import os
import tempfile

import pytest

from users.base import User, UserSource
from users.csv_source import CSVUserSource


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
