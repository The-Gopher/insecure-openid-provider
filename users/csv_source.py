import csv
from typing import List

from .base import User, UserSource

# Canonical column names (case-insensitive) for the required fields.
_SUB_COLS = ("sub", "id", "username")
_NAME_COLS = ("name", "display_name", "full_name")
_EMAIL_COLS = ("email",)
_TAGS_COLS = ("tags",)


def _first_value(row: dict, candidates: tuple, default: str = "") -> str:
    """Return the value of the first matching key found in *row*."""
    lower = {k.lower(): v for k, v in row.items()}
    for col in candidates:
        if col in lower:
            return lower[col]
    return default


class CSVUserSource(UserSource):
    """A :class:`~users.base.UserSource` that reads users from a CSV file.

    The CSV file must have a header row.  The following column names are
    recognised (case-insensitive):

    * **sub / id / username** — unique identifier for the user (required)
    * **name / display_name / full_name** — human-readable display name
    * **email** — e-mail address
    * **tags** — semicolon-separated tag list (e.g. ``qa;legacy``)

    Any additional columns are stored in ``User.extra``. Every user returned
    by this source is additionally auto-tagged ``csv`` so the data-source
    origin is visible on the login page.
    """

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath

    def get_users(self) -> List[User]:
        users: List[User] = []
        reserved = set(_SUB_COLS + _NAME_COLS + _EMAIL_COLS + _TAGS_COLS)
        with open(self.filepath, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                sub = _first_value(row, _SUB_COLS)
                if not sub:
                    continue
                name = _first_value(row, _NAME_COLS, default=sub)
                email = _first_value(row, _EMAIL_COLS)
                raw_tags = _first_value(row, _TAGS_COLS)
                tags = [t.strip() for t in raw_tags.split(";") if t.strip()]
                if "csv" not in tags:
                    tags.append("csv")
                extra = {
                    k: v
                    for k, v in row.items()
                    if k.lower() not in reserved
                }
                users.append(
                    User(sub=sub, name=name, email=email, extra=extra, tags=tags)
                )
        return users
