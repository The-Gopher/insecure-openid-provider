import json
import logging
import urllib.error
import urllib.request
from typing import List

from .base import User, UserSource

_RESERVED = {"sub", "name", "email", "id", "username", "display_name", "tags"}


class HTTPUserSource(UserSource):
    """A :class:`~users.base.UserSource` that fetches users from an HTTP service.

    The remote service must return JSON of the form::

        {"users": [{"sub": "...", "name": "...", "email": "...", ...}, ...]}

    Per-entry the following keys are recognised: ``sub`` (or ``id`` /
    ``username``), ``name`` (or ``display_name``), ``email``, and ``tags``
    (a JSON list of strings, or a semicolon-separated string for parity
    with the CSV source). Any additional keys are stored in ``User.extra``.
    Every user returned by this source is additionally auto-tagged ``http``
    so the data-source origin is visible on the login page.

    On any network or parse failure the source returns an empty list and
    logs a warning, so a transient outage in the remote service does not
    break login when a CSV source is also configured.
    """

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self.url = url
        self.timeout = timeout

    def get_users(self) -> List[User]:
        try:
            with urllib.request.urlopen(self.url, timeout=self.timeout) as resp:
                payload = json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            logging.warning("HTTPUserSource: failed to fetch %s: %s", self.url, exc)
            return []

        if not isinstance(payload, dict):
            return []
        raw = payload.get("users", [])
        if not isinstance(raw, list):
            return []

        users: List[User] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            sub = entry.get("sub") or entry.get("id") or entry.get("username")
            if not sub:
                continue
            name = entry.get("name") or entry.get("display_name") or sub
            email = entry.get("email", "")
            raw_tags = entry.get("tags")
            if isinstance(raw_tags, list):
                tags = [str(t).strip() for t in raw_tags if str(t).strip()]
            elif isinstance(raw_tags, str):
                tags = [t.strip() for t in raw_tags.split(";") if t.strip()]
            else:
                tags = []
            if "http" not in tags:
                tags.append("http")
            extra = {k: v for k, v in entry.items() if k not in _RESERVED}
            users.append(
                User(
                    sub=str(sub),
                    name=str(name),
                    email=str(email),
                    extra=extra,
                    tags=tags,
                )
            )
        return users
