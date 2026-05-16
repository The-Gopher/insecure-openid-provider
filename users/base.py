from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class User:
    """Represents an identity that can log in via the OpenID provider."""

    sub: str
    name: str
    email: str
    extra: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def claims(self) -> dict:
        """Return the standard OpenID Connect claims for this user."""
        data = {
            "sub": self.sub,
            "name": self.name,
            "email": self.email,
        }
        data.update(self.extra)
        return data


class UserSource(ABC):
    """Abstract base class for retrieving the list of available users.

    Implement this interface to add new user backends (e.g. LDAP, database,
    JSON file, etc.).  Only the CSV backend is provided out of the box; see
    :class:`~users.csv_source.CSVUserSource`.
    """

    @abstractmethod
    def get_users(self) -> List[User]:
        """Return every user available from this source."""

    def get_user(self, sub: str) -> Optional[User]:
        """Look up a single user by their *sub* claim."""
        for user in self.get_users():
            if user.sub == sub:
                return user
        return None
