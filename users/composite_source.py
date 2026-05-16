from typing import Dict, List

from .base import User, UserSource


class CompositeUserSource(UserSource):
    """A :class:`~users.base.UserSource` that merges several other sources.

    Users are concatenated in the order the sources are passed.  When two
    sources contribute a :class:`User` with the same ``sub``, the entry
    from the later source wins — this lets a dynamic remote source
    override a stale row from a static CSV.
    """

    def __init__(self, *sources: UserSource) -> None:
        self.sources = sources

    def get_users(self) -> List[User]:
        merged: Dict[str, User] = {}
        for source in self.sources:
            for user in source.get_users():
                merged[user.sub] = user
        return list(merged.values())
