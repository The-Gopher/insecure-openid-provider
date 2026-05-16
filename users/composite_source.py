from dataclasses import replace
from typing import Dict, List

from .base import User, UserSource


class CompositeUserSource(UserSource):
    """A :class:`~users.base.UserSource` that merges several other sources.

    Users are concatenated in the order the sources are passed.  When two
    sources contribute a :class:`User` with the same ``sub``, the entry
    from the later source wins for ``name`` / ``email`` / ``extra`` — this
    lets a dynamic remote source override a stale row from a static CSV.
    ``tags`` are unioned across all contributing sources (preserving the
    order they were first seen), so a user that appears in multiple
    sources carries the tags of every source they came from.
    """

    def __init__(self, *sources: UserSource) -> None:
        self.sources = sources

    def get_users(self) -> List[User]:
        merged: Dict[str, User] = {}
        for source in self.sources:
            for user in source.get_users():
                existing = merged.get(user.sub)
                if existing is not None:
                    combined = list(existing.tags)
                    for tag in user.tags:
                        if tag not in combined:
                            combined.append(tag)
                    user = replace(user, tags=combined)
                merged[user.sub] = user
        return list(merged.values())
