"""存储故障注入包装器，用于验证"异常不降级放行"。"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from app.errors import StoreError
from app.storage.models import CsrfTokenRecord, SessionRecord, UserRecord
from app.storage.store import Store


class FailingStore(Store):
    """对指定方法抛 StoreError 的 Store 装饰器；其余方法透传。"""

    def __init__(self, inner: Store, failing_methods: frozenset[str] | set[str]) -> None:
        self._inner = inner
        self._failing = set(failing_methods)

    def _maybe_fail(self, name: str) -> None:
        if name in self._failing:
            raise StoreError(f"injected failure: {name}")

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self._maybe_fail("transaction")
        with self._inner.transaction():
            yield

    def get_user(self, username: str) -> UserRecord | None:
        self._maybe_fail("get_user")
        return self._inner.get_user(username)

    def put_user(self, user: UserRecord) -> None:
        self._maybe_fail("put_user")
        self._inner.put_user(user)

    def get_session(self, session_id: str) -> SessionRecord | None:
        self._maybe_fail("get_session")
        return self._inner.get_session(session_id)

    def put_session(self, session: SessionRecord) -> None:
        self._maybe_fail("put_session")
        self._inner.put_session(session)

    def delete_session(self, session_id: str, *,
                       cause: str = "logout") -> None:
        self._maybe_fail("delete_session")
        self._inner.delete_session(session_id, cause=cause)

    def list_user_sessions(self, username: str) -> list[SessionRecord]:
        self._maybe_fail("list_user_sessions")
        return self._inner.list_user_sessions(username)

    def list_user_tombstone_ids(self, username: str) -> list[str]:
        self._maybe_fail("list_user_tombstone_ids")
        return self._inner.list_user_tombstone_ids(username)

    def is_tombstoned(self, session_id: str, now: float) -> bool:
        self._maybe_fail("is_tombstoned")
        return self._inner.is_tombstoned(session_id, now)

    def tombstone_info(self, session_id: str) -> dict | None:
        self._maybe_fail("tombstone_info")
        return self._inner.tombstone_info(session_id)

    def rotate_session(self, old_id: str, new: SessionRecord,
                       now: float) -> None:
        self._maybe_fail("rotate_session")
        self._inner.rotate_session(old_id, new, now)

    def invalidate_user_sessions(self, username: str, now: float,
                                 *, cause: str = "invalidated") -> int:
        self._maybe_fail("invalidate_user_sessions")
        return self._inner.invalidate_user_sessions(
            username, now, cause=cause)

    def get_csrf(self, token: str) -> CsrfTokenRecord | None:
        self._maybe_fail("get_csrf")
        return self._inner.get_csrf(token)

    def put_csrf(self, token: CsrfTokenRecord) -> None:
        self._maybe_fail("put_csrf")
        self._inner.put_csrf(token)

    def delete_csrf(self, token: str) -> None:
        self._maybe_fail("delete_csrf")
        self._inner.delete_csrf(token)

    def revoke_csrf(self, token: str) -> None:
        self._maybe_fail("revoke_csrf")
        self._inner.revoke_csrf(token)

    def get_revoked_csrf(self, token: str) -> CsrfTokenRecord | None:
        self._maybe_fail("get_revoked_csrf")
        return self._inner.get_revoked_csrf(token)
