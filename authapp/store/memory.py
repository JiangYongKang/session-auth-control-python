"""线程安全的内存存储（本地完整验证用）。

服务层用例会在整个“读-判定-写”临界区持有 store.lock()，
保证并发失败计数、锁定与全局失效不会产生半更新。
底层异常一律归一化为 STORAGE_ERROR，绝不向上泄漏为放行。
"""
from __future__ import annotations

from contextlib import contextmanager
from threading import RLock

from authapp.errors import AuthError, ErrorCode
from authapp.models import LoginFailure, SessionRecord, User


def _storage_fail(exc: BaseException) -> AuthError:
    if isinstance(exc, AuthError):
        return exc
    return AuthError(
        ErrorCode.STORAGE_ERROR, "存储异常，请求已拒绝", internal=repr(exc)
    )


class MemoryStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._users_by_name: dict[str, User] = {}
        self._users_by_id: dict[str, User] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._failures: dict[str, LoginFailure] = {}

    @contextmanager
    def lock(self):
        acquired = self._lock.acquire(blocking=True)
        if not acquired:  # RLock.acquire 一般恒为 True，此处为防御
            raise AuthError(ErrorCode.STORAGE_ERROR, "无法获取存储锁")
        try:
            yield
        except AuthError:
            raise
        except Exception as exc:
            raise _storage_fail(exc)
        finally:
            self._lock.release()

    def get_user(self, username: str) -> User | None:
        try:
            return self._users_by_name.get(username)
        except Exception as exc:
            raise _storage_fail(exc)

    def get_user_by_id(self, user_id: str) -> User | None:
        try:
            return self._users_by_id.get(user_id)
        except Exception as exc:
            raise _storage_fail(exc)

    def put_user(self, user: User) -> None:
        try:
            self._users_by_name[user.username] = user
            self._users_by_id[user.user_id] = user
        except Exception as exc:
            raise _storage_fail(exc)

    def get_session(self, session_id: str) -> SessionRecord | None:
        try:
            return self._sessions.get(session_id)
        except Exception as exc:
            raise _storage_fail(exc)

    def put_session(self, record: SessionRecord) -> None:
        try:
            self._sessions[record.session_id] = record
        except Exception as exc:
            raise _storage_fail(exc)

    def delete_session(self, session_id: str) -> None:
        try:
            self._sessions.pop(session_id, None)
        except Exception as exc:
            raise _storage_fail(exc)

    def list_user_sessions(self, user_id: str) -> list[SessionRecord]:
        try:
            return [s for s in self._sessions.values() if s.user_id == user_id]
        except Exception as exc:
            raise _storage_fail(exc)

    def revoke_user_sessions(self, user_id: str, epoch: int) -> None:
        """把该用户全部会话标记失效（注销/改密/MFA 重置共用）。

        必须在持有 store.lock() 时调用：与计数、纪元更新同临界区完成。
        """
        try:
            for record in self._sessions.values():
                if record.user_id == user_id and not record.revoked:
                    record.revoked = True
        except Exception as exc:
            raise _storage_fail(exc)

    def get_failure(self, username: str) -> LoginFailure | None:
        try:
            return self._failures.get(username)
        except Exception as exc:
            raise _storage_fail(exc)

    def put_failure(self, failure: LoginFailure | None) -> None:
        try:
            if failure is None:
                return
            self._failures[failure.username] = failure
        except Exception as exc:
            raise _storage_fail(exc)

    def clear_failure(self, username: str) -> None:
        try:
            self._failures.pop(username, None)
        except Exception as exc:
            raise _storage_fail(exc)
