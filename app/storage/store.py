"""存储抽象与内存实现。

并发安全：所有复合读改写操作必须在 transaction() 单锁内完成，
保证失败计数原子化、会话轮换/失效全量且一致。

被轮换、登出或批量失效的会话标识写入"墓碑"，
以便把"重放旧标识"与"标识从未存在"区分判定；
墓碑保留至该会话本应绝对过期的时刻。

随会话一起被撤销（轮换/登出/失效）的 CSRF 令牌同样写入 CSRF 墓碑，
与"从未签发的伪造令牌"区分；会话标识的换入/换出与 CSRF 令牌的
换入/换出在同一把锁内完成，任何时刻都不存在半更新。
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

from app.errors import StoreError
from app.storage.models import CsrfTokenRecord, SessionRecord, UserRecord


class Store:
    """存储协议基类。所有方法失败时抛 StoreError，不得返回伪造的放行数据。"""

    @contextmanager
    def transaction(self) -> Iterator[None]: ...

    # --- 用户 ---
    def get_user(self, username: str) -> UserRecord | None: ...
    def put_user(self, user: UserRecord) -> None: ...

    # --- 会话 ---
    def get_session(self, session_id: str) -> SessionRecord | None: ...
    def put_session(self, session: SessionRecord) -> None: ...
    def delete_session(self, session_id: str, *,
                       cause: str = "logout") -> None: ...
    def list_user_sessions(self, username: str) -> list[SessionRecord]: ...
    def list_user_tombstone_ids(self, username: str) -> list[str]: ...
    def is_tombstoned(self, session_id: str, now: float) -> bool: ...
    def tombstone_info(self, session_id: str) -> dict | None: ...
    def rotate_session(self, old_id: str, new: SessionRecord,
                       now: float, *,
                       new_csrf: CsrfTokenRecord | None = None) -> None: ...
    def invalidate_user_sessions(self, username: str,
                                 now: float) -> int: ...

    # --- CSRF ---
    def get_csrf(self, token: str) -> CsrfTokenRecord | None: ...
    def put_csrf(self, token: CsrfTokenRecord) -> None: ...
    def delete_csrf(self, token: str) -> None: ...
    def csrf_tombstone_info(self, token: str) -> dict | None: ...


class InMemoryStore(Store):
    """线程安全的内存存储（单 RLock 保证复合操作原子性）。"""

    def __init__(self) -> None:
        self._users: dict[str, UserRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}
        # sid -> {"keep_until": float, "username": str, "cause": str}
        self._tombstones: dict[str, dict] = {}
        self._csrfs: dict[str, CsrfTokenRecord] = {}
        # csrf token -> {"session_id": str, "username": str, "cause": str}
        # 已撤销令牌的墓碑：语义为"该令牌曾签发且已撤销"，
        # 必须能与"从未签发的令牌"稳定区分；进程生命周期内保留。
        self._csrf_tombstones: dict[str, dict] = {}
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            yield

    # --- 用户 ---
    def get_user(self, username: str) -> UserRecord | None:
        with self._lock:
            u = self._users.get(username)
            return None if u is None else _copy_user(u)

    def put_user(self, user: UserRecord) -> None:
        with self._lock:
            self._users[user.username] = _copy_user(user)

    # --- 会话 ---
    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            s = self._sessions.get(session_id)
            return None if s is None else _copy_session(s)

    def put_session(self, session: SessionRecord) -> None:
        with self._lock:
            self._sessions[session.session_id] = _copy_session(session)

    def _tombstone_locked(self, sid: str, keep_until: float,
                          username: str, cause: str,
                          epoch: int | None = None) -> None:
        # 墓碑在进程生命周期内保留：语义为"该标识曾签发且已撤销"，
        # 必须能与"从未存在的标识"稳定区分；不按会话过期时间清理。
        prev = self._tombstones.get(sid)
        self._tombstones[sid] = {
            "keep_until": max(prev["keep_until"], keep_until) if prev
            else keep_until,
            "username": username or (prev["username"] if prev else ""),
            # 第一次撤销的原因保留（轮换/登出/过期/失效）
            "cause": (prev["cause"] if prev else cause),
            "epoch": epoch if epoch is not None
            else (prev.get("epoch") if prev else None),
        }

    def _retire_csrf_locked(self, token: str | None, username: str,
                            cause: str, session_id: str = "") -> None:
        """把活动 CSRF 令牌原子地撤入墓碑。调用方必须已持锁。

        与旧会话标识同事务处理，保证不会出现"标识已换但旧令牌仍可用"
        或"新令牌已发但不可用"的半更新。墓碑进程内保留，
        使"曾签发但已撤销"可与"从未签发（伪造）"区分。
        """
        if not token:
            return
        record = self._csrfs.pop(token, None)
        if record is None and token not in self._csrf_tombstones:
            return
        prev = self._csrf_tombstones.get(token)
        self._csrf_tombstones[token] = {
            "session_id": session_id
            or (record.session_id if record is not None else "")
            or (prev["session_id"] if prev else ""),
            "username": username
            or (record.username if record is not None else "")
            or (prev["username"] if prev else ""),
            "cause": (prev["cause"] if prev else cause),
        }

    def delete_session(self, session_id: str, *,
                       cause: str = "logout") -> None:
        with self._lock:
            s = self._sessions.pop(session_id, None)
            if s is not None:
                self._tombstone_locked(session_id, s.absolute_expiry,
                                       s.username, cause, s.epoch)
                self._retire_csrf_locked(s.csrf_token, s.username, cause,
                                         session_id=session_id)

    def list_user_sessions(self, username: str) -> list[SessionRecord]:
        with self._lock:
            return [_copy_session(s) for s in self._sessions.values()
                    if s.username == username]

    def list_user_tombstone_ids(self, username: str) -> list[str]:
        """该用户已撤销（入墓碑）的会话标识，用于"已失效引用"的可区分判定。"""
        with self._lock:
            return [sid for sid, t in self._tombstones.items()
                    if t.get("username") == username]

    def is_tombstoned(self, session_id: str, now: float) -> bool:
        with self._lock:
            return session_id in self._tombstones

    def tombstone_info(self, session_id: str) -> dict | None:
        with self._lock:
            t = self._tombstones.get(session_id)
            return None if t is None else dict(t)

    def rotate_session(self, old_id: str, new: SessionRecord,
                       now: float, *,
                       new_csrf: CsrfTokenRecord | None = None) -> None:
        """原子轮换：旧的必须存在 -> 旧的与旧 CSRF 同事务入墓碑，
        新会话生效、新 CSRF 同事务落库。要么整步完成，要么完全不变。"""
        with self._lock:
            old = self._sessions.get(old_id)
            if old is None:
                if old_id in self._tombstones:
                    raise StoreError("cannot rotate tombstoned session")
                raise StoreError("cannot rotate unknown session")
            old_csrf = old.csrf_token
            old.rotated = True
            del self._sessions[old_id]
            self._tombstone_locked(old_id, old.absolute_expiry,
                                   old.username, "rotated", old.epoch)
            self._retire_csrf_locked(old_csrf, old.username, "rotated",
                                     session_id=old_id)
            self._sessions[new.session_id] = _copy_session(new)
            if new_csrf is not None:
                # 极端碰撞下新令牌不得覆盖旧墓碑/旧记录
                if new_csrf.token in self._csrf_tombstones \
                        or new_csrf.token in self._csrfs:
                    raise StoreError("csrf token collision")
                self._csrfs[new_csrf.token] = _copy_csrf(new_csrf)

    def invalidate_user_sessions(self, username: str, now: float,
                                 *, cause: str = "invalidated") -> int:
        """原子地使某用户全部活动会话失效（入墓碑）。返回失效数量。"""
        with self._lock:
            ids = [sid for sid, s in self._sessions.items()
                   if s.username == username]
            for sid in ids:
                s = self._sessions.pop(sid)
                s.rotated = True
                self._tombstone_locked(sid, s.absolute_expiry,
                                       s.username, cause, s.epoch)
                self._retire_csrf_locked(s.csrf_token, s.username, cause,
                                         session_id=sid)
            return len(ids)

    # --- CSRF ---
    def get_csrf(self, token: str) -> CsrfTokenRecord | None:
        with self._lock:
            t = self._csrfs.get(token)
            return None if t is None else _copy_csrf(t)

    def put_csrf(self, token: CsrfTokenRecord) -> None:
        with self._lock:
            self._csrfs[token.token] = CsrfTokenRecord(
                token=token.token, session_id=token.session_id,
                username=token.username, origin=token.origin,
                expires_at=token.expires_at)

    def delete_csrf(self, token: str) -> None:
        with self._lock:
            self._csrfs.pop(token, None)

    def csrf_tombstone_info(self, token: str) -> dict | None:
        with self._lock:
            t = self._csrf_tombstones.get(token)
            return None if t is None else dict(t)


# 存储返回副本，避免调用方绕开锁修改内部状态。
def _copy_user(u: UserRecord) -> UserRecord:
    return UserRecord(
        username=u.username, password_hash=u.password_hash,
        roles=tuple(u.roles), totp_secret=u.totp_secret,
        totp_enrolled=u.totp_enrolled, totp_last_step=u.totp_last_step,
        fail_count=u.fail_count, fail_window_start=u.fail_window_start,
        locked_until=u.locked_until, session_epoch=u.session_epoch)


def _copy_session(s: SessionRecord) -> SessionRecord:
    return SessionRecord(
        session_id=s.session_id, username=s.username, created_at=s.created_at,
        last_seen=s.last_seen, absolute_expiry=s.absolute_expiry,
        idle_expiry=s.idle_expiry, mfa_verified=s.mfa_verified,
        epoch=s.epoch, csrf_token=s.csrf_token, rotated=s.rotated)


def _copy_csrf(t: CsrfTokenRecord) -> CsrfTokenRecord:
    return CsrfTokenRecord(token=t.token, session_id=t.session_id,
                           username=t.username, origin=t.origin,
                           expires_at=t.expires_at)
