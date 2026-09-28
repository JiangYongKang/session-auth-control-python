"""存储抽象与内存实现。

并发安全：所有复合读改写操作必须在 transaction() 单锁内完成，
保证失败计数原子化、会话轮换/失效全量且一致。

被轮换、登出或批量失效的会话标识写入"墓碑"，
以便把"重放旧标识"与"标识从未存在"区分判定；
墓碑保留至该会话本应绝对过期的时刻。
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
                       now: float) -> None: ...
    def invalidate_user_sessions(self, username: str,
                                 now: float) -> int: ...

    # --- CSRF ---
    def get_csrf(self, token: str) -> CsrfTokenRecord | None: ...
    def put_csrf(self, token: CsrfTokenRecord) -> None: ...
    def delete_csrf(self, token: str) -> None: ...
    def revoke_csrf(self, token: str) -> None: ...
    def get_revoked_csrf(self, token: str) -> CsrfTokenRecord | None: ...


class InMemoryStore(Store):
    """线程安全的内存存储（单 RLock 保证复合操作原子性）。"""

    def __init__(self) -> None:
        self._users: dict[str, UserRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}
        # sid -> {"keep_until": float, "username": str, "cause": str}
        self._tombstones: dict[str, dict] = {}
        self._csrfs: dict[str, CsrfTokenRecord] = {}
        # 已撤销 CSRF（轮换 / 升级）令牌的墓碑：令牌 -> 撤销前的绑定记录。
        # 用于把"曾签发但已撤销"与"从未签发（伪造）"稳定区分；
        # 与会话墓碑一致，在进程生命周期内保留，不做过期清理。
        self._revoked_csrf: dict[str, CsrfTokenRecord] = {}
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

    def delete_session(self, session_id: str, *,
                       cause: str = "logout") -> None:
        with self._lock:
            s = self._sessions.pop(session_id, None)
            if s is not None:
                self._tombstone_locked(session_id, s.absolute_expiry,
                                       s.username, cause, s.epoch)

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
                       now: float) -> None:
        """原子轮换：旧的必须存在 -> 旧的入墓碑，新的生效。"""
        with self._lock:
            old = self._sessions.get(old_id)
            if old is None:
                if old_id in self._tombstones:
                    raise StoreError("cannot rotate tombstoned session")
                raise StoreError("cannot rotate unknown session")
            old.rotated = True
            del self._sessions[old_id]
            self._tombstone_locked(old_id, old.absolute_expiry,
                                   old.username, "rotated", old.epoch)
            self._sessions[new.session_id] = _copy_session(new)

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

    def revoke_csrf(self, token: str) -> None:
        """撤销一个活动 CSRF 令牌：从活动集移除并写入 CSRF 墓碑。

        必须在事务（单锁）内与对应会话的轮换/失效一起调用，
        保证"旧令牌仍可用"与"新令牌尚不可用"两种半状态都不可见。
        """
        with self._lock:
            rec = self._csrfs.pop(token, None)
            if rec is not None:
                self._revoked_csrf[token] = _copy_csrf(rec)

    def get_revoked_csrf(self, token: str) -> CsrfTokenRecord | None:
        with self._lock:
            t = self._revoked_csrf.get(token)
            return None if t is None else _copy_csrf(t)


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
