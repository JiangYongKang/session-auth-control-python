"""存储抽象：所有访问必须经锁串行化；异常归一化为 STORAGE_ERROR。"""
from __future__ import annotations

from typing import ContextManager, Protocol

from authapp.models import LoginFailure, SessionRecord, User


class Store(Protocol):
    def lock(self) -> ContextManager[None]:
        ...

    # 用户
    def get_user(self, username: str) -> User | None:
        ...

    def get_user_by_id(self, user_id: str) -> User | None:
        ...

    def put_user(self, user: User) -> None:
        ...

    # 会话
    def get_session(self, session_id: str) -> SessionRecord | None:
        ...

    def put_session(self, record: SessionRecord) -> None:
        ...

    def delete_session(self, session_id: str) -> None:
        ...

    def list_user_sessions(self, user_id: str) -> list[SessionRecord]:
        ...

    def revoke_user_sessions(self, user_id: str, epoch: int) -> None:
        """把该用户全部会话标记失效（注销/改密/MFA 重置共用）。"""
        ...

    # 登录失败计数
    def get_failure(self, username: str) -> LoginFailure | None:
        ...

    def put_failure(self, failure: LoginFailure | None) -> None:
        ...
