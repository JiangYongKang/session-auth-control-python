"""登录失败节流与临时锁定。

语义（阈值 threshold、观察窗口 window、锁定时长 lock 均可配置）：
- 每次失败在窗口内累加（按失败时间戳滑动计数）；
- 计数达到阈值 -> 立即锁定 lock 秒，计数保留；
- 锁定期间任何登录（即使口令正确）都拒绝并返回 ACCOUNT_LOCKED（可区分）；
- 锁过期后：若窗口内失败数仍达阈值则重新拒绝/续锁，否则清空计数放行；
- 成功登录清空计数。

并发安全：调用方在整个“检查锁-验密-计数/锁定”流程持有同一把存储锁，
本类的方法假定运行在该临界区内，因此并发失败不会绕过计数或重复锁定。
"""
from __future__ import annotations

from authapp.clock import Clock
from authapp.config import AuthConfig
from authapp.errors import AuthError, ErrorCode
from authapp.models import LoginFailure
from authapp.store.base import Store


class ThrottleController:
    def __init__(self, store: Store, config: AuthConfig, clock: Clock) -> None:
        self.store = store
        self.config = config
        self.clock = clock

    def ensure_not_locked(self, username: str) -> None:
        """锁定中抛 ACCOUNT_LOCKED；锁已过期则惰性清理。"""
        now = self.clock.now()
        user = self.store.get_user(username)
        if user is not None and user.is_locked(now):
            remaining = int(round(user.locked_until - now))
            raise AuthError(
                ErrorCode.ACCOUNT_LOCKED,
                f"账号已临时锁定，请 {max(remaining, 0)} 秒后再试",
                internal="locked",
            )
        failure = self.store.get_failure(username)
        if failure is not None:
            failure.prune(now, self.config.fail_window_seconds)
            if failure.locked and failure.count >= self.config.fail_threshold:
                # 用户对象锁字段丢失但计数仍达阈值：保守续锁，不降级。
                if user is not None:
                    user.locked_until = now + self.config.lock_seconds
                    self.store.put_user(user)
                raise AuthError(
                    ErrorCode.ACCOUNT_LOCKED, "账号已临时锁定", internal="relocked"
                )
            if failure.count == 0:
                self.store.clear_failure(username)
                if user is not None and user.locked_until is not None:
                    user.locked_until = None
                    self.store.put_user(user)

    def record_failure(self, username: str) -> bool:
        """在观察窗口内追加一次失败；达到阈值则加锁（临界区内执行）。

        返回本次失败是否触发了新加锁，供审计使用。
        """
        now = self.clock.now()
        failure = self.store.get_failure(username)
        if failure is None:
            failure = LoginFailure(
                username=username, count=0, window_started_at=now
            )
        failure.prune(now, self.config.fail_window_seconds)
        failure.first_failures.append(now)
        failure.count = len(failure.first_failures)
        newly_locked = False
        if failure.count >= self.config.fail_threshold and not failure.locked:
            failure.locked = True
            user = self.store.get_user(username)
            if user is not None:
                # 并发下也只设置同一个目标时间戳，杜绝重复/叠加锁定。
                user.locked_until = now + self.config.lock_seconds
                self.store.put_user(user)
            newly_locked = True
        self.store.put_failure(failure)
        return newly_locked

    def record_success(self, username: str) -> None:
        self.store.clear_failure(username)
        user = self.store.get_user(username)
        if user is not None and user.locked_until is not None:
            user.locked_until = None
            self.store.put_user(user)
