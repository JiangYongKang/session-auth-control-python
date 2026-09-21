"""默认拒绝的权限判定：角色 × 资源范围组合，服务端权威。

资源命名：分层路径，如 "app/self"、"admin/audit/2026"。
策略项：role -> {action: set[允许的资源路径前缀]}；"*" 表示全域。
安全要点：
- 策略完全由服务端配置持有，从不读取请求体里的角色/范围；
- 无权限与“资源不存在”对外是同一个 FORBIDDEN，避免探测资源是否存在；
- 匹配失败、角色缺失、动作未知一律拒绝（default deny）。
"""
from __future__ import annotations

from authapp.clock import Clock
from authapp.config import AuthConfig
from authapp.errors import AuthError, ErrorCode
from authapp.models import User
from authapp.store.base import Store

Action = str
Resource = str

# 服务端内置策略（集中审阅，不接受客户端覆盖）。
DEFAULT_POLICY: dict[str, dict[Action, set[str]]] = {
    "admin": {
        "read": {"*"},
        "write": {"*"},
        "admin": {"*"},
    },
    "auditor": {
        "read": {"admin/audit", "admin/sessions"},
    },
    "member": {
        "read": {"app/public", "app/self"},
        "write": {"app/self"},
    },
}

# 服务端登记的真实资源；未知资源同样返回 FORBIDDEN（不泄漏存在性）。
KNOWN_RESOURCES: set[str] = {
    "app/public",
    "app/self",
    "app/self/orders",
    "app/orders",
    "admin/audit",
    "admin/audit/2026",
    "admin/sessions",
    "admin/users",
}


def _prefix_allows(prefix: str, resource: str) -> bool:
    if prefix == "*":
        return True
    return resource == prefix or resource.startswith(prefix.rstrip("/") + "/")


class AccessController:
    def __init__(
        self,
        store: Store,
        config: AuthConfig,
        clock: Clock,
        policy: dict[str, dict[Action, set[str]]] | None = None,
        known_resources: set[str] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.clock = clock
        self.policy = policy if policy is not None else DEFAULT_POLICY
        self.known_resources = (
            known_resources if known_resources is not None else KNOWN_RESOURCES
        )

    def _decide(self, user: User, action: Action, resource: Resource) -> bool:
        if not isinstance(action, str) or not action:
            return False
        if not isinstance(resource, str) or not resource:
            return False
        for role in user.roles:
            allowed_prefixes = self.policy.get(role, {}).get(action)
            if not allowed_prefixes:
                continue
            if any(_prefix_allows(p, resource) for p in allowed_prefixes):
                return True
        return False  # 默认拒绝

    def check(self, user: User, action: Action, resource: Resource) -> None:
        """无权访问或资源不存在，统一抛 FORBIDDEN，不区分二者。"""
        resource_known = resource in self.known_resources
        allowed = self._decide(user, action, resource) if resource_known else False
        if not allowed:
            raise AuthError(
                ErrorCode.FORBIDDEN, "拒绝访问该资源", internal="default_deny"
            )
