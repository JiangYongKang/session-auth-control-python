"""默认拒绝的权限判定：角色 × 资源范围（前缀）。

判定依据：
- 主体角色只来自服务端会话解析（绝不信客户端提交的角色/范围）；
- 任一角色的任一资源前缀匹配资源、且包含动作 => 允许；
- 其余一律拒绝。对"资源不存在"和"存在但无权"，调用方统一以
  FORBIDDEN 回应，不泄漏资源是否存在；判定细节只写受控审计。
"""
from __future__ import annotations

from app.audit import AuditEvent, AuditLogger
from app.config import SecurityConfig
from app.errors import AppError, ErrorCode

VALID_ACTIONS = frozenset({"read", "write", "admin"})


class AccessService:
    def __init__(self, config: SecurityConfig, audit: AuditLogger) -> None:
        self.config = config
        self.audit = audit

    def evaluate(self, roles: tuple[str, ...], resource: str,
                 action: str) -> tuple[bool, str]:
        """返回 (允许, 判定依据)。依据为可复现的稳定字符串。"""
        if action not in VALID_ACTIONS:
            return False, f"unknown_action:{action}"
        if not resource or not isinstance(resource, str):
            return False, "empty_resource"

        granted = False
        matched_scope: str | None = None
        for perms in self.config.permissions_for(tuple(roles)):
            for prefix, actions in perms.items():
                if action in actions and (
                        prefix == "" or resource == prefix
                        or resource.startswith(prefix)):
                    granted = True
                    matched_scope = prefix if prefix else "<all>"
                    break
            if granted:
                break

        if granted:
            return True, (f"role_scope_match roles={sorted(roles)} "
                          f"scope={matched_scope!r} action={action}")
        if not roles:
            return False, "default_deny:no_roles"
        return False, (f"default_deny roles={sorted(roles)} "
                       f"resource={resource!r} action={action}")

    def authorize(self, roles: tuple[str, ...], resource: str,
                  action: str, *, user: str | None = None) -> None:
        allowed, basis = self.evaluate(roles, resource, action)
        if not allowed:
            self.audit.record(
                AuditEvent.ACCESS_DENIED, user=user, result="denied",
                reason=ErrorCode.FORBIDDEN.value,
                decision_basis=basis,
                role_count=len(roles))
            # 统一 FORBIDDEN：不存在与无权不可区分
            raise AppError(ErrorCode.FORBIDDEN, "access denied")
        self.audit.record(
            AuditEvent.ACCESS_ALLOWED, user=user, result="ok",
            reason=None, decision_basis=basis, action=action)
