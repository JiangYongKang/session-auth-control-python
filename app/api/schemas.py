"""API 请求/响应模型。"""
from __future__ import annotations

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str
    password: str
    roles: list[str] | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class MfaCodeRequest(BaseModel):
    code: str


class UnbindRequest(BaseModel):
    password: str
    code: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class ResourceRequest(BaseModel):
    resource: str
    action: str


class RolesRequest(BaseModel):
    roles: list[str]


class SessionRevokeRequest(BaseModel):
    # 引用固定为 256 位 HMAC 的十六进制（64 字符）；格式非法在入口即拒绝
    reference: str = Field(min_length=64, max_length=64, pattern=r"[0-9a-f]{64}")


class ErrorResponse(BaseModel):
    error: str
    reason: str
