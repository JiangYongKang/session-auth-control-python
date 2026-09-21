"""API 请求/响应模型。"""
from __future__ import annotations

from pydantic import BaseModel


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


class ErrorResponse(BaseModel):
    error: str
    reason: str
