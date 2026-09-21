"""本地运行入口：uvicorn main:app --reload。

应用装配见 authapp.deps，路由见 authapp.api。
"""
from authapp.deps import app

__all__ = ["app"]
