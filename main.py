import os

from app.api.app_factory import create_app

# 默认无任何特权账号。需要初始管理员时显式设置：
#   BOOTSTRAP_ADMIN_USER=root BOOTSTRAP_ADMIN_PASSWORD=...
_admin_user = os.environ.get("BOOTSTRAP_ADMIN_USER")
_admin_pw = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")
_bootstrap = (_admin_user, _admin_pw) if (_admin_user and _admin_pw) else None

app = create_app(bootstrap_admin=_bootstrap)
