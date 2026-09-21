# 可配置行为

配置由 `app/config.py` 的 `default_config()` / `load_config()` 加载，
启动期强校验；任何非法值都抛 `ConfigError`（对外 `CONFIG_ERROR`），服务不启动。

## 配置项

### `password`（口令策略）

| 键 | 默认 | 约束 |
| --- | --- | --- |
| `min_length` | 8 | >= 1 |
| `require_digit` | true | bool |
| `require_alpha` | true | bool |

### `throttle`（失败节流 / 锁定）

| 键 | 默认 | 含义 |
| --- | --- | --- |
| `max_failures` | 5 | 观察窗口内触发锁定的失败次数 |
| `window_seconds` | 300 | 失败计数观察窗口（秒） |
| `lock_seconds` | 900 | 临时锁定时长（秒） |

均必须为正整数。

### `totp`（一次性口令）

| 键 | 默认 | 约束 |
| --- | --- | --- |
| `period` | 30 | 时间步长（秒），正整数 |
| `digits` | 6 | 6–8 |
| `drift_steps` | 1 | 允许的前后步偏移数，0–5 |
| `issuer` | `session-auth-control` | 非空，otpauth URI 发行方 |

`drift_steps=N` 表示接受当前步前后各 N 步（窗口大小 `2N+1`）。
设为 0 则只接受当前步。

### `session`（会话与 CSRF）

| 键 | 默认 | 含义 |
| --- | --- | --- |
| `idle_timeout_seconds` | 1800 | 空闲超时（滑动） |
| `absolute_timeout_seconds` | 28800 | 绝对超时（上限） |
| `csrf_ttl_seconds` | 1800 | CSRF 令牌有效期 |

要求 `idle <= absolute`，均为正整数。

### `role_permissions`（角色权限矩阵）

形如：

```json
{
  "admin":  {"":       ["read", "write", "admin"]},
  "viewer": {"docs/":  ["read"]},
  "editor": {"docs/":  ["read", "write"]}
}
```

- key 为角色名；value 为 `资源前缀 -> 动作列表`。
- 空前缀 `""` 表示匹配所有资源。
- 合法动作仅 `read` / `write` / `admin`；动作集合不能为空。
- 未配置的角色等价于无任何权限（默认拒绝）。

### `self_service_roles`（自助注册可申请的角色白名单）

- 默认 `["viewer", "editor"]`。
- 必须是 `role_permissions` 中已存在的角色；空集合表示注册后一律无角色。
- 不在白名单的角色（如 `admin`）不能通过 `/auth/register` 获取，
  只能由管理员通过 `POST /admin/users/{username}/roles` 授予，
  或经 `bootstrap_admin` 受信引导。

### 初始管理员引导

默认不创建任何特权账号。启动时设置环境变量即可引导一个 admin：

```bash
BOOTSTRAP_ADMIN_USER=root BOOTSTRAP_ADMIN_PASSWORD='强口令' \
  uv run uvicorn main:app --port 8000
```

## 在测试中覆盖配置

```python
from app.api.app_factory import create_app
from app.config import default_config

cfg = default_config({
    "throttle": {"max_failures": 1, "window_seconds": 10, "lock_seconds": 30},
    "totp": {"drift_steps": 0},
    "session": {"idle_timeout_seconds": 10,
                "absolute_timeout_seconds": 100,
                "csrf_ttl_seconds": 5},
})
app = create_app(config=cfg)
```

故障注入：

```python
# 指定存储方法抛 StoreError（验证不降级放行）
create_app(failing_methods=frozenset({"get_user"}))
# 时间源始终失败
create_app(time_source=FailingTimeSource())
```
