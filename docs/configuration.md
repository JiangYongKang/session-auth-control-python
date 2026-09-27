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
| `max_sessions_per_account` | 10 | 每账号活动会话数上限（正整数） |

要求 `idle <= absolute`，均为正整数；`max_sessions_per_account` 必须为
正整数（`1` 表示仅保留最近一次登录的会话）。达到上限再登录时，在同一存储
事务内先清扫过期会话、再按"最旧优先"原子淘汰，新登录会话始终保留，
任何时刻活动会话数都不超过该值。

### 会话稳定引用的密钥

会话清单中的 `reference` 是 `(账号, 会话标识)` 在服务端密钥下的 HMAC-SHA256。
该密钥由 `SessionReferenceSigner` 在进程启动时随机生成（`secrets.token_bytes(32)`），
因此：

- 不落盘、不随任何接口输出，引用不可反推原始标识；
- 引用仅在**同一进程生命周期内**可解析。进程重启后旧引用不再能解析，
  会话本身仍按原有效期/墓碑语义正常工作，用户重新查看清单即可获得新引用。
- 需要跨进程/多副本共享时，应通过受控配置向 `SessionReferenceSigner(secret=...)`
  注入统一密钥（当前内存存储本身也是单进程的，多副本部署需先替换存储实现）。

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
                "csrf_ttl_seconds": 5,
                "max_sessions_per_account": 3},
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
