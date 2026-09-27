# 本地验证方法

## 环境

- Python 3.14+、`uv`。
- 安装依赖：`uv sync`。

## 1. 运行单元 / 集成测试

```bash
uv run pytest
```

测试使用 FastAPI `TestClient` + 可控时间源（`ManualTimeSource`）+
内存存储 + 审计缓冲，无需外部服务。

pytest 已配置 `log_cli = WARNING`，运行时会实时打印形如下面的
**可复现输入与判定结论**（敏感字段已脱敏）：

```
app.audit: AUDIT {"event": "CSRF_REJECTED", "fields": {"origin": "http://evil.example"},
  "reason": "CSRF_BOUND_ORIGIN", "result": "denied", "user": "alice"}
```

### 测试文件与重点攻击路径

| 文件 | 覆盖重点 |
| --- | --- |
| `tests/test_auth_login.py` | 不可逆口令、用户不存在/口令错误不可区分、审计区分原因 |
| `tests/test_session_lifecycle.py` | 会话固定、标识轮换、登出/过期重放、登录态失效 |
| `tests/test_throttle.py` | 失败阈值、锁定提示、窗口重置、并发锁定一次、阈值可配 |
| `tests/test_csrf.py` | CSRF 缺失/伪造/过期/跨会话/跨来源绕过、表单与 JSON 一致 |
| `tests/test_access_control.py` | 默认拒绝、越权、前缀边界、不信客户端角色、MFA 待确认拦截 |
| `tests/test_mfa.py` | 绑定前置条件、错误/重放/时间漂移区分、解绑、管理员重置 |
| `tests/test_session_invalidation.py` | 改密/全量登出立即一致失效、并发无半更新 |
| `tests/test_session_management.py` | 活动会话清单、稳定引用、定向收回、跨账号/失效引用拒绝、容量上限与并发登录淘汰 |
| `tests/test_infra_failures.py` | 存储/时间源/未知异常 fail-closed、错误归一化 |
| `tests/test_audit.py` | 审计事件覆盖与口令/验证码/会话标识脱敏 |

只跑某一类：

```bash
uv run pytest tests/test_throttle.py -q
uv run pytest -q -k "replay or csrf or throttle or mfa"
# 新能力（清单 / 定向收回 / 容量上限 / 并发）
uv run pytest tests/test_session_management.py -q
uv run pytest -q -k "revoke or capacity or reference"
# 连续多轮确认稳定性（新测试含并发登录/收回场景）
for i in 1 2 3; do uv run pytest -q || break; done
```

## 2. 启动真实服务

```bash
uv run uvicorn main:app --port 8000
# 或 uv run python -m uvicorn main:app --port 8000
```

健康检查（会探测时间源与存储）：

```bash
curl -s http://127.0.0.1:8000/health
```

## 3. 端到端脚本

```bash
./scripts_e2e.sh
```

脚本会在 8131 端口启动 uvicorn，用 curl 依次验证：
注册/登录、不可区分失败、越权、CSRF 跨来源/缺失、
正常放行、登出后旧标识重放。期望最后输出 `E2E_DONE`。

## 4. 手工复现关键场景

以下请求假设服务运行在 `http://127.0.0.1:8000`，且已注册
`alice / Sup3rSecret`（viewer）。

```bash
BASE=http://127.0.0.1:8000
# 登录（同源 Origin）
LOGIN=$(curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -H 'Origin: http://local.test' \
  -d '{"username":"alice","password":"Sup3rSecret"}')
SID=$(python3 -c "import sys,json;print(json.load(sys.stdin)['session_id'])" <<<"$LOGIN")
CSRF=$(python3 -c "import sys,json;print(json.load(sys.stdin)['csrf_token'])" <<<"$LOGIN")

# 越权写（viewer 无 write）
curl -s -X POST $BASE/access/resource -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test' \
  -d '{"resource":"docs/a","action":"write"}'
# => {"reason":"FORBIDDEN", ...}

# CSRF 跨来源
curl -s -X POST $BASE/access/resource -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://evil' \
  -d '{"resource":"docs/a","action":"write"}'
# => {"reason":"CSRF_BOUND_ORIGIN", ...}

# 登出后重放
curl -s -X POST $BASE/auth/logout -H "X-Session-Id: $SID" \
  -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test'
curl -s -X POST $BASE/access/resource -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -d '{"resource":"docs/a","action":"read"}'
# => {"reason":"SESSION_REPLAYED", ...}
```

## 5. 多因素手工流程

绑定：

```bash
# 1) 已登录会话上开始绑定，记下 secret
curl -s -X POST $BASE/mfa/enroll/start \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test'
# 2) 用认证器（或 python 计算）当前 6 位码确认
curl -s -X POST $BASE/mfa/enroll/confirm -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test' \
  -d '{"code":"123456"}'
```

之后登录返回 `mfa_required=true`，用 `/mfa/verify` 完成第二步。
脚本/测试中可用：

```python
from app.security.totp import generate_code, current_step
code = generate_code(secret, current_step(now, period=30))
```

## 6. 自助会话管理与容量上限手工流程

以下假设已用 `alice / Sup3rSecret` 登录（未绑定 MFA 时登录即视为已完成
多因素），`SID` / `CSRF` 为最近一次登录返回值。

```bash
# 多登录几次制造多条活动会话
curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -H 'Origin: http://local.test' \
  -d '{"username":"alice","password":"Sup3rSecret"}' >/dev/null

# 查看本人活动会话（只读，GET 无需 CSRF；需登录 + MFA）
curl -s $BASE/account/sessions -H "X-Session-Id: $SID" | python3 -m json.tool
# => {"sessions":[{"reference":"<64hex>","created_at":...,"last_seen_at":...,
#                  "mfa_verified":true,"current":...}], "count":N}

# 取出非当前会话的引用，定向收回它（状态变更：需 CSRF + 同源）
REF=$(curl -s $BASE/account/sessions -H "X-Session-Id: $SID" \
  | python3 -c "import sys,json;print(next(s['reference'] for s in json.load(sys.stdin)['sessions'] if not s['current']))")
curl -s -X POST $BASE/account/sessions/revoke -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test' \
  -d "{\"reference\":\"$REF\"}"
# => {"status":"revoked"}

# 再次收回同一引用 => 410 SESSION_REFERENCE_REVOKED
# 用其他账号的引用 / 64 位伪造值 => 404 SESSION_REFERENCE_UNKNOWN
# 不带 CSRF => 403 CSRF_MISSING
```

验证容量上限（测试/本地可临时调小上限）：

```python
from app.api.app_factory import create_app
from app.config import default_config
cfg = default_config({"session": {"max_sessions_per_account": 3}})
app = create_app(config=cfg)   # 同一账号第 4 次登录将原子淘汰最旧会话
```

并发登录/收回的原子性由内存存储的单一 `RLock` 保证，
见 `tests/test_session_management.py` 中的
`test_concurrent_logins_never_exceed_capacity` 与
`test_concurrent_revoke_and_eviction_leave_consistent_state`。

## 7. 错误判定码速查

- 认证：`INVALID_CREDENTIALS`、`ACCOUNT_LOCKED`
- 会话：`UNAUTHENTICATED`、`SESSION_EXPIRED`、`SESSION_REPLAYED`、
  `SESSION_INVALIDATED`、`SESSION_CONFIRMATION_PENDING`
- 会话引用：`SESSION_REFERENCE_REVOKED`（410，曾有效已撤销）、
  `SESSION_REFERENCE_UNKNOWN`（404，对该账号不存在/属他人/伪造）
- MFA：`MFA_CODE_INVALID`、`MFA_CODE_REUSED`、`MFA_TIME_DRIFT`、
  `MFA_NOT_ENROLLED`、`MFA_ALREADY_ENROLLED`
- 授权 / CSRF：`FORBIDDEN`、`CSRF_MISSING/INVALID/EXPIRED/BOUND_SESSION/BOUND_ORIGIN`
- 基础设施：`STORE_UNAVAILABLE`、`TIME_SOURCE_UNAVAILABLE`、
  `CONFIG_ERROR`、`INTERNAL_ERROR`
