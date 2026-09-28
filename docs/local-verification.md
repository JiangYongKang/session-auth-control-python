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
| `tests/test_session_rotation.py` | 轮换后新令牌立即完成状态变更、旧令牌 CSRF_REVOKED 与伪造可区分（超 TTL 仍稳定）、旧标识 SESSION_REPLAYED、轮换只作用本条会话、引用跨账号隔离、轮换×淘汰×定向收回并发无半更新 |
| `tests/test_throttle.py` | 失败阈值、锁定提示、窗口重置、并发锁定一次、阈值可配 |
| `tests/test_csrf.py` | CSRF 缺失/伪造/过期/跨会话/跨来源绕过、表单与 JSON 一致 |
| `tests/test_access_control.py` | 默认拒绝、越权、前缀边界、不信客户端角色、MFA 待确认拦截 |
| `tests/test_mfa.py` | 绑定前置条件、错误/重放/时间漂移区分、解绑、管理员重置 |
| `tests/test_session_invalidation.py` | 改密/全量登出立即一致失效、并发无半更新 |
| `tests/test_session_management.py` | 清单稳定/隔离/引用不可反推、定向收回只影响目标、已失效与未知引用区分、跨账号拒绝、串行与并发容量淘汰 |
| `tests/test_infra_failures.py` | 存储/时间源/未知异常 fail-closed、错误归一化 |
| `tests/test_audit.py` | 审计事件覆盖与口令/验证码/会话标识脱敏 |

只跑某一类：

```bash
uv run pytest tests/test_throttle.py -q
uv run pytest -q -k "replay or csrf or throttle or mfa"
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
正常放行、显式轮换（新令牌放行、旧令牌 `CSRF_REVOKED`、伪造
`CSRF_INVALID`、旧标识 `SESSION_REPLAYED`）、登出后旧标识重放。
期望最后输出 `E2E_DONE`。

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

### 4.1 轮换后新令牌立即可用、旧令牌可区分失效

以下用 editor 账号演示（write 需要 editor 权限；viewer 上也可用
登出 / 改密 / 定向收回验证同一结论）：

```bash
BASE=http://127.0.0.1:8000
curl -s -X POST $BASE/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Sup3rSecret","roles":["editor"]}'
L=$(curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -H 'Origin: http://local.test' \
  -d '{"username":"alice","password":"Sup3rSecret"}')
OLD_SID=$(python3 -c "import sys,json;print(json.load(sys.stdin)['session_id'])" <<<"$L")
OLD_CSRF=$(python3 -c "import sys,json;print(json.load(sys.stdin)['csrf_token'])" <<<"$L")

# 轮换（旧令牌授权本次轮换）
R=$(curl -s -X POST $BASE/auth/rotate -H "X-Session-Id: $OLD_SID" \
  -H "X-CSRF-Token: $OLD_CSRF" -H 'Origin: http://local.test')
SID=$(python3 -c "import sys,json;print(json.load(sys.stdin)['session_id'])" <<<"$R")
CSRF=$(python3 -c "import sys,json;print(json.load(sys.stdin)['csrf_token'])" <<<"$R")

# 1) 新令牌同源状态变更：立即 200（写资源、登出、改密、定向收回同理）
curl -s -X POST $BASE/access/resource -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test' \
  -d '{"resource":"docs/a","action":"write"}'
# => {"status":"allowed", ...}

# 2) 新标识 + 旧令牌：CSRF_REVOKED（曾签发、已随轮换撤销）
curl -s -X POST $BASE/access/resource -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $OLD_CSRF" -H 'Origin: http://local.test' \
  -d '{"resource":"docs/a","action":"write"}'
# => {"reason":"CSRF_REVOKED", ...}

# 3) 新标识 + 伪造令牌：CSRF_INVALID（从未签发，与 2 可区分）
curl -s -X POST $BASE/access/resource -H 'Content-Type: application/json' \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $(python3 -c 'print("00"*32)')" \
  -H 'Origin: http://local.test' -d '{"resource":"docs/a","action":"write"}'
# => {"reason":"CSRF_INVALID", ...}

# 4) 旧标识重放：SESSION_REPLAYED（与从未存在的 UNAUTHENTICATED 可区分）
curl -s -X POST $BASE/access/resource -H 'Content-Type: application/json' \
  -H "X-Session-Id: $OLD_SID" -d '{"resource":"docs/a","action":"read"}'
# => {"reason":"SESSION_REPLAYED", ...}
```

并发交错（轮换 × 并发登录的容量淘汰 × 并发定向收回）无需手工复现，
直接运行 `tests/test_session_rotation.py` 中的并发用例，
或连续多轮 `uv run pytest` 观察稳定通过。

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

## 6. 自助会话管理手工流程

以下请求沿用第 4 节的 `$SID` / `$CSRF`（已登录 alice）。

```bash
# 查看本人活动会话（只读，无需 CSRF）
curl -s $BASE/account/sessions -H "X-Session-Id: $SID" -H 'Origin: http://local.test'
# => {"sessions":[{"ref":"…64hex…","created_at":...,"last_seen":...,
#                  "mfa_verified":true,"current":true}]}

# 用引用定向收回其中一条（状态变更，必须带 CSRF）
REF=$(curl -s $BASE/account/sessions -H "X-Session-Id: $SID" \
  -H 'Origin: http://local.test' | python3 -c "import sys,json;print(json.load(sys.stdin)['sessions'][0]['ref'])")
curl -s -X POST $BASE/account/sessions/$REF/revoke \
  -H "X-Session-Id: $SID" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://local.test'
# => {"status":"revoked"}
# 再次收回同一引用 => 409 SESSION_ALREADY_REVOKED
# 随机/他账号引用      => 404 NOT_FOUND（两者同形）
# 收回后重放该标识    => 401 SESSION_REPLAYED（区别于从未存在的 UNAUTHENTICATED）
```

容量上限：用 `session.max_active_sessions_per_account` 覆盖配置启动
（或直接运行 `uv run pytest tests/test_session_management.py -q`），
连续登录超过上限后，清单条数恒等于上限，最早登录的会话重放得到
`SESSION_REPLAYED`，最新会话始终可用。

## 7. 错误判定码速查

- 认证：`INVALID_CREDENTIALS`、`ACCOUNT_LOCKED`
- 会话：`UNAUTHENTICATED`、`SESSION_EXPIRED`、`SESSION_REPLAYED`、
  `SESSION_INVALIDATED`、`SESSION_CONFIRMATION_PENDING`、
  `SESSION_ALREADY_REVOKED`、`NOT_FOUND`（会话引用不存在，404）
- MFA：`MFA_CODE_INVALID`、`MFA_CODE_REUSED`、`MFA_TIME_DRIFT`、
  `MFA_NOT_ENROLLED`、`MFA_ALREADY_ENROLLED`
- 授权 / CSRF：`FORBIDDEN`、`CSRF_MISSING/INVALID/REVOKED/EXPIRED/BOUND_SESSION/BOUND_ORIGIN`
- 基础设施：`STORE_UNAVAILABLE`、`TIME_SOURCE_UNAVAILABLE`、
  `CONFIG_ERROR`、`INTERNAL_ERROR`
