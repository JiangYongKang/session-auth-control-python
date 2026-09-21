# 会话式身份认证与访问控制（本地可完整验证）

基于 FastAPI 的一套**服务端会话**身份认证与访问控制参考实现，覆盖：

- 账号注册 / 登录（PBKDF2 不可逆口令存储；用户名不存在与口令错误对外不可区分）
- 服务端会话与**标识轮换**（登录升级换标识；登出/过期/改密后旧标识不可复活）
- 基于 TOTP 的多因素校验（绑定/校验/解绑前置条件；错误码 / 时间偏移 / 重放可区分）
- 默认拒绝的 RBAC（角色 × 资源路径前缀；资源存在性不泄漏；角色只来自服务端）
- 有状态变更接口的 CSRF 防护（令牌绑定会话与来源、一次性、可过期）
- 登录失败节流与临时锁定（阈值/窗口/锁时长可配置；并发计数原子化）
- 注销 / 改密 / MFA 重置对该账号全部既有会话**立即一致失效**
- 审计日志覆盖登录、登出、权限拒绝、锁定、MFA 变更，且不记录敏感明文
- 存储 / 时间源 / 配置异常**归一化且默认拒绝**，绝不降级放行

## 目录结构

```
authapp/
  errors.py     归一化错误码（对外可区分、不泄漏敏感信息）
  config.py     全部可配置项 + 启动期配置校验（fail_open 被禁止）
  clock.py      时间源抽象（SystemClock / 测试可控 FakeClock）
  models.py     User / SessionRecord / LoginFailure 领域模型
  audit.py      审计日志（白名单字段 + HMAC 指纹，不落敏感明文）
  sessions.py   会话创建/解析/轮换/登出/过期
  csrf.py       CSRF 令牌签发/校验（会话、来源、TTL、一次性）
  access.py     默认拒绝 RBAC 策略
  throttle.py   失败计数/滑动窗口/临时锁定
  mfa.py        TOTP 绑定/校验/解绑与三类失败区分
  service.py    认证门面：所有用例在单个存储临界区内完成
  api.py        FastAPI 路由、Cookie、CSRF 依赖、统一错误响应
  deps.py       默认装配（单例）
  security/     口令哈希(pbkdf2)、随机令牌、TOTP/HOTP
  store/        存储抽象 + 线程安全内存实现
tests/          pytest 套件（重放/CSRF 绕过/越权/节流并发/MFA 重放）
docs/
  security-model.md  会话与权限模型、MFA 与节流配置、威胁与判定对照
```

## 本地运行

要求 Python 3.14+，使用 [uv](https://docs.astral.sh/uv/)：

```bash
uv sync                       # 安装依赖（含 pytest）
uv run uvicorn main:app --reload --port 8000
# 健康检查
curl -s http://127.0.0.1:8000/healthz
```

> 本地默认监听 HTTP，Cookie 的 `secure` 标志为 False 以便本机验证；
> 生产置于 HTTPS 反代后时应在 `authapp/api.py` 中改为 `secure=True`。

## 本地验证（测试）

```bash
uv run pytest -q                                  # 全部用例
uv run pytest -q -s tests/test_distinguishable_verdicts.py   # 打印“输入->判定”
uv run pytest -q tests/test_session_replay.py     # 会话重放
uv run pytest -q tests/test_csrf.py               # CSRF 绕过
uv run pytest -q tests/test_access_control.py     # 越权访问
uv run pytest -q tests/test_throttle.py           # 失败节流（含并发）
uv run pytest -q tests/test_mfa.py tests/test_mfa_cross_session_replay.py  # MFA 重放
uv run pytest -q tests/test_concurrent_invalidation.py                     # 并发失效一致性
```

测试使用可控时钟（`tests/conftest.py: FakeClock`），可精确复现过期、时间偏移、
锁窗口；`test_distinguishable_verdicts.py` 会在单测日志中打印**可复现输入与判定结论**
（敏感字段已脱敏）。

## 端到端手工演练（HTTP）

下例中 `ORIGIN` 必须在配置白名单内（默认 `https://app.example.local`）。

```bash
BASE=http://127.0.0.1:8000
J=/tmp/cj.txt; rm -f $J

# 1) 自助注册（默认零角色；请求体里的 roles 会被忽略，无法提权）
curl -s -X POST $BASE/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'

# 2) 登录（成功下发 HttpOnly Cookie sid）
curl -s -c $J -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'

# 3) 失败不可区分：不存在用户 / 错误口令返回完全相同
curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"ghost","password":"password123"}'

# 4) 读受保护资源
curl -s -b $J $BASE/api/resource/app/self

# 5) 写操作：先申领一次性 CSRF 令牌，再带 Origin + 头部提交
TOK=$(curl -s -b $J $BASE/auth/csrf | python3 -c 'import sys,json;print(json.load(sys.stdin)["csrf_token"])')
curl -s -b $J -X POST $BASE/api/resource/app/self \
  -H "Origin: https://app.example.local" -H "x-csrf-token: $TOK" \
  -H 'Content-Type: application/json' -d '{"payload":{"k":1}}'
# 同一令牌再次使用 -> 403 csrf_invalid（一次性）

# 6) 登出后重放旧 sid -> 401 unauthenticated（旧标识无法复活）
curl -s -b $J -X POST $BASE/auth/logout
```

### 预置管理员 / 角色分配

服务端角色**只能**由具备 `admin` 权限的会话通过受控接口分配：

```bash
# 在 Python 中引导一个管理员（模拟运维受控开通）
uv run python -c "from authapp.deps import get_service; get_service().register('root','rootpassword1',roles=['admin'])"
# 之后：root 登录 -> 领 CSRF -> 建 member 用户
```

## 可配置行为（`authapp/config.py: AuthConfig`）

| 配置项 | 默认值 | 含义 |
| --- | --- | --- |
| `session_ttl_seconds` | 1800 | 会话有效期 |
| `csrf_token_ttl_seconds` | 1800 | CSRF 令牌有效期（一次性） |
| `allowed_origins` | `https://app.example.local` | 允许的 Origin/Referer 白名单 |
| `fail_window_seconds` | 300 | 登录失败滑动观察窗口 |
| `fail_threshold` | 5 | 窗口内触发临时锁定的失败次数 |
| `lock_seconds` | 900 | 临时锁定时长（锁内即使口令正确也拒绝） |
| `totp_period` / `totp_digits` | 30 / 6 | TOTP 步长与位数 |
| `totp_lookback_steps` / `totp_lookahead_steps` | 1 / 1 | 时间偏移容忍窗口（步数） |
| `min_password_length` | 8 | 注册/改密口令最小长度 |
| `fail_open` | 固定 False | 禁止基础设施异常时降级放行（构造即拒绝） |

## 错误判定依据（`error.code`）

详见 `docs/security-model.md` 的“判定对照表”。例如：
`invalid_credentials`（用户不存在/口令错误同一结果）、`account_locked`、
`mfa_invalid_code` / `mfa_time_skew` / `mfa_replayed_code`、
`session_expired` / `session_revoked` / `unauthenticated`、
`csrf_missing` / `csrf_expired` / `csrf_invalid` / `csrf_session_mismatch` /
`csrf_origin_mismatch`、`forbidden`、`storage_error` / `time_source_error` /
`config_error`。
