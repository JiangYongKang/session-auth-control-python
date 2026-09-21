# session-auth-control (Python / FastAPI)

会话式身份认证与访问控制参考实现：登录、多因素校验、会话生命周期、
权限判定、CSRF 防护、失败节流与审计，在 JSON 与表单两类入口下行为一致、
判定可解释，且在存储 / 时间源异常时 fail-closed（不降级放行）。

## 快速开始

```bash
uv sync
uv run pytest                 # 59+ 项测试，实时打印脱敏审计判定日志
uv run uvicorn main:app --port 8000
./scripts_e2e.sh              # 真实服务器 + curl 端到端验证
```

## 能力一览

- 账号注册 / 登录；PBKDF2 不可逆口令存储；用户不存在与口令错误对外不可区分。
- 服务端会话；登录/升级即轮换标识防会话固定；登出、过期、改密/重置后旧标识
  进入墓碑，重放可区分且不复活。
- RFC 6238 TOTP 多因素；时间漂移、验证码复用、验证码错误三类失败可区分。
- 默认拒绝的 RBAC（角色 × 资源前缀 × 动作），角色只取自服务端会话，
  无权与资源不存在统一 403。
- 有状态变更请求强制 CSRF：缺失 / 伪造 / 过期 / 跨会话 / 跨来源均可区分。
- 可配置阈值与观察窗口的失败节流与临时锁定；并发失败不绕过计数、不重复锁定；
  锁定期内口令正确也返回可区分的 423。
- 改密、多因素重置、全设备登出通过会话纪元 + 单事务原子失效全部既有会话，
  并发下无半更新。
- 审计覆盖登录 / 登出 / 权限拒绝 / 锁定 / MFA 变更，口令、验证码、
  会话与令牌明文一律脱敏。
- 存储、时间源、配置异常归一为可区分错误码，绝不放行；`/health` 真实探测依赖。

## 目录

- `app/` 应用代码
  - `config.py` / `errors.py` / `audit.py` / `time_source.py`
  - `security/` 口令哈希、TOTP、CSRF 原语
  - `storage/` 存储协议、线程安全内存实现、故障注入
  - `services/` 认证、多因素、权限判定
  - `api/` FastAPI 路由、依赖、应用工厂
- `tests/` 以**会话重放、CSRF 绕过、越权、节流并发、MFA 重放**为重点的测试
- `docs/`
  - [security-model.md](docs/security-model.md) 会话与权限模型
  - [configuration.md](docs/configuration.md) 多因素与节流等可配置行为
  - [local-verification.md](docs/local-verification.md) 本地验证方法
