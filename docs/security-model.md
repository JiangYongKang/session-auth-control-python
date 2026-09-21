# 会话与权限模型

本服务实现一套在各入口（JSON API、表单 API）下行为一致、判定可解释的
会话式身份认证与访问控制能力。所有拒绝路径都返回稳定的判定码
（`reason`），受控审计日志记录可复现的输入与结论，且不包含任何敏感明文。

## 1. 身份与口令

- 注册：`POST /auth/register`。
- 口令以 **PBKDF2-HMAC-SHA256**（每用户随机 salt、200k 次迭代）存储，
  编码格式为 `pbkdf2_sha256$iter$salt$hash`。存储中不存在明文，也无法逆推。
- 口令策略可配置：最小长度、必须含数字/字母。
- **角色授予（垂直越权防护）**：自助注册只允许申请配置白名单
  （`self_service_roles`，默认 `viewer` / `editor`）内的角色；
  请求 `admin` 等特权角色直接返回 403 `FORBIDDEN` 且不落库。
  特权角色只能通过：
  - 受信引导：`create_app(bootstrap_admin=(user, pw))`
    （`main.py` 中由 `BOOTSTRAP_ADMIN_USER/PASSWORD` 环境变量控制，
    默认不创建任何管理员）；
  - 管理员端点：`POST /admin/users/{username}/roles`
    （要求 admin 动作权限 + CSRF；授权成功即作废目标既有会话）。
- 登录：`POST /auth/login`。
  - **用户名不存在与口令错误对外完全不可区分**：同样的 HTTP 状态（401）、
    同样的 `INVALID_CREDENTIALS`、同样的文案。
  - 二者只在受控审计日志里以 `failure_cause=user_not_found|bad_password`
    区分；对不存在的用户不落库，避免账号枚举侧信道。

## 2. 服务端会话与标识轮换

- 会话状态全部保存在服务端（内存实现）。客户端只持有一个 256 位随机会话标识
  （`X-Session-Id` 头），角色/范围/MFA 状态均来自服务端，客户端无法篡改提权。
- 每个会话有：
  - `idle_expiry`：空闲超时（默认 1800s，滑动续期）；
  - `absolute_expiry`：绝对过期（默认 28800s，持续活动也无法越过）；
  - `epoch`：创建时所属的账号"会话纪元"；
  - `mfa_verified`：是否已完成多因素；
  - `csrf_token`：与该会话绑定的活动 CSRF 令牌。
- **会话固定防护**：
  - 登录成功总是签发全新随机会话标识；
  - 可显式调用 `POST /auth/rotate` 再次轮换；
  - 多因素校验成功后同样轮换标识。
  - 被轮换的旧标识进入"墓碑"（tombstone），立即失效。
- **登出 / 过期 / 作废后不得复活**：
  - 登出 `POST /auth/logout`；全设备登出 `POST /auth/logout-all`。
  - 被撤销的标识保存在墓碑中，再次提交判定为 `SESSION_REPLAYED`；
    从未签发过的伪造标识判定为 `UNAUTHENTICATED`，二者可区分。
  - 过期的当次返回 `SESSION_EXPIRED`，随后的重放返回 `SESSION_REPLAYED`。
  - 因改密 / MFA 解绑 / MFA 重置 / 全设备登出导致的失效，返回
    `SESSION_INVALIDATED`（内部仍记为重放事件并带墓碑原因）。

### 会话纪元（session_epoch）

改密、MFA 绑定/解绑、管理员 MFA 重置、全设备登出都会让账号纪元 `+1`，
并在**同一个存储事务**中：

1. 更新账号（纪元前进）；
2. 把该账号当前所有活动会话写入墓碑。

因此多个触发并发发生时，由单一锁串行化，结果要么完全生效要么不生效，
不会出现"只失效一部分会话"或"密码已改但旧会话仍可用"的半更新状态。

## 3. 多因素（TOTP，RFC 6238）

- 共享密钥为随机 base32；同时返回 `otpauth://` URI 供认证器扫码。
- 绑定流程（前置条件明确）：
  1. `POST /mfa/enroll/start`：已登录且**尚未绑定**才能开始
     （已绑定返回 `MFA_ALREADY_ENROLLED`）；
  2. `POST /mfa/enroll/confirm`：用当前一次性码确认，确认成功才算绑定完成；
     绑定成功即作废该账号既有会话，需重新登录并走第二步。
- 登录第二步：登录返回 `mfa_required=true` 后，会话处于"待确认"，
  访问资源会得到 `SESSION_CONFIRMATION_PENDING`；调用
  `POST /mfa/verify` 完成第二步，成功后会话升级、标识轮换。
- 解绑 `POST /mfa/unbind`：需要**口令 + 当前一次性码**双重再确认。
- 管理员重置 `POST /admin/mfa-reset/{username}`：要求调用方具备
  `admin` 动作权限；重置后目标账号全部既有会话立即失效。

### 三类失败被明确区分

| 判定码 | 含义 |
| --- | --- |
| `MFA_CODE_INVALID` | 允许时间窗内各步均不匹配（验证码错误） |
| `MFA_CODE_REUSED` | 命中的时间步 ≤ 上次已消费步（同一验证码重复使用） |
| `MFA_TIME_DRIFT` | 服务端允许窗口的最新步都不晚于已消费步（时钟偏移超出窗口） |

每个用户记录 `totp_last_step`（已消费时间步）。**只有窗口内确实匹配到一个
已消费步时才判 `REUSED`**，因此错误验证码不会被误报为重放。时间漂移优先
于重放判定。标准 RFC 6238 测试向量已用于交叉校验。

## 4. 权限判定（默认拒绝）

- 模型：角色 × 资源范围（前缀）× 动作（`read` / `write` / `admin`）。
  配置示例见 `app/config.py` 的 `DEFAULT_ROLE_PERMISSIONS`：
  - `admin`：空前缀 `""` 表示匹配全部资源、全部动作；
  - `viewer`：`docs/` 上 `read`；
  - `editor`：`docs/` 上 `read,write`。
- 判定：主体角色取自服务端会话；任一角色的任一前缀匹配资源且包含动作则允许；
  其余**默认拒绝**。`docs-evil` 不会匹配 `docs/` 前缀。
- 服务端**从不**读取请求体里的 `roles` / `scope` / `is_admin` 等字段。
- 对"资源不存在"和"存在但无权"统一返回 403 `FORBIDDEN`，不泄漏资源是否存在。
- 每次判定都写审计：`ACCESS_ALLOWED` / `ACCESS_DENIED`，
  含可复现的 `decision_basis`（角色、范围、动作、default_deny 原因）。

## 5. 跨站请求伪造（CSRF）

- 登录时随会话签发 256 位 CSRF 令牌；会话轮换 / MFA 升级时重新签发。
- 令牌在服务端记录与会话、来源（Origin）绑定，并带独立 TTL。
- 有状态变更的请求（登出、改密、轮换、MFA 绑定/解绑/重置、`write/admin`
  资源动作）必须通过 CSRF 校验。`read` 动作不强制 CSRF。
- JSON 入口用 `X-CSRF-Token` 头；表单入口可用同名头或 `csrf_token` 字段。
- 可区分拒绝码：

| 判定码 | 含义 |
| --- | --- |
| `CSRF_MISSING` | 未提交令牌 |
| `CSRF_INVALID` | 令牌服务端不存在（伪造） |
| `CSRF_EXPIRED` | 超过 CSRF TTL |
| `CSRF_BOUND_SESSION` | 令牌属于其他会话 |
| `CSRF_BOUND_ORIGIN` | 令牌来源与请求 Origin 不一致 |

## 6. 登录失败节流与临时锁定

可配置项（见下）：

- `max_failures`：观察窗口内允许的连续失败次数（默认 5）；
- `window_seconds`：失败计数的观察窗口（默认 300s）；
- `lock_seconds`：触发后的锁定时长（默认 900s）。

行为：

- 窗口内失败达到阈值的那一次请求即锁定账号；锁定期内**即使口令正确也拒绝**，
  返回独立的 423 `ACCOUNT_LOCKED`（与口令错误 401 可区分），并带
  `retry_after` 秒数。
- 窗口过期后计数重置；锁过期后可用正确口令登录。
- 计数与锁定在**单一存储事务**内读改写：并发失败请求不会绕过计数、
  不会超计、也不会把"设置锁定"重复执行多次（审计中 `lock_set=true`
  恰好出现一次，之后的请求都是"锁定期拒绝"）。

## 7. 异常归一化与 fail-closed

当存储、时间源或配置异常时，**绝不降级为放行**，统一返回同构错误体：

```json
{"error": "request_denied", "reason": "<CODE>", "detail": "..."}
```

| 判定码 | HTTP | 场景 |
| --- | --- | --- |
| `STORE_UNAVAILABLE` | 503 | 存储读写异常 |
| `TIME_SOURCE_UNAVAILABLE` | 503 | 取当前时间失败 |
| `CONFIG_ERROR` | 500 | 非法配置（启动期即 fail-closed） |
| `INTERNAL_ERROR` | 500 | 其他未预期异常（记录 `INFRA_ERROR`） |

`/health` 会主动探测时间源与存储，异常即返回 503，不报假健康。
存储故障注入包装器 `FailingStore`、时间故障 `FailingTimeSource` 用于测试验证。

## 8. 审计

- 通道：标准 logging（logger `app.audit`，WARNING 级别 JSON 行）
  以及内存缓冲（测试可读取断言）。
- 覆盖事件：注册、登录成功/失败/锁定、登出、会话过期/重放、
  访问允许/拒绝、CSRF 拒绝、MFA 绑定/校验/解绑/重置、改密、基础设施异常。
- 脱敏：键名包含 `password / secret / totp / otp / code / session_id /
  sid / csrf / token` 等片段的字段一律输出 `<redacted>`；
  审计中不会出现口令、一次性验证码、会话/CSRF 令牌明文。
