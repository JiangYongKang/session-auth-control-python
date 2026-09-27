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

## 3. 账号自助会话管理与容量控制

在既有会话机制之上，提供"看清并收回本人登录态"以及"每账号在线会话封顶"
两层能力。两个端点都要求**已登录且完成多因素校验**；收回是状态变更，
还必须通过与登出/改密相同的 CSRF 校验与登录态校验。

### 3.1 查看本人活动会话

- `GET /account/sessions`（只读，不强制 CSRF）：返回当前账号全部活动会话。
  每条包含：

  | 字段 | 含义 |
  | --- | --- |
  | `reference` | 该会话的稳定引用（见 3.2），用于定向收回 |
  | `created_at` | 创建时间（UTC ISO-8601） |
  | `last_seen_at` | 最近活跃时间（UTC ISO-8601） |
  | `mfa_verified` | 是否已完成多因素 |
  | `current` | 是否为发起本次请求的会话本身 |

- **稳定顺序**：按 `(创建时间, 会话标识)` 排序；同一时刻重复查看，条数、
  顺序与引用完全一致。
- **跨账号隔离**：查询只按服务端主体的账号过滤，用户永远只能看到本人会话；
  不同账号的结果互不相关。
- 已过期的会话在列表视图中与正常解析路径一致地被原子清扫（转入墓碑），
  不会出现在清单里，也不占用容量名额。

### 3.2 稳定引用（reference）

对外不暴露原始会话标识，而是给出一个**不可反推、绑定账号、长期稳定**的引用：

- 引用为 `(账号, 会话标识)` 在服务端密钥下的 **HMAC-SHA256**（256 位，
  十六进制 64 字符）：
  - **不可反推**：单向散列 + 进程级随机密钥，拿到引用无法恢复会话标识，
    引用中也不包含标识的任何明文片段；
  - **不能跨账号使用**：HMAC 消息把账号名作为绑定域，解析时必须以调用者
    本人账号重新计算，并**只在属于该账号的候选会话/墓碑集合内**常量时间
    比对。其他账号的引用、随机伪造值在本账号候选集合中都没有对应消息，
    无法借此探测他人会话是否存在；
  - **稳定**：同一 `(账号, 会话标识)` 任意时刻得到同一引用，重复查看不变。
- 会话标识轮换（显式 `/auth/rotate`、MFA 升级）后会产生新会话标识，
  因此对应**新引用**；旧标识已入墓碑，旧引用解析为"已收回"。
  （实现修正：显式轮换签发的新 CSRF 令牌现在会与 MFA 升级路径一样在
  服务端落库并退役旧令牌，旋转后的会话才能正常通过后续状态变更校验。）

### 3.3 定向收回单条会话

- `POST /account/sessions/revoke`，请求体 `{"reference": "<64 hex>"}`，
  需要登录 + MFA + CSRF。
- 只作废引用对应的**那一条**会话（写入墓碑）：
  - 该会话立即失效，再次使用其原始标识时判定为 `SESSION_REPLAYED`，
    与"标识从未存在"（`UNAUTHENTICATED`）可区分；
  - 同一账号的其余会话完全不受影响；允许收回 `current=true` 的当前会话。
- 对不能命中的引用，返回两个**稳定且可互相区分**的结果，且不泄漏他人会话：

  | 判定码 | HTTP | 含义 |
  | --- | --- | --- |
  | `SESSION_REFERENCE_REVOKED` | 410 | 引用曾属于本人，但对应会话已被收回/过期/容量淘汰/轮换 |
  | `SESSION_INVALIDATED` | 401 | 引用对应会话是被全量登出/改密/MFA 重置等账号级失效作废的 |
  | `SESSION_REFERENCE_UNKNOWN` | 404 | 引用对该账号不存在：伪造、格式合法但无匹配、**或属于其他账号** |

  跨账号使用他人引用一律落到 `SESSION_REFERENCE_UNKNOWN`，无法据此判断
  他人会话是否存在。引用格式非法（非 64 位 hex）在入口即
  `VALIDATION_ERROR`（422）。
- 收回与容量淘汰、轮换等在**列表视图、重放判定、审计上完全同构**：
  每条被作废的会话各写一条 `SESSION_REVOKED`（字段 `cause` 区分
  `self_revoke` / `capacity_evicted`，墓碑原因保留首次撤销原因），
  审计中不记录引用明文（引用属敏感令牌）。

### 3.4 每账号在线会话数上限

- 配置项 `session.max_sessions_per_account`（默认 10，正整数，非法即
  fail-closed）。上限按账号独立计数。
- 登录成功、新会话落库的**同一存储事务/同一把锁内**执行容量约束：
  1. 先原子清扫该账号已过期的会话（过期不占名额）；
  2. 若活动会话数仍超过上限，按 `(创建时间, 会话标识)` **淘汰最旧**的
     若干条，直到恰好等于上限；
  3. 本次新登录会话被排除在淘汰候选之外，**新登录始终保留**。
- 因此任何时刻该账号活动会话数都不超过上限；并发登录由单锁串行化，
  "创建 + 淘汰"对每个登录都是一个原子步骤，不会出现超员或半更新。
- 被容量淘汰的会话与被逐条收回完全同构：入墓碑、原始标识重放判
  `SESSION_REPLAYED`、对应引用判 `SESSION_REFERENCE_REVOKED`、
  审计为 `SESSION_REVOKED cause=capacity_evicted`。并发的定向收回与淘汰
  经同一把锁串行，最终状态始终是"活动会话数 ≤ 上限"的一致状态。

### 3.5 与既有失效机制的兼容关系

| 既有机制 | 对会话/引用的影响 |
| --- | --- |
| `POST /auth/logout`（单条登出） | 同条会话入墓碑；其引用随后判 `SESSION_REFERENCE_REVOKED` |
| `POST /auth/logout-all`（全量登出） | 纪元 +1，全部会话原子失效；其引用判 `SESSION_INVALIDATED` |
| 改密 `POST /account/password` | 纪元 +1，全部会话失效；引用判 `SESSION_INVALIDATED` |
| MFA 绑定 / 解绑 / 管理员重置 | 纪元 +1，全部会话失效；引用判 `SESSION_INVALIDATED` |
| 空闲 / 绝对过期 | 当次使用判 `SESSION_EXPIRED`；引用判 `SESSION_REFERENCE_REVOKED` |
| 显式轮换 / MFA 升级轮换 | 旧标识入墓碑（旧引用"已收回"），新标识对应新引用 |
| 容量淘汰 | 被淘汰会话与逐条收回同构，引用判 `SESSION_REFERENCE_REVOKED` |
| 管理员变更角色 | 纪元 +1，目标全部会话失效；引用判 `SESSION_INVALIDATED` |

## 4. 多因素（TOTP，RFC 6238）

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

## 5. 权限判定（默认拒绝）

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

## 6. 跨站请求伪造（CSRF）

- 登录时随会话签发 256 位 CSRF 令牌；会话轮换 / MFA 升级时重新签发。
- 令牌在服务端记录与会话、来源（Origin）绑定，并带独立 TTL。
- 有状态变更的请求（登出、改密、轮换、定向收回会话、MFA 绑定/解绑/重置、
  `write/admin` 资源动作）必须通过 CSRF 校验。会话清单查询（GET）与
  `read` 动作不强制 CSRF。
- JSON 入口用 `X-CSRF-Token` 头；表单入口可用同名头或 `csrf_token` 字段。
- 可区分拒绝码：

| 判定码 | 含义 |
| --- | --- |
| `CSRF_MISSING` | 未提交令牌 |
| `CSRF_INVALID` | 令牌服务端不存在（伪造） |
| `CSRF_EXPIRED` | 超过 CSRF TTL |
| `CSRF_BOUND_SESSION` | 令牌属于其他会话 |
| `CSRF_BOUND_ORIGIN` | 令牌来源与请求 Origin 不一致 |

## 7. 登录失败节流与临时锁定

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

## 8. 异常归一化与 fail-closed

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

## 9. 审计

- 通道：标准 logging（logger `app.audit`，WARNING 级别 JSON 行）
  以及内存缓冲（测试可读取断言）。
- 覆盖事件：注册、登录成功/失败/锁定、登出、会话过期/重放/收回（含容量
  淘汰）、会话清单查询、访问允许/拒绝、CSRF 拒绝、MFA 绑定/校验/解绑/
  重置、改密、基础设施异常。
- 脱敏：键名包含 `password / secret / totp / otp / code / session_id /
  sid / csrf / token` 等片段的字段一律输出 `<redacted>`；
  审计中不会出现口令、一次性验证码、会话/CSRF 令牌明文。
