# 安全模型说明

## 1. 账号与口令

- 口令以 **PBKDF2-HMAC-SHA256**（240000 轮 + 每口令独立 16 字节随机盐）不可逆存储，
  哈希串自描述算法、轮数、盐、摘要；校验采用 `hmac.compare_digest` 恒定时间比较。
- **用户枚举防护**：“用户名不存在”与“口令错误”对外返回完全相同的
  `401 invalid_credentials`；对不存在用户也做一次等成本 PBKDF2 校验，消除时序侧信道。
  二者差异仅以 `reason=user_not_found / bad_password` 写入受控审计日志，不进响应体。
- 登录入口不因口令长度/类型返回可区分错误（仅注册/改密有长度要求，体现“设置”而非“核验”）。
- 角色永不采信客户端：自助注册强制 `roles=None`（零角色，最小权限）；
  权限判定读取的是服务端存储的 `User.roles`。角色只能由具备 `admin` 动作的会话
  通过 `POST /admin/users` 分配。

## 2. 会话模型（防固定、防重放）

- 会话是**纯服务端状态**，客户端只持有不透明高熵标识（256bit，HttpOnly、SameSite=Strict）。
- **登录成功即更换标识（防会话固定）**：
  - 未启用 MFA：登录临界区内删除该账号全部既有标识，仅保留一个全新标识；
  - 已启用 MFA：登录先签发“待二因素”标识，仅轮换此前遗留的待二因素会话（避免多个
    挂起窗口）；MFA 校验通过、会话转正时再删除该待二因素标识并换新，同时
    `epoch+1` 吊销其它已认证会话。
  无论哪条路径，攻击者预置的旧标识在登录后都会落到“不存在”。
- 失效方式（三条独立防线，任意一条成立即拒绝）：
  1. **物理删除**：轮换/登出直接从存储移除旧标识，重放得到“不存在”，无法复活；重复登出幂等。
  2. **revoked 标记**：改密 / MFA 解绑（重置）/ 注销在存储临界区内批量 `revoked`；
     返回 `session_revoked`。
  3. **auth_epoch 纪元校验**：`SessionRecord.auth_epoch` 与 `User.auth_epoch` 不符即拒绝并删除。
- 到期会话判定为 `session_expired`，并立即物理删除；再次使用转为 `unauthenticated`。
- 待二因素会话 `mfa_completed=False`，不能访问任何受保护资源（`mfa_required`）。

### 登录与 MFA 两阶段流程

```
POST /auth/login
  ├─ 未绑定 MFA：200 + 已认证会话
  └─ 已绑定 MFA：200 + 待二因素会话（mfa_completed=False）
POST /auth/mfa {code}
  └─ 校验通过（当前时间步、首次使用）：
       同一临界区内：epoch+=1 → 吊销该账号其它全部会话 → 删除待二因素标识
                  → 签发带新纪元的已认证新标识（防固定）
```

绑定采用两步式：`GET /auth/mfa/bind`（签发待确认密钥，**不落库到用户**）→
`POST /auth/mfa/bind/confirm`（首屏验证码正确才生效）。绑定本身不踢会话，
以避免“绑定确认后自身 CSRF 失效”；旧会话在下次 MFA 登录转正时随纪元递增统一吊销。

## 2.1 注销 / 改密 / MFA 重置的即时一致性

所有账号级状态变更都在**单个存储临界区（`store.lock()`）**内完成“读用户 → 改状态 →
批量吊销会话”，因此并发触发时不会出现只失效一部分或半更新：

| 触发 | 用户字段变化 | 既有会话 |
| --- | --- | ------ |
| 改密 | `password_hash` 更新，`auth_epoch+1` | 全部 revoked（含当前），要求重新登录 |
| MFA 解绑（重置） | `mfa_secret=None`，`auth_epoch+1` | 全部 revoked |
| MFA 绑定确认 | `mfa_secret` 生效 | 不立即踢；下次 MFA 登录转正时随 epoch+1 吊销 |
| MFA 登录成功 | `auth_epoch+1` | 除新会话外全部 revoked；旧待二因素标识物理删除 |
| 登出 | — | 该标识物理删除（幂等） |

## 3. 多因素（TOTP）

- 标准 RFC6238/4226：HMAC-SHA1（可扩展）、可配置步长/位数/前后偏移步数。
- **三类失败严格区分**（HTTP 均为 401，但 `error.code` 不同）：
  - `mfa_invalid_code`：窗口内无匹配（含非法格式）→ 不消费；
  - `mfa_time_skew`：命中非当前时间步（过旧/过新）→ 不消费、不通过；
  - `mfa_replayed_code`：当前时间步验证码已成功使用过。
- **重放防护是用户级的**：`User.mfa_last_step` 记录最近成功消费的时间步。
  同一时间步（只有一个合法验证码）在任何会话、任何入口都只能成功一次；
  会话级 `SessionRecord.consumed_mfa` 作为第二道记录。因此即便更换会话重放同一验证码，
  仍返回 `mfa_replayed_code` 且绝不成功。
- 前置条件：未绑定发起校验 → `mfa_not_bound`；已绑定再次绑定 → `mfa_already_bound`；
  未先 `begin_bind` 就确认 → `invalid_request`；解绑必须通过当前一次性口令。

## 4. 访问控制（默认拒绝）

- 资源为分层路径，如 `app/self/orders`、`admin/audit`；
  策略 `角色 -> 动作 -> 允许的路径前缀集合`，`*` 表示全域（默认仅 admin）。
- 判定只使用**服务端用户角色**与**服务端策略表**（`authapp/access.py`），
  前缀按路径段匹配（`admin/audit` 覆盖 `admin/audit/2026`，但 `app/self` 不能借兄弟名越权）。
- **资源存在性保密**：服务端维护已知资源集合，未知资源即使管理员也返回同一个
  `403 forbidden`，无法借此探测资源是否存在；无角色、动作未知、输入非法同样 403。
- 未经认证为 `401`，与已认证但无权的 `403 forbidden` 相区分。

## 5. CSRF（有状态变更）

- 令牌服务端保存 `token -> (session_id, expires_at)`，24 字节高熵随机串。
- 状态变更接口（写资源、改密、MFA 绑定确认/解绑、管理员建户）统一经 `require_csrf`：
  先校 **Origin/Referer 白名单**，再校令牌；缺失来源一律拒绝（不把“无 Origin”当放行）。
- 可区分结果：`csrf_missing`（带合法来源但无令牌）、`csrf_origin_mismatch`
  （无来源/来源不可信）、`csrf_invalid`（未知或**已消费**）、
  `csrf_session_mismatch`（令牌被搬到其它会话）、`csrf_expired`。
- 令牌**一次性**：验证通过立即销毁，重放即 `csrf_invalid`；会话轮换/登出时清理其名下令牌。
- `/auth/mfa` 与 `/auth/login`、`/auth/logout` 属于登录/终止动作，不依赖既有登录态，
  故不设 CSRF 令牌要求；所有写业务数据的接口强制 CSRF。

## 6. 节流与临时锁定

- 按用户名记录滑动窗口内失败时间戳；达到 `fail_threshold` 立即锁定 `lock_seconds`。
- “检查锁 → 核验口令 → 失败计数/加锁”全程在同一把存储锁内，
  并发失败请求不会绕过计数（测试 `test_concurrent_failures...` 用 3 倍阈值并发，
  断言计数精确且“加锁跃迁”恰好一次）。
- 锁定期内任何登录（**即使口令正确**）返回 `423 account_locked`（可区分提示与剩余秒数）；
  计数/锁字段丢失但计数仍达阈值时保守续锁，不降级。
- 窗口/锁均过期后惰性清零，恢复登录；成功登录清空计数与锁字段。

## 7. 审计

- 事件：`register`、`login`（success/mfa_required/denied/locked）、`mfa_login`、
  `logout`、`access_denied`、`account_locked`、`password_change`、`mfa_change`。
- 字段白名单 + 疑似敏感键兜底丢弃；用户名/用户ID/会话ID 仅以 HMAC-SHA256 截断
  **指纹**出现；**绝不记录**口令、TOTP 验证码、MFA secret、会话标识、CSRF 令牌。
- 输出单行 JSON（`tests` 中捕获为缓冲区断言“无泄漏”）。

## 8. 异常归一化与默认拒绝

| 来源 | 归一化结果 | HTTP |
| --- | --- | --- |
| 存储读写异常 | `storage_error` | 500 |
| 时间源异常 | `time_source_error` | 500 |
| 非法配置（含试图 `fail_open=True`） | `config_error` | 500（拒绝启动） |
| 未知异常 | 不吞掉、不放过请求 | 500 |

`AuthConfig.fail_open` 只允许 `False`，从数据结构上禁止“异常时放行”。
存储层把底层异常包装为 `AuthError(STORAGE_ERROR)`；时钟异常包装为 `TIME_SOURCE_ERROR`。

## 9. 判定对照表（被拒路径 → code）

| 场景 | HTTP | error.code |
| --- | --- | --- |
| 用户不存在 / 口令错误 | 401 | `invalid_credentials` |
| 锁定期登录（口令对或错） | 423 | `account_locked` |
| 无会话 / 登出或轮换后旧标识重放 | 401 | `unauthenticated` |
| 会话过期（首次） | 401 | `session_expired` |
| 改密/重置/纪元不符 | 401 | `session_revoked` |
| 待二因素访问受保护资源 | 401 | `mfa_required` |
| MFA 验证码错 | 401 | `mfa_invalid_code` |
| MFA 时间偏移 | 401 | `mfa_time_skew` |
| MFA 验证码重复使用 | 401 | `mfa_replayed_code` |
| 未绑定/已绑定/未发起绑定 | 409/409/400 | `mfa_not_bound` / `mfa_already_bound` / `invalid_request` |
| 已认证但越权 / 资源不存在 | 403 | `forbidden` |
| 写操作缺令牌（来源合法） | 403 | `csrf_missing` |
| 写操作无/伪来源 | 403 | `csrf_origin_mismatch` |
| 令牌未知或已消费 | 403 | `csrf_invalid` |
| 令牌用于其它会话 | 403 | `csrf_session_mismatch` |
| 令牌过期 | 403 | `csrf_expired` |
| 存储/时间/配置异常 | 500 | `storage_error` / `time_source_error` / `config_error` |

## 10. 本地可复现性

- 时间相关用例（过期、TOTP 步、锁窗口）全部走 `FakeClock`，无真实等待；
- TOTP 验证码由测试端用同一 secret 经 `authapp.security.totp.code_at` 生成，
  可在任意指定时刻精确复现；
- 并发用例使用 `ThreadPoolExecutor` 对同一临界区施压，断言计数/吊销最终态；
- 判定打印：`uv run pytest -s tests/test_distinguishable_verdicts.py`。
