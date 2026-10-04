# Privacy Gateway（本地策略 · 脱敏访问 · 审计回放）

一个完全本地化的敏感数据访问与脱敏控制服务。所有调用方、资源、策略与审计记录都由
进程内存储模拟，**不依赖任何外部服务或真实凭据**。同一身份在同一策略版本下的读取结果、
脱敏输出与审计结论都是确定性、可解释、可复现的。

- 框架：FastAPI（仅使用仓库已声明依赖；测试使用 `pytest`）
- 运行：Python 3.14 / uv
- 当前基准时间：**2026-09-23T12:00:00Z**（测试通过可注入时钟固定在此刻）

## 1. 目录结构

| 文件 | 职责 |
| --- | --- |
| `privacy_gateway/models.py` | 策略、调用方、资源、决策、审计条目、保留期延长的不可变数据模型 |
| `privacy_gateway/errors.py` | 带稳定 `code` 的拒绝异常，拒绝原因彼此可区分 |
| `privacy_gateway/policies.py` | 策略版本解析、策略校验与冲突检测（默认拒绝） |
| `privacy_gateway/masking.py` | 确定性脱敏原语：visible/redact/mask/hash |
| `privacy_gateway/store.py` | 本地存储；策略版本不可变，仅“当前版本”指针可移动；保留期延长登记 |
| `privacy_gateway/audit.py` | 追加式、幂等、加锁全序的审计日志；游标式增量/分批导出 |
| `privacy_gateway/decider.py` | 决策引擎：认证→授权→保留期（含延长）→脱敏→审计 |
| `privacy_gateway/holds.py` | 保留期延长（法务保留）的挂上 / 解除，动作本身可审计、可回放 |
| `privacy_gateway/evidence.py` | 决策取证导出（确定性、含摘要）与离线校验 |
| `privacy_gateway/replay.py` | 基于审计快照回放历史结论（不重新判定） |
| `privacy_gateway/fixtures.py` | 确定性种子数据（调用方/资源/两个策略版本） |
| `privacy_gateway/clock.py` | 可注入时钟（`SystemClock` / `FixedClock`） |
| `privacy_gateway/app.py` | HTTP 装配（支持依赖注入，便于测试） |

## 2. 策略模型

策略以**不可变版本**（如 `policy-v1`、`policy-v2`）整体存储，每个版本包含若干
`ScopePolicy`：

```text
Policy(version, scope_policies, default_retention_days, created_at)
  └── ScopePolicy(scope, allowed_callers, field_rules,
                  default_field_action, retention_days, on_expiry)
        └── FieldRule(field_name, action, keep_prefix, hash_prefix)
```

- **默认拒绝（deny by default）**：身份未知、scope 未被任何规则覆盖（策略缺省）、
  字段未被规则治理、策略版本不存在、策略内部冲突，全部拒绝，绝不隐式放行。
- **版本不可变**：同一版本号写入不同内容会得到 `POLICY_CONFLICT`；更新策略只能新增版本
  并切换“当前版本”指针。历史决策永远绑定并回放其当时的版本。
- 种子策略演进（见 `fixtures.py`）：
  - `policy-v1`：仅 `alice` 可读 `patient_health`；账单保留 180 天；银行卡号哈希。
  - `policy-v2`（当前）：新增 `bob` 可读 `patient_health`；诊断码由整段抹除改为保留
    4 字符前缀；账单保留收紧到 90 天且超期返回墓碑；新增 `audit_logs` scope（仅 `carol`）。

## 3. 脱敏规则

每个字段的动作由策略版本固定，均为纯函数，相同输入永远得到相同输出：

| 动作 | 输出 | 示例 |
| --- | --- | --- |
| `visible` | 原值（显式允许的非敏感字段） | `REC-1001` |
| `redact` | 固定标记，不含任何原值信息 | `[REDACTED]` |
| `mask` | 保留固定长度前缀，其余替换为 `*` | `138********`、`张**`、`hype****************` |
| `hash` | `sha256:` + 稳定 SHA-256 摘要前缀 | `sha256:01a54629` |

字段按名称排序后处理，保证输出顺序确定。响应、异常信息、结构化日志、审计记录中
**只出现脱敏后的值或安全标识（caller_id / resource_id / scope / 字段名 / 版本号）**，
原始敏感值（SSN、手机号、卡号、邮箱等）不会出现在任何位置（测试 `test_no_raw_secret_in_logs_or_audit` 强制校验）。

## 4. 决策流水线与拒绝原因

`Decider.decide()` 的每个阶段都有独立、可区分的拒绝码：

| 顺序 | 阶段 | 失败码 / HTTP 状态 |
| --- | --- | --- |
| 1 | 幂等/回放短路（按 `request_id`） | `IDEMPOTENCY_CONFLICT` 409（同 id 不同载荷） |
| 2 | 调用方认证 | `UNAUTHORIZED_CALLER` 401 |
| 3 | 策略版本解析/校验 | `POLICY_NOT_FOUND` 404 / `POLICY_CONFLICT` 409 |
| 4 | 资源查找 | `RESOURCE_NOT_FOUND` 404 |
| 5 | scope 是否被策略覆盖 | `SCOPE_NOT_POLICIED` 403（策略缺省） |
| 6 | scope 授权（allow list） | `ACCESS_DENIED` 403 |
| 7 | 字段级授权（字段越权） | `FIELD_FORBIDDEN` 403 |
| 8 | 保留期检查（含保留期延长，见 6.1） | `RETENTION_EXPIRED` 410 或墓碑（200, `decision=tombstone`） |
| 9 | 确定性脱敏 | — |
| 10 | 追加审计（每 request_id 仅一条） | — |

拒绝也会产生决策结果（`decision=deny` + `deny_code`）并被审计，因此拒绝结论同样可回放。

## 5. 审计语义

- **追加式 + 全序**：`AuditLog` 用锁保证“查重 → 分配序号 → 追加”原子执行；并发下序号
  连续无空洞，顺序确定，30 路并发测试见 `test_concurrent_distinct_requests_get_gapfree_sequence`。
- **幂等**：相同 `request_id` + 相同安全载荷指纹（SHA-256，内容仅含身份/资源/版本/字段列表）
  的重复提交或重试直接返回原条目，**不会产生重复审计**；同 id 不同载荷 → 409 且不改变状态。
- **只存安全材料**：决策、拒绝码、判定依据（`basis`）、脱敏后字段快照、策略版本、
  `expired` / `hold_active` 状态、依据描述与时间戳。
- 单测日志中每次判定都会打印：输入（caller/resource/请求版本/字段）、命中的策略版本、
  判定依据（如 `access-denied`、`retention-expired`、`allow-under-retention-hold`、
  `retention-hold-placed`）以及命中的字段规则。
  用 `uv run pytest -s` 可查看 `[trace]` 行。

## 6. 保留期语义

- 资源年龄 = 决策时钟 − `resource.created_at`；保留天数取 scope 级
  `retention_days`，缺省回退到策略级 `default_retention_days`。
- 超期数据**绝不静默返回完整内容**，由 scope 的 `on_expiry` 决定：
  - `deny`（默认）：410 风格拒绝，响应/审计不含任何字段值；
  - `tombstone`：`decision=tombstone, expired=true`，仅含资源标识；
  - `purge`：先从本地存储擦除再拒绝，擦除事件同样审计；重试仍是稳定的同一条拒绝。
- 同一资源在不同版本下结论可以不同（种子中 `r-bill-mid` 已 145 天：v1 的 180 天窗口内
  允许，v2 的 90 天窗口外为墓碑）。**策略升级不影响历史结论**：回放始终渲染存储的快照，
  不重新访问现行策略或数据。

## 6.1 保留期延长 / 解除（法务保留）

运营可以对**某个具体资源**挂一个保留期延长（retention hold，相当于法务保留）：

- **语义**：延长生效期间，资源即使已超过普通保留期也按“未超期”处理——正常读出、
  **脱敏规则完全不变**；解除（release）之后立即回到普通保留期的处理（超期即按
  `on_expiry` 拒绝 / 墓碑 / 擦除）。延长期间 `purge` 不会擦除该资源。
- **状态记录**：每条读取的审计条目都记录当时的 `expired`（是否已超普通保留期）与
  `hold_active`（是否挂着延长）。延长期间的放行记为
  `basis=allow-under-retention-hold`，与普通放行（`allow`）、越权
  （`access-denied`）、超期（`retention-expired`）等依据明确区分。
- **一致性**：因为状态落在审计条目里，同一请求的首次判定、幂等重试、事后回放拿到的
  结论（含“当时到底超没超期”）完全一致，前后不打架。
- **动作可审计**：挂上 / 解除本身是一等审计事件（`decision=recorded`，
  `event_type=retention_hold / retention_release`，
  `basis=retention-hold-placed / retention-hold-released`），同样可回放、幂等
  （按 `hold_id` / `release_id` 去重；同 id 不同载荷 → `IDEMPOTENCY_CONFLICT`）。
- 操作人必须是已登记调用方，否则 `UNAUTHORIZED_CALLER`；解除时没有生效中的延长 →
  `HOLD_NOT_FOUND`（404）。

## 6.2 决策取证导出与离线校验

- `GET /v1/evidence/{request_id}` 导出一份机器可读的取证材料（JSON，
  `format=privacy-gateway-evidence/v1`）：决策、拒绝码、判定依据、策略版本、
  `expired` / `hold_active` 状态、脱敏后字段快照、请求指纹、时间戳，以及对全部内容
  计算的 SHA-256 `digest`。**不含任何原始敏感值**。
- **确定性**：导出是存储审计条目的纯函数（键排序、固定分隔符、UTF-8 的规范化
  序列化），同一条历史结论在任何时间、任何进程重新导出都**逐字节一致**，可直接按
  字节核对（测试含子进程交叉验证）。
- `POST /v1/evidence/verify`（body 为取证材料 JSON）做离线校验：先核对材料自身
  digest，再从当前审计轨迹重新导出同一历史结论并逐字节比对。任何不一致——材料被
  改动、digest 不符、状态字段（`expired` / `hold_active` / `basis` 等）对不上、
  找不到对应历史结论——都会得到 `consistent=false` 并列出全部 `mismatches`，
  绝不静默放过。
- **兼容范围**：校验按 `format` 版本号对齐，目前仅接受
  `privacy-gateway-evidence/v1`；格式不匹配会作为不一致显式报出。取证材料描述的是
  导出时的历史结论，策略升级、资源后续变化不影响对历史结论的校验。

## 6.3 审计增量 / 分批导出

- `GET /v1/audit/export?after=<seq>&limit=<n>` 按序号游标分批取审计：
  返回 `{entries, next_cursor, has_more}`，把 `next_cursor` 回填即可断点续传。
- **不漏不重**：审计是追加式、序号连续无空洞的全序日志，每一页在单次加锁快照上
  计算；导出过程中有新访问写入时，新条目只会被后续页取到，顺序永远按序号升序。
- **游标可重用**：同一游标重复查询永远返回同一页，重试不会串页或错乱；游标超过
  末尾时返回空页且 `has_more=false`。
- **容量边界**：`limit` 缺省/上限为 1000（`AuditLog.MAX_PAGE_SIZE`），非法值会被
  钳制；`AuditLog.iter_pages()` 以生成器方式流式产出，不会把全部历史一次性读入
  调用方内存。

## 7. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `GET /health` | 健康检查与当前策略版本 |
| `POST /v1/access/decide` | 提交读取决策（body 见下） |
| `GET /v1/audit` | 按序号列出全部审计条目 |
| `GET /v1/audit/export?after=&limit=` | 游标式增量/分批导出审计（见 6.3） |
| `GET /v1/audit/{request_id}` | 查看单次请求的审计条目 |
| `GET /v1/replay` | 回放全部历史决策（与当时一致的响应形态） |
| `POST /v1/holds` | 对资源挂保留期延长（`hold_id`/`resource_id`/`operator_id`/`reason`） |
| `POST /v1/holds/release` | 解除资源的保留期延长（`release_id`/`resource_id`/`operator_id`） |
| `GET /v1/evidence/{request_id}` | 导出该结论的取证材料（见 6.2） |
| `POST /v1/evidence/verify` | 校验取证材料与历史结论是否一致 |
| `GET /v1/policies` | 列出已存版本与当前版本 |
| `POST /v1/policies/{version}/activate` | 切换当前策略版本 |

决策请求体：

```json
{
  "request_id": "q-001",
  "caller_id": "alice",
  "resource_id": "r-patient-1",
  "policy_version": "policy-v1",
  "fields": ["record_id", "ssn"]
}
```

`policy_version` 省略时使用当前版本；`fields` 省略时按资源全部字段走一遍字段授权
（未治理字段将导致 `FIELD_FORBIDDEN`）。

## 8. 本地验证

```bash
uv sync                                  # 安装依赖（含 pytest 开发依赖）
uv run pytest -v -s                      # 全量测试 + 打印判定 trace
uv run pytest -q                         # 安静模式（当前 47 个用例全部通过）
uv run fastapi dev main.py               # 启动服务：http://127.0.0.1:8000/docs
```

快速手动验证（服务启动后）：

```bash
# 允许：alice 在 v2 下读取，ssn 哈希、diagnosis 保留 4 字符前缀
curl -s -X POST localhost:8000/v1/access/decide -H 'content-type: application/json' \
  -d '{"request_id":"q1","caller_id":"alice","resource_id":"r-patient-1"}'

# 同一请求重试 -> 返回完全相同结果，审计不新增
curl -s -X POST localhost:8000/v1/access/decide -H 'content-type: application/json' \
  -d '{"request_id":"q1","caller_id":"alice","resource_id":"r-patient-1"}'

# 指定 v1：bob 被拒绝（ACCESS_DENIED），diagnosis 在 v1 下应为 [REDACTED]
curl -s -X POST localhost:8000/v1/access/decide -H 'content-type: application/json' \
  -d '{"request_id":"q2","caller_id":"bob","resource_id":"r-patient-1","policy_version":"policy-v1"}'

# 不存在的版本 -> POLICY_NOT_FOUND（不放行）
curl -s -X POST localhost:8000/v1/access/decide -H 'content-type: application/json' \
  -d '{"request_id":"q3","caller_id":"alice","resource_id":"r-patient-1","policy_version":"policy-vX"}'

curl -s localhost:8000/v1/replay         # 回放：历史结论不受当前版本影响

# 保留期延长：r-patient-old 本已超期（410），挂延长后可读，解除后恢复超期
curl -s -X POST localhost:8000/v1/holds -H 'content-type: application/json' \
  -d '{"hold_id":"h1","resource_id":"r-patient-old","operator_id":"carol","reason":"legal case 42"}'
curl -s -X POST localhost:8000/v1/access/decide -H 'content-type: application/json' \
  -d '{"request_id":"q4","caller_id":"alice","resource_id":"r-patient-old"}'   # allow + hold_active
curl -s -X POST localhost:8000/v1/holds/release -H 'content-type: application/json' \
  -d '{"release_id":"rel1","resource_id":"r-patient-old","operator_id":"carol"}'

# 取证导出与离线校验（重复导出逐字节一致；篡改后 consistent=false）
curl -s localhost:8000/v1/evidence/q4 > evidence-q4.json
curl -s -X POST localhost:8000/v1/evidence/verify -H 'content-type: application/json' \
  -d @evidence-q4.json

# 审计增量导出：游标翻页，断点续传
curl -s 'localhost:8000/v1/audit/export?after=0&limit=2'
```

## 9. 测试覆盖一览

- `tests/test_access_and_masking.py`：六类拒绝原因可区分、脱敏确定性与版本差异、
  原始值不出现在日志中（caplog 校验输入/版本/依据三要素）。
- `tests/test_concurrency_idempotency.py`：30 路并发序号连续无重复、同请求 10 路并发
  只产生一条审计、拒绝重试稳定、同 id 不同载荷 409、载荷指纹稳定性。
- `tests/test_policy_version_retention.py`：版本升级不改历史结论、超期拒绝不返内容、
  跨版本保留阈值差异、purge 擦除后可审计、版本不存在拒绝、策略冲突拒绝、版本不可变。
- `tests/test_masking_primitives.py`：mask/hash 纯函数确定性与回放顺序/内容稳定。
- `tests/test_retention_hold.py`：延长期间超期资源可读且脱敏不变、解除后立即回到
  保留期处理、延长/解除事件可审计可回放且依据可区分、首次/重试/回放状态一致、
  延长阻止 purge、操作幂等与冲突、无延长时解除报 `HOLD_NOT_FOUND`。
- `tests/test_evidence.py`：取证导出跨时间/跨进程逐字节一致、反复校验一致、
  篡改/digest 损坏/未知 id 均明确报不一致、材料不含原始敏感值、
  `expired`/`hold_active`/`basis` 状态与历史结论对齐。
- `tests/test_audit_export.py`：分批导出完整有序不重不漏、游标重用同页、越界空页、
  页大小钳制、流式迭代、并发写入下导出不漏不重、HTTP 端点断点续传。
