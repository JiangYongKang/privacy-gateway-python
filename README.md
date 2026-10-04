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
| `privacy_gateway/models.py` | 策略、调用方、资源、决策、审计条目、保留期延长记录的不可变数据模型 |
| `privacy_gateway/errors.py` | 带稳定 `code` 的拒绝异常，拒绝原因彼此可区分 |
| `privacy_gateway/policies.py` | 策略版本解析、策略校验与冲突检测（默认拒绝） |
| `privacy_gateway/masking.py` | 确定性脱敏原语：visible/redact/mask/hash |
| `privacy_gateway/store.py` | 本地存储；策略版本不可变，仅“当前版本”指针可移动；保留期延长记录 |
| `privacy_gateway/audit.py` | 追加式、幂等、加锁全序的审计日志（访问决策 + 生命周期事件） |
| `privacy_gateway/decider.py` | 决策引擎：认证→授权→保留期（含延长）→脱敏→审计 |
| `privacy_gateway/holds.py` | 保留期延长 / 解除（法务保留），动作本身可审计、可回放 |
| `privacy_gateway/forensics.py` | 决策取证导出（字节确定）与离线校验（CONSISTENT / INCONSISTENT） |
| `privacy_gateway/export.py` | 审计增量 / 分批导出：游标分页、断点续传、内存有界 |
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
| 8 | 保留期检查（含延长） | `RETENTION_EXPIRED` 410 或墓碑（200, `decision=tombstone`）；挂有有效延长时放行 |
| 9 | 确定性脱敏 | — |
| 10 | 追加审计（每 request_id 仅一条） | — |

拒绝也会产生决策结果（`decision=deny` + `deny_code`）并被审计，因此拒绝结论同样可回放。

## 5. 审计语义

- **追加式 + 全序**：`AuditLog` 用锁保证“查重 → 分配序号 → 追加”原子执行；并发下序号
  连续无空洞，顺序确定，30 路并发测试见 `test_concurrent_distinct_requests_get_gapfree_sequence`。
- **幂等**：相同 `request_id` + 相同安全载荷指纹（SHA-256，内容仅含身份/资源/版本/字段列表）
  的重复提交或重试直接返回原条目，**不会产生重复审计**；同 id 不同载荷 → 409 且不改变状态。
- **只存安全材料**：决策、拒绝码、脱敏后字段快照、策略版本、依据描述与时间戳。
- **事件类型可区分**：每条审计带 `event_type`（`access` / `hold_place` / `hold_release`），
  访问决策另固化判定当时的 `retention_state`（是否超期、是否因延长放行），
  保证首次判定、重试与回放对“当时超没超期”的回答一致。
- 单测日志中每次判定都会打印：输入（caller/resource/请求版本/字段）、命中的策略版本、
  判定依据（如 `access-denied`、`retention-expired`、`retention-hold-active`、
  `hold-place`）以及命中的字段规则。
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

## 7. 保留期延长 / 解除（法务保留）

运营可以对**某个具体资源**挂一条保留期延长（`RetentionHold`），效果与语义：

- **挂上（place）**：资源即使已超过普通保留期，读取也照常放行，**脱敏规则完全不变**；
  授权、字段治理等其他判定一概不受影响（延长只暂停保留期这一阶段，不会放大权限）。
  该结论的 `retention_state` 记为 `past_retention_hold_active`，`expired=true`，
  日志依据为 `retention-hold-active`，与普通读取（`decision`）、越权（`access-denied`）、
  超期（`retention-expired`）明确区分。
- **解除（release）**：立即恢复普通保留期处理，下一次读取重新按超期拒绝/墓碑。
- **动作本身可审计、可回放**：挂上与解除都会写入审计流，`event_type` 分别为
  `hold_place` / `hold_release`（区别于访问决策的 `access`），携带 hold_id、资源、
  操作人与时间，不含任何字段内容；回放接口同样能渲染这两条事件。
- **幂等**：同一 `hold_id` 相同载荷重复挂 → 返回原记录、不新增审计；不同载荷 →
  `HOLD_CONFLICT` 409。重复解除 → 返回原解除记录，不新增审计。
- **结论一致性**：是否挂有延长直接决定“当时算不算超期”。每条决策都把当时的
  `retention_state`（`within_retention` / `past_retention` /
  `past_retention_hold_active`）固化进审计快照，因此同一请求无论是第一次判定、
  解除后重试，还是事后回放，结论与“当时超没超期”的状态都完全一致。

## 8. 决策取证导出与离线校验

- **导出**：`GET /v1/forensics/{request_id}` 把一条已产生的历史结论渲染为机器可读的
  取证文档（规范 JSON：键排序、紧凑分隔符、纯 ASCII），内容为审计条目快照
  （决策、deny_code、`retention_state`、脱敏后字段快照、时间戳）+ 条目规范编码的
  SHA-256 校验和。**不含任何原始敏感值**。
- **字节确定**：同一历史结论在任何时间、任何进程重复导出，结果逐字节一致，
  可直接按字节核对。
- **校验**：`POST /v1/forensics/verify`（或 `verify_evidence(blob, audit)`）做两层核对——
  文档自完整性（校验和）+ 与权威审计流中的历史结论逐字段比对。任何篡改或漂移
  （包括“当时是否超期”“按哪种方式处理”对不上）都返回明确的
  `{"status": "INCONSISTENT", "mismatches": [...]}`，绝不静默放过；校验结论同样只含
  安全字段。 malformed 输入不会抛异常，一律判 INCONSISTENT。
- **兼容范围**：文档携带 `schema = privacy-gateway/evidence@1`，校验只接受该版本；
  其他版本一律 INCONSISTENT。校验需要能访问同一审计流（权威来源）。

## 9. 审计增量 / 分批导出

- `GET /v1/audit-export?cursor=&limit=` 按游标分页；`stream_entries()` 提供生成器式
  流式导出，任何时刻只持有一页，**内存有界**，大导出不会把全部历史读进内存。
- 游标基于**连续无空洞的审计序号**（格式 `pg1:<sequence>`，指向上次最后一条之后）：
  导出过程中有新访问并发写入时，已导出的条目不会重复、未导出的不会遗漏，顺序稳定。
- **断点续传 / 幂等**：同一游标重复请求返回同一页；从任意游标继续即可接着导。
- `limit` 被钳制在 `[1, 1000]`；非法游标返回 `INVALID_CURSOR` 400。

## 10. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `GET /health` | 健康检查与当前策略版本 |
| `POST /v1/access/decide` | 提交读取决策（body 见下） |
| `GET /v1/audit` | 按序号列出全部审计条目 |
| `GET /v1/audit/{request_id}` | 查看单次请求的审计条目 |
| `GET /v1/replay` | 回放全部历史决策（与当时一致的响应形态） |
| `GET /v1/policies` | 列出已存版本与当前版本 |
| `POST /v1/policies/{version}/activate` | 切换当前策略版本 |
| `POST /v1/holds` | 挂保留期延长（body：`hold_id`/`resource_id`/`placed_by`/`reason`） |
| `POST /v1/holds/{hold_id}/release` | 解除保留期延长（body：`released_by`） |
| `GET /v1/holds/{hold_id}` | 查看延长记录（含是否仍有效） |
| `GET /v1/audit-export?cursor=&limit=` | 增量 / 分批导出审计（游标分页） |
| `GET /v1/forensics/{request_id}` | 导出该结论的取证文档（字节确定） |
| `POST /v1/forensics/verify` | 校验取证文档（body：`{"evidence": {...}}`） |

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

## 11. 本地验证

```bash
uv sync                                  # 安装依赖（含 pytest 开发依赖）
uv run pytest -v -s                      # 全量测试 + 打印判定 trace
uv run pytest -q                         # 安静模式（当前 44 个用例全部通过）
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

# 保留期延长：r-patient-old 已超期，挂延长后可读（脱敏照旧），解除后回到超期拒绝
curl -s -X POST localhost:8000/v1/holds -H 'content-type: application/json' \
  -d '{"hold_id":"h-1","resource_id":"r-patient-old","placed_by":"ops","reason":"legal case"}'
curl -s -X POST localhost:8000/v1/access/decide -H 'content-type: application/json' \
  -d '{"request_id":"q4","caller_id":"alice","resource_id":"r-patient-old"}'
curl -s -X POST localhost:8000/v1/holds/h-1/release -H 'content-type: application/json' \
  -d '{"released_by":"ops"}'

# 取证导出 + 校验；审计增量导出
curl -s localhost:8000/v1/forensics/q4
curl -s -X POST localhost:8000/v1/forensics/verify -H 'content-type: application/json' \
  -d "{\"evidence\": $(curl -s localhost:8000/v1/forensics/q4)}"
curl -s 'localhost:8000/v1/audit-export?limit=2'
```

## 12. 测试覆盖一览

- `tests/test_access_and_masking.py`：六类拒绝原因可区分、脱敏确定性与版本差异、
  原始值不出现在日志中（caplog 校验输入/版本/依据三要素）。
- `tests/test_concurrency_idempotency.py`：30 路并发序号连续无重复、同请求 10 路并发
  只产生一条审计、拒绝重试稳定、同 id 不同载荷 409、载荷指纹稳定性。
- `tests/test_policy_version_retention.py`：版本升级不改历史结论、超期拒绝不返内容、
  跨版本保留阈值差异、purge 擦除后可审计、版本不存在拒绝、策略冲突拒绝、版本不可变。
- `tests/test_masking_primitives.py`：mask/hash 纯函数确定性与回放顺序/内容稳定。
- `tests/test_retention_holds.py`：延长期间超期资源可读且脱敏照旧、解除后立即回到
  保留期处理、挂上/解除可审计可回放且依据可区分、重试与回放结论（含当时是否超期）
  完全一致、挂/解除幂等与冲突、延长不放大权限。
- `tests/test_forensics.py`：取证文档重复导出逐字节一致、三种处理方式（allow / deny /
  延长放行）校验一致、篡改与伪造一律 INCONSISTENT、malformed 输入不抛异常、
  导出与校验结论不含原始敏感值。
- `tests/test_audit_export.py`：分页全集有序无空洞、游标复用同页、断点续传、
  limit 边界与钳制、流式导出内存有界、并发写入下导出不漏不重、HTTP 端点与非法游标。
