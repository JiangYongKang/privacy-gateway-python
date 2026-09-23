# privacy-gateway（本地版）

一套**敏感数据访问与脱敏控制**的参考实现：在纯本地、纯内存、无任何外部服务与
真实凭据的前提下，模拟“调用方身份 / 资源范围 / 策略版本 / 审计记录”，
使得同一次访问在任意时间、任意并发下都得到**一致、可解释、可复现**的结论。

技术栈：Python 3.14 + FastAPI（仅用仓库已声明依赖，测试用 pytest）。

---

## 1. 模块结构

| 文件 | 职责 |
| --- | --- |
| `privacy_gateway/models.py` | 领域模型与枚举（主体、资源、规则、策略版本、请求、结论、审计条目） |
| `privacy_gateway/policy.py` | 策略版本仓库：不可变发布、**发布期冲突校验**、规则匹配 |
| `privacy_gateway/masking.py` | 四种确定性脱敏原语与结论指纹（HMAC-SHA256，本地固定盐） |
| `privacy_gateway/retention.py` | 保留期到期判定（`now >= created_at + retention_days`） |
| `privacy_gateway/service.py` | 主门面：判定 → 脱敏 → 审计，全流程加锁串行化 + 幂等缓存 |
| `privacy_gateway/audit.py` | 审计幂等写入、连续序号、结论指纹与历史回放比对 |
| `privacy_gateway/store.py` | 本地内存存储（调用方、资源） |
| `privacy_gateway/clock.py` | 可注入时钟（`SystemClock` / `FixedClock`），时间戳确定 |
| `privacy_gateway/logging_utils.py` | 安全日志：只打输入/版本/规则/原因/字段名，值自动净化 |
| `privacy_gateway/seed.py` | 确定性种子数据与两个策略版本（v1/v2） |
| `privacy_gateway/api.py` / `main.py` | FastAPI HTTP 层与装配入口 |

## 2. 策略模型

- **规则（Rule）**：`(principal_id, scope, effect, allowed_fields, field_rules)`
  - `principal_id` 与 `scope` 支持精确值或通配符 `"*"`；
  - `effect ∈ {allow, deny}`，显式 `deny` 与“无规则命中”是两回事；
  - `allowed_fields` 是该规则可读字段的白名单，`field_rules` 为每个字段
    指定脱敏方式；`field_rules` 的键必须在白名单内，否则发布拒绝。
- **策略版本（PolicyVersion）**：版本号 `version` + 一组规则 + 创建时间 +
  父版本 + 该版本的保留期动作。
  - 版本一经发布**不可变**，重复发布同版本号按冲突拒绝；
  - 同一版本内两条规则若在“主体 × 范围”上存在交集 → **发布期冲突拒绝**
    （`POLICY_CONFLICT`），杜绝运行期“命中哪条”的二义性；
  - “当前版本”通过 `set_current()` 显式切换；没有任何当前版本时，
    所有请求以 `POLICY_MISSING` 拒绝；请求也可用 `policy_version`
    显式锁定版本，版本不存在以 `POLICY_VERSION_NOT_FOUND` 拒绝。
- **缺省拒绝（fail-closed）**：未命中任何规则一律 `POLICY_DEFAULT_DENY`，
  任何冲突、缺省、版本缺失都不会默认放行。

种子内置两版策略（见 `seed.py`）：

- `v1`：alice 可读 `patient`（phone 部分遮蔽、diagnosis 全遮蔽），
  bob 可读 `billing`（amount 明文为策略显式授予），carol 对 patient 显式 deny；
  保留期动作 `DENY`。
- `v2`：alice 的 phone 升级为 HMAC 假名；新增 carol 对 diagnosis 的
  全遮蔽只读；保留期动作改为 `REDACT`。

### 判定顺序（拒绝原因彼此可区分）

1. 策略版本解析（显式版本须存在，否则取当前版本）；
2. 主体、资源必须存在；
3. 规则匹配：无命中 → `policy_default_deny`；命中 `deny` → `unauthorized`；
4. 字段越权：任一请求字段不在白名单（或资源中不存在）→
   `field_forbidden`，且 `deny_detail` 列出全部越权字段名，整单拒绝；
5. 保留期检查（见第 4 节）；
6. 逐字段脱敏后返回，响应中**只有被请求且被授权的字段**。

## 3. 脱敏规则

全部为输入的纯函数（同值同模式 ⇒ 同结果），实现在 `masking.py`：

| 模式 | 输出（以 `13800138000` 为例） | 用途 |
| --- | --- | --- |
| `none` | `13800138000` | 仅策略显式授予的非敏感字段（如金额） |
| `full` | `<REDACTED>` | 完全遮蔽 |
| `partial` | `1*********0` | 保留首尾结构；长度 ≤2 全 `*` |
| `hash` | `hmac:2dcf4ffaf87b18e1` | 固定本地盐 HMAC-SHA256 前 16 位，可比较不可逆 |

未在 `field_rules` 中配置的授权字段默认按 `full` 遮蔽（宁紧勿松）。

**不泄漏原则**：响应里被拒绝字段一律不出现；拒绝结论的 `fields` 恒为 `{}`；
异常只携带原因枚举；审计不存任何字段值；日志中的字段值会被净化为
`<value:len=N>`。单测对全部日志做过原始值扫描，敏感样例值出现次数为 0。

## 4. 审计与保留语义

### 审计（`audit.py` + `service.py`）

- **幂等**：以 `request_id` 为幂等键。重复提交/并发重试只产生一条记录，
  并直接返回首次的完整（脱敏后）结论；
- **确定性顺序**：判定与写入在同一把可重入锁内完成，审计 `seq` 连续递增，
  时间戳来自可注入时钟。并发下“先拿到锁的请求 seq 最小”，与线程调度无关；
- **只记录结论的形状**：主体/资源 ID、请求字段名、策略版本、命中规则标签、
  允许与否、原因枚举、返回字段名，以及对**脱敏后结论**的 SHA-256 指纹；
- **回放**：`replay(request_id)` 使用历史条目锁定的策略版本重新评估，
  再逐字节比对指纹、原因、版本、规则标签与拒绝详情，输出 `consistent`。
  即使当前策略已升级，历史决策仍必须与当时一致（见
  `test_policy_update_does_not_change_replayed_history`）。

### 保留期（`retention.py` + 策略版本的 `retention_action`）

到期条件：`now >= resource.created_at + retention_days`（边界含等号）。
到期后的行为由**当时锁定的策略版本**决定，三种动作都不会静默返回完整内容：

- `deny`：以 `retention_expired` 拒绝（v1 默认）；
- `purge`：先把存储中的字段落地为 `<REDACTED>` 再拒绝；
- `redact`：允许访问，但所有字段强制全遮蔽（v2 行为）。

## 5. HTTP 接口

| 方法/路径 | 说明 |
| --- | --- |
| `POST /v1/access` | 提交访问（按 `request_id` 幂等） |
| `GET  /v1/audit/{id}` | 查询单条审计（无值，仅字段名与指纹） |
| `GET  /v1/audit` | 按 seq 升序列出审计 |
| `POST /v1/replay/{id}` | 回放并返回一致性比对 |
| `GET  /v1/policies` | 当前版本与全部版本 |
| `PUT  /v1/policies/current` | 切换当前版本（不存在 → 404） |

业务拒绝统一返回 `200 + {"allowed": false, "reason": ...}`，
`reason` 取自可区分的原因枚举：`unauthorized` / `field_forbidden` /
`policy_default_deny` / `policy_missing` / `policy_version_not_found` /
`policy_conflict` / `retention_expired`。

## 6. 本地验证方法

```bash
# 依赖同步（pytest 已配置为 dev 依赖）
uv sync

# 运行全部单测（28 个）：越权访问、并发、重复提交、回放分歧、保留期、HTTP
uv run pytest -q

# 想在单测日志中查看每条判定的输入 / 命中策略版本 / 判定依据：
uv run pytest -o log_cli=true -o log_cli_level=INFO

# 启动本地服务（无外部依赖）
uv run uvicorn main:app --reload
```

手动调用示例：

```bash
curl -s -X POST localhost:8000/v1/access -H 'content-type: application/json' -d '{
  "request_id": "demo-1",
  "principal_id": "alice",
  "resource_id": "patient-1",
  "fields": ["name", "phone"]
}'
# => phone 被部分脱敏；重试同一 request_id 返回完全相同的结论且审计不增加
```

## 7. 设计约束小结

- 仅依赖 `fastapi[standard]` 与测试用 `pytest`，无网络/数据库/真实凭据；
- 全部时钟可注入（`FixedClock`），输出可复现；
- 并发通过单锁串行化保证确定；指纹与 HMAC 均为确定性算法；
- 任何路径（响应、异常、日志、审计）都不出现原始敏感值。
