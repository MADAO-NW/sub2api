# 提示词审计优化设计

## 文档状态

本文件记录“提示词审计优化”的最终实现语义，并替代本 change 中早期的 priority failover、Unicode 分片、宽松类别解析、仅保存脱敏预览、无邮件/无自动停用等旧设计。若本文件与早期 proposal、历史证据或注释冲突，以本文件、同目录 implementation-guide 和三份 delta spec 的当前内容为准。

## Context

sub2api 已有独立的 Content Moderation 能力。Prompt Audit 继续位于 backend/internal/securityaudit，不并入 ContentModerationService，也不改变既有 Moderations、关键词、Hash、邮件、封号或 content_moderation_logs 语义。

本轮优化解决以下问题：

- 审核模型只能按优先级故障切换，无法让多个模型共同裁决。
- 第三方模型缺少管理员可维护的完整业务政策。
- 分片、提前阻断和共享 deadline 会让不同模型看到不同文本。
- 宽松 parser 会接受协议之外的输出。
- Event 顶层字段无法解释每个模型的独立结果。
- store_pass_events=false 或 Event 被删除后，阈值计数缺少稳定事实源。

## Goals / Non-Goals

### Goals

- Qwen3Guard 与第三方 OpenAI-compatible 模型统一输出严格两行 Qwen 协议。
- 所有启用 endpoint 按配置数组顺序逐一执行：Qwen3Guard 接收现有完整 Prompt 一次，第三方模型按可信角色片段审核并在必要时联合审核。
- 支持完整 Outcome 复用，以及第三方 endpoint 内按角色、轮次和审核契约复用原始片段结果。
- 支持任一阻断、多数阻断、全体阻断三种确定性聚合。
- 保存每模型脱敏结果、独立成功分类流水、用户处置状态和动作 Outbox。
- 支持最近窗口邮件提醒、累计自动停用和单账号重新启用时计数重置。
- 在同步模式保持 fail-closed，并继续保证账号选择、计费和上游副作用为零。
- 管理台展示可编辑审核提示词、只读固定协议、聚合门槛、每模型指标和处置统计。

### Non-Goals

- 不审核模型输出，不改写或脱敏后转发用户请求。
- 不增加 tokenizer、tokenizer assets、模型 /tokenize 调用或固定字符分片。
- 不保存模型完整响应、reasoning content、审核模型 Token 或 Base URL。
- 不实现人工审批、申诉、批量账号恢复或 Event 详情中的计数重置入口。
- 不改变现有 ScanText、FullPrompt、PromptHash 和最新 user 前置语义；仅从同一协议提取结果额外保留角色、逻辑消息顺序和轮次范围。
- 不重构现有 Content Moderation 或网关协议 envelope。

## 1. 统一模型协议

### 1.1 Adapter

Endpoint 增加轻量 adapter：

- qwen3guard：原生 Qwen3Guard。
- openai_compatible_qwen：第三方 OpenAI-compatible 模型，但必须返回同一 Qwen 两行格式。

所有 endpoint 仍使用 Chat Completions。列表顺序是执行顺序，不代表权重；禁用模型跳过。

### 1.2 固定输出协议

后端只保留一个不可编辑常量，协议版本为 qwen-two-line-v2。固定输出增加发送前两行自检，并要求模型只返回：

- 第一行 Safety: Safe、Safety: Controversial 或 Safety: Unsafe。
- 第二行 Categories: None，或九个官方类别按固定顺序用逗号加空格连接。
- 第二行之后不得有解释、理由、JSON、Markdown 或第三行。

GET config 返回 prompt_contract.version 与 prompt_contract.fixed_output_prompt。PUT DTO 不含 prompt_contract，前端也不得复制或提交固定文本。

### 1.3 管理员审核提示词

audit_prompt 是管理员可编辑的完整业务政策，默认值由后端提供。存在启用的 openai_compatible_qwen 时不能为空。

第三方 system message 严格按以下顺序组成：

管理员审核提示词 + 两个换行 + 后端固定角色规则（或联合审核规则）+ 可选纠格式提示 + 后端固定输出协议

固定协议必须位于最后，之后不得追加动态文本。角色由网关根据请求结构确定，正文中的角色声明不能覆盖它；被审正文始终只放在普通 user message 中，不能取得审核模型的可信 system 权限。

第三方模型首次返回 HTTP 2xx 但 envelope、content 或两行协议无效时，允许在同一个 endpoint timeout 内执行一次纠格式重试。纠格式提示由后端固定模板和稳定错误码组成，放在 audit_prompt 与固定输出协议之间；固定协议仍是 system 最后一段。第二次成功按有效分类处理，第二次失败不再立即重试。

Qwen3Guard 请求继续只发送一条包含现有完整 Prompt 的 user message，并发送 seed=42，不增加角色 JSON 或角色提示。第三方每次片段/联合请求只发送一条 system 和一条 user，不发送 seed。两类请求都使用 temperature=0、stream=false，不发送 max_tokens、max_completion_tokens、thinking、reasoning_effort 或 response_format，由供应商和模型使用自身默认生成上限。

### 1.4 严格 parser

两类 adapter 共用一个 parser。只允许 CRLF 归一为 LF，并最多容忍一个末尾换行；其余空白不做宽松 trim。parser 必须拒绝：

- JSON、Markdown 围栏、标题、前后缀、解释或第三行。
- Safety 大小写、标签、顺序或值错误。
- Categories 未知、重复、错误大小写或错误分隔符。
- Safe 与非 None 组合。
- Controversial/Unsafe 与 None 组合。

输出错误记录稳定 detail code，并进入模型失败语义，绝不默认 Safe。

模型仍被要求按固定目录顺序输出，但类别在业务上是集合。parser 对名称、分隔符和唯一性校验通过后，必须在服务端按固定目录确定性排序；仅顺序不同不得触发 format_repair 或模型失败。

## 2. 配置与发布

setting key 仍为 prompt_audit_config，并继续使用版本 CAS、SecretEncryptor、内存快照和 Redis 失效通知。

配置核心字段：

- enabled、blocking_enabled、blocking_latest_turn_only、store_pass_events。
- strategy 固定为 ordered_all。
- aggregation_strategy 为 any_block、majority_block 或 all_block，默认 any_block。
- audit_prompt。
- worker_count、queue_capacity、scanners、all_groups、group_ids。
- notifications.admin_email。
- enforcement.email_warning：enabled、服务端维护的 rule_revision、lookback_count、violation_threshold。
- enforcement.account_disable：enabled、violation_threshold。
- endpoints[]：id、name、adapter、protocol、base_url、model、token_ciphertext、timeout_ms、enabled。
- config_version、updated_at、updated_by、change_summary。

不再存在 input_limit、全局 evaluation timeout、Token 上限、思考等级或返回 schema 配置。

保存校验：

- enabled=true 时至少一个模型启用。
- endpoint ID 唯一，adapter 和 protocol 必须受支持。
- 第三方启用时 audit_prompt 非空。
- aggregation_strategy 只允许三种固定值。
- timeout_ms 只约束该模型的一次调用，单位为毫秒；保留 100ms 最小值，不设置业务最大值，仅拒绝无法安全转换为 Go time.Duration 的技术无效值。
- 后端按请求数组原顺序保存，不按 ID、名称或 adapter 排序。
- 邮件提醒开启时 N>0、M>0 且 M<=N。
- 自动停用开启时 M>0。
- 任一处置规则开启时管理员邮箱必填且格式合法。
- Token 只写不回显。

邮件规则的开关、N 或 M 变化时，后端递增 rule_revision；其他配置变化不修改该修订号。

## 3. 文本、角色片段与顺序执行

PromptSnapshot 继续按既有规则生成 ScanText、FullPrompt 和 PromptHash：

- 提取所有已支持协议的客户端可控文本。
- 最新非空 user 前置，其余内容保持确定顺序。
- scanText、metadataText 和 SHA-256 基于同一完整字符串。
- 图片二进制、base64 和远程图片内容不进入审核文本。

在不改变上述整份快照语义的前提下，同一提取流程额外保留 source_role、逻辑消息原始顺序和 turn_scope，并把同一逻辑消息的多个文本块合并为一个 AuditSegment。system/developer 为 active；最后连续 user 轮次为 current，更早 user 为 historical；assistant/model/tool 根据其与最后 user 的位置标记 current 或 historical。`BlockingLatestTurnOnly` 保留且默认 false；显式为 true 时，同步审核只选择最后连续 user 与其之前最近连续 assistant/model，无 user 时回退完整范围，异步始终审核完整请求。

Event 的 full_prompt 可按既有 Event 快照上限保存；该存储上限不得影响模型输入。Qwen3Guard 对选定范围的完整、未分片、未静默截断 Prompt 审核一次。每个第三方 endpoint 按片段原顺序审核其未命中缓存的角色片段；所有片段均 Pass 时该 endpoint 直接 Pass，不执行联合审核。若直接影响当前任务的片段为 Critical，该 endpoint 直接 Critical；其余存在风险片段时，同一 endpoint 对直接影响片段与非 Pass 上下文执行一次联合审核。一个第三方 endpoint 无论包含多少片段，最终只形成一个模型级结果和一票。

一次 attempt 冻结：

- endpoint 数组及其顺序、adapter、model、timeout。
- audit_prompt hash 与固定协议版本。
- aggregation strategy、启用模型数和阻断门槛。
- config_version。

执行规则：

1. 依次遍历所有启用模型。
2. 每个模型创建独立 timeout context。
3. Block、已达到门槛、error 或 timeout 后仍继续后续模型。
4. Qwen endpoint 在一个 attempt 中只调用一次；第三方 endpoint 对每个唯一未命中片段最多调用一次，并在规则触发时最多追加一次联合审核。
5. 异步 Worker 在每次模型调用前刷新 Job 租约；claim_version 失效立即停止。
6. 只有任务取消、Shutdown 或租约失效可以中断剩余模型。

## 4. 聚合与失败语义

设 N 为冻结的启用模型数，B 为有效 Critical+Block 数，E 为 error/timeout 数。

阻断门槛：

| 策略 | 门槛 |
| --- | --- |
| any_block | 1 |
| majority_block | floor(N/2)+1 |
| all_block | N |

error/timeout 不从 N 中剔除，也不降低门槛。

确定性聚合：

1. B 达到门槛：最终 Critical/Block；若 E>0，同时标记 partial_failure。
2. E=N：没有成功分类，进入现有 retry/failed。
3. B 未达门槛且 E>0：最终 Flag/Warn，partial_failure=true。
4. E=0 且存在未达门槛的 Block 或任何 Warn：最终 Flag/Warn。
5. 全部 Allow：最终 Pass/Allow。

异步模式保存上述结果。同步 blocking 模式中，达到门槛仍返回 Block；未达门槛且 E>0 时返回 unavailable/invalid 并保持 fail-closed。同步结果必须先按独立记录路径落事实，再向网关返回；记录失败不反转已确定门禁结果。

全局与每节点 bulkhead 继续限制并发，但不再使用首节点共享 deadline、节点 failover、分片早停或 failover 指标作为执行机制。

## 5. Timeout、租约与 Payload TTL

每个模型只使用自己的 timeout_ms。前一模型耗尽 timeout 不消耗后一模型的额度。异步 Worker 在模型调用前刷新租约，并在调用期间每 30 秒持续刷新；任一次刷新失败都取消当前模型调用，旧 Worker 不得继续提交结果。processing 超过 90 秒未刷新时才允许回收，因此任意合法长 timeout 都不得触发误回收。

异步任务的 payload TTL 按冻结 attempt 预算动态计算，至少覆盖：

- 所有启用模型 timeout 之和。
- 最大尝试次数和现有退避。
- Worker 调度与安全余量。

TTL 短于既有 30 分钟默认值时仍使用 30 分钟；不得设置会让按当前模型数量和 timeout 推导出的最大重试周期提前过期的硬上限。它只保护短期扫描载荷，不改变 PostgreSQL Job/Outcome 的事实状态。

timeout、所有启用模型之和、最大尝试次数、退避和安全余量的换算必须检查整数溢出。这里的可表示范围是运行时技术边界，不得恢复固定 30 秒或其他业务上限。

## 6. 数据模型与隐私边界

181_prompt_audit.sql 和 182_prompt_audit_full_prompt.sql 是 checksum 不可变的历史迁移；full_prompt 继续由 182 提供。224_prompt_audit_enforcement.sql 一次性增加多模型结果、成功分类流水、处置状态、动作 Outbox 和失败模型调用诊断表，不回填历史数据。229_prompt_audit_result_reuse.sql 为 Outcome 增加历史复用与评估契约字段，并新增第三方片段原始结果表、Outcome 片段使用关系表及索引。

### 6.1 Job 与 Event

prompt_audit_jobs 保存任务状态、脱敏快照和 claim_version，不保存扫描正文。

prompt_audit_events 保存可选管理员复核事件，包括 full_prompt 和 model_results：

- aggregation：strategy、enabled_model_count、block_threshold、config_version、prompt_contract_version、audit_prompt_hash、partial_failure、评估输入/角色契约 Hash、完整/片段/联合调用数、片段命中数，以及完整历史命中时的 reused_from_outcome_id。
- models[]：sequence、endpoint_id、adapter、model、input_mode、片段数/命中数/联合审核、Safety、Categories、平台 decision/action、latency、可选 usage、稳定 error_code。

model_results 不保存模型完整响应、reasoning content、Token、Base URL 或管理员审核提示词。

### 6.2 失败模型调用诊断

prompt_audit_model_attempts 保存所有失败模型调用的节点、模型、调用序号、HTTP 状态、错误码、usage、延迟和受限响应体。它不得保存请求头、Authorization 或 API Key，不进入日志、API 或前端。响应正文上限 256 KiB，30 天后由后台任务清空，hash、大小、截断标记和其他元数据随 Job 保留。异步状态变更与诊断同事务写入；阻断模式全部失败时创建 failed Job，但不创建 Event 或 Outcome。

### 6.3 成功分类流水

每个成功分类 Job 恰好写一条 prompt_audit_outcomes，以 job_id 唯一。它是邮件窗口和累计停用的唯一计数事实源。

Outcome 只保存轻量分类事实和冻结聚合元数据，不保存 Prompt、预览、审核提示词、凭据或模型完整响应。store_pass_events=false 时 Pass 没有 Event，但仍必须有 Outcome；全部模型失败时不得写 Outcome。Event/Job 删除不影响 Outcome。若审核完成前用户已物理删除，Job/Event/Outcome 的 user_id 置空并保留身份快照与 Outcome，不创建 State 或 Action。

提取 Prompt 后，blocking 与 async 共用全站 Outcome 历史查询。只有 prompt_hash、evaluation_input_hash、evaluation_contract_version、role_contract_hash、config_version、audit_prompt_hash、prompt_contract_version、aggregation_strategy、enabled_model_count 和 block_threshold 全部匹配，且原 Outcome 是非 partial_failure 的 pass/flag/critical 完整结果时才允许复用。复用跳过本次全部审核模型调用；当前请求仍创建新的 Job、Outcome 和可选 Event，并按当前用户执行邮件、累计停用和鉴权缓存失效。新 Outcome 的 reused_from_outcome_id 直接指向原始模型评估 Outcome，历史复用结果本身不得再次作为来源，避免形成复用链。

历史查询失败时按缓存未命中处理并回退到正常模型评估，不得改变 blocking 的 fail-closed 语义。配置版本、审核提示词、固定协议、聚合策略、启用模型数或门槛变化都会使历史结果失效。

完整 Outcome 未命中时，仅 openai_compatible_qwen 使用片段历史。系统必须先按 endpoint 批量查询全部唯一片段键；键包含正文 Hash、policy role、turn scope、endpoint/adapter、config version、审核提示词 Hash、角色提示词 Hash、评估契约版本和固定协议版本。命中只跳过该 endpoint 的该片段调用，不跨 endpoint 共享；Qwen 不查写片段缓存。联合审核结果不进入片段结果表。当前 Outcome 仅为直接影响结论、非 Pass 上下文或参与联合审核的片段记录使用关系，并始终直接指向原始片段结果，禁止复用链。

违规的唯一定义是 decision=critical 且 action=Block。

### 6.4 State 与 Action Outbox

prompt_audit_enforcement_states 每用户一行，用行锁串行更新：

- email_rule_revision、email_window_start_outcome_id、email_rule_armed、email_last_action_id。
- disable_violation_count、disable_reset_outcome_id、disable_last_action_id。

prompt_audit_enforcement_actions 保存 email_warning、account_disabled、counter_reset 动作及管理员/用户两个收件人的独立投递状态。动作与分类/用户状态同事务提交；邮件在提交后异步投递。

State、Action 和邮件均不得复制 Prompt、预览、audit_prompt、固定协议全文、Token、Base URL 或模型完整响应。

## 7. 阈值处置

### 7.1 普通邮件提醒

只在 email_warning 开启期间对新 Outcome 求值。新 rule_revision 从每个用户下一条 Outcome 建立窗口边界。

按 request_created_at DESC、id DESC 读取该边界后的最近 N 条成功分类；不足 N 条按已有数量。违规数从小于 M 越过到大于等于 M 时创建一次 email_warning；持续在阈值上方不重复，跌回阈值下方后重新布防。

普通提醒只要求管理员收件人。

### 7.2 自动停用

开关启用期间，本次 Outcome 为违规且用户 role=user 时，在 State 行锁内累计。关闭开关暂停累计，重新开启从原累计继续，关闭期间不补记。

累计达到 M 时只条件更新 status=active 的普通用户为 disabled。admin 永不累计、永不停用；已 disabled 用户不重复停用或发停用邮件。降低阈值不批量扫描，在下一条新违规时判断。

停用成功后创建唯一 account_disabled Action，并分别通知管理员邮箱和用户邮箱，不受普通邮件提醒开关影响。用户邮箱依次取 Outcome 快照和当前用户邮箱；仍为空则只跳过用户收件人，并记录稳定 user_email_missing 原因码。

同一 Outcome 同时达到邮件与停用阈值时，只创建 account_disabled，并把邮件窗口设为未布防。

### 7.3 单账号重新启用

现有 PUT /api/v1/admin/users/:id 是唯一恢复入口。普通用户 disabled→active 时：

1. 在同一业务事务中先锁 Prompt Audit State。
2. 清零 disable_violation_count，并把 disable_reset_outcome_id 更新为该用户最新 Outcome ID。
3. 写唯一 counter_reset Action。
4. 再更新 users.status 并提交。
5. 提交后失效该用户鉴权缓存。

该操作不清空邮件窗口，不删除历史 Event、Outcome 或 Action。重复 active 请求不得重复重置。前端只显示统一成功提示，不补发第二个请求。

## 8. 邮件 Outbox

通知 Worker 从 Action 表使用 FOR UPDATE SKIP LOCKED 领取到期动作。管理员和用户状态分别为 not_required、pending、sent 或 failed；一个收件人成功后不得因另一个失败而重发。

邮件使用独立 Prompt Audit 事务通知事件和模板，文案描述被审核用户及分类事实，不复用会把管理员误写成违规请求人的 Content Moderation 用户模板。

邮件失败只更新对应收件人状态、attempts、next_attempt_at 和稳定的 admin_email_delivery_failed 或 user_email_delivery_failed 错误码，不回滚 Outcome、Event、计数或账号停用，也不重新调用模型。

邮件内容可以包含 Action/Outcome/Event ID、时间、用户基本信息、最终分类、类别、窗口/累计值、阈值、账号状态和后台链接，但不得包含任何 Prompt 内容或模型原始响应。

## 9. 管理 API 与控制台

继续复用 /admin/prompt-audit 的 config、probe、runtime、events 和删除 API；用户恢复继续复用 PUT /api/v1/admin/users/:id。

配置页顺序：

1. 运行概览。
2. 已添加审核模型。
3. 第三方模型审核提示词与只读固定返回协议。
4. 审计范围、九类分类和三种聚合策略。
5. 阈值处置与通知。
6. 审核事件。

Endpoint 支持新增、编辑、删除、启停、探测、上移和下移。上移/下移只重排数组。

Probe：

- Qwen3Guard 使用固定无害 user 文本并验证严格两行输出。
- 第三方使用当前草稿 audit_prompt + 固定协议作为 system，并使用固定无害 user 文本。
- 连接成功但格式错误时保留实际 HTTP status，并返回稳定“输出协议无效”错误。

运行态增加每模型顺序/开关/probe、请求和分类数、错误、usage、P50/P95；整条顺序审核 P50/P95、partial failure；聚合策略、模型快照数、门槛、协议版本、audit prompt hash；Outcome、违规、提醒、停用和邮件失败统计。

Event 详情展示每模型 Safety、Categories、decision/action、latency、usage、error_code、输入模式、片段命中和联合审核摘要，并展示必要的第三方片段结果及历史来源；不展示模型完整响应。历史完整复用事件显示来源 Outcome ID，并说明本次未调用审核模型。full_prompt 仅供管理员敏感复核。

## 10. 网关与协议错误

Prompt Audit 的 off/async/blocking 三态、Coordinator 优先级和现有 HTTP/SSE/WS envelope 保持不变。

同步模式必须在账号选择、并发 slot、预扣、计费、上游连接/写入和 SSE 首字节之前完成。Prompt Block 返回 403 prompt_guard_blocked；未达门槛的 partial failure 或全部失败按错误类型返回 503 prompt_guard_unavailable / prompt_guard_invalid_response。

Responses WebSocket 首轮和后续每个 response.create 都独立检查，Block 使用 4403，Unavailable/Invalid 使用 1013。

## 11. 可观测性

日志只允许稳定 ID、配置/聚合数值、decision/action、latency、结果来源、历史 Outcome ID、状态和稳定错误码。input_limit、分片正文、Prompt、audit_prompt、固定协议全文、Token、Authorization、完整 Base URL/query 和模型完整返回禁止进入日志。

运行指标同时保留网关 Guard 总体指标，并新增：

- 每 endpoint 请求、Pass/Flag/Critical/error、输入/输出/reasoning token、P50/P95。
- 整条 evaluation total、partial_failure、P50/P95。
- Outcome、违规、提醒、停用和邮件失败累计。

## 12. 上线与回滚

上线顺序：

1. 默认保持 Prompt Audit、普通提醒和自动停用关闭。
2. 先在测试分组开启 async，比较 Qwen 与第三方模型的分类漂移、延迟和 partial failure。
3. 选择聚合策略并观察邮件阈值。
4. 再开启普通提醒，核对窗口边沿语义。
5. 经人工复核后才启用自动停用和 blocking。

回滚优先关闭 blocking，再关闭自动停用和普通提醒，最后关闭 Prompt Audit。回滚不删除表、历史 Outcome、Event 或 Action；暂停邮件 dispatcher 时保留未完成 Outbox。
