# 提示词审计优化实施指导

## 1. 权威边界

本指南与当前 design.md、三份 delta spec 共同描述最终实现。以下旧语义已废弃：priority failover、input_limit、Unicode 分片、首节点共享 deadline、Block 早停、未知类别宽松接受、仅保存脱敏预览、Prompt Audit 不发邮件/不自动停用。

实施必须保持：

- Prompt Audit 继续是 backend/internal/securityaudit 下的独立垂直模块，默认关闭。
- 现有 Content Moderation 的 API、数据、邮件、Hash 和封号语义不变。
- 网关 off/async/blocking 三态、协议错误 envelope 和无下游副作用门禁不变。
- PromptSnapshot 提取逻辑不做功能改造；模型输入使用完整 scanText。
- Guard Token 只存在于写 DTO、短生命周期解密内存和 Authorization header。
- 完整 Prompt 只可存在于请求/Redis 临时载荷和管理员可访问的 Event full_prompt；Outcome、State、Action、邮件和普通日志禁止复制。
- 不安装新 Go、前端或模型运行时依赖。

## 2. 目标依赖方向

- 协议 Handler → SecurityAudit Coordinator → 现有 Content Moderation 端口与 PromptService。
- PromptService → ConfigManager、JobRepository、PayloadStore、Scanner、Metrics、Notification Worker。
- PostgreSQL → Job、Event、Outcome、Enforcement State、Enforcement Action。
- Redis → 临时完整扫描载荷与配置失效通知。
- Admin API → PromptAdminHandler；用户恢复仍走现有 UserHandler/adminService.UpdateUser。
- Vue 页面只依赖 Public DTO，不读取 Storage DTO、token_ciphertext、Redis key 或原始模型响应。

构造函数不启动 goroutine。Prompt Runner、回收器、配置订阅和通知 Worker 均由 PromptService.Start 启动，并由 Shutdown/Wait 有界收口。

## 3. 主要文件职责

后端核心：

- prompt_contract.go：默认管理员审核提示词、固定输出协议和协议版本。
- prompt_config.go / prompt_config_store.go：Storage/Active/Public/Update DTO、校验、CAS、加密、顺序保留和规则修订。
- prompt_qwen3guard.go：两类 adapter 的请求构造、OpenAI 响应 envelope、usage 和统一严格 parser。
- prompt_model_runner.go：ordered-all、独立 timeout、聚合门槛和每模型明细。
- prompt_guard.go：同步 fail-closed、bulkhead、结果记录与鉴权缓存失效。
- prompt_worker.go：异步 claim、每模型前租约刷新、重试与动态 Payload TTL。
- prompt_repository.go / prompt_event_repository.go：Job/Event/Outcome 完成事务和查询删除。
- prompt_enforcement_repository.go：Outcome、State 行锁、邮件窗口、累计停用和单账号重置。
- prompt_notification_worker.go：Action Outbox 分收件人投递。
- prompt_metrics.go / prompt_runtime.go：总体、每模型、整条审核和处置统计。

数据库：

- backend/migrations/181_prompt_audit.sql 和 182_prompt_audit_full_prompt.sql 保持历史内容与 checksum 不变。
- full_prompt 继续由 182 提供。
- 新增 224_prompt_audit_enforcement.sql，一次性增加 model_results、Outcome、State、Action、失败调用诊断及相关索引；不回填历史分类结果或处置计数。

前端：

- EndpointPool.vue：adapter、顺序、timeout、凭据、探测、上移/下移。
- AuditPromptPanel.vue：audit_prompt 编辑与后端 prompt_contract 只读展示。
- PolicyPanel.vue：范围、九类 scanner、三种聚合与实时门槛。
- EnforcementPanel.vue：管理员邮箱、普通提醒 N/M、累计停用 M。
- RuntimeOverview.vue：每模型、整条 evaluation、聚合和处置统计。
- EventDetailDialog.vue：每模型脱敏结构化结果。
- UsersView.vue：复用单账号启用动作，只补充统一成功提示。

## 4. 实施顺序

### 4.1 统一协议与配置

1. 固定 PromptContractVersion 和 FixedOutputPrompt。
2. 给 endpoint storage/active/public/update 增加 adapter，移除 input_limit。
3. 增加 audit_prompt、aggregation_strategy、notifications 和 enforcement。
4. GET 返回 prompt_contract；PUT 类型物理上不包含该字段。
5. 校验第三方审核提示词、三种聚合、邮件 N/M、停用阈值和管理员邮箱。
6. 保存与 clone 严格保留 endpoint 数组顺序。
7. 修改邮件规则开关/N/M 时由后端递增 rule_revision。

### 4.2 Scanner 与 ordered-all

1. Qwen 请求：一条 user、seed=42。
2. 第三方请求：一条 system、一条 user；system 为 audit_prompt + 两个换行 + FixedOutputPrompt。
3. 两类请求统一 temperature=0、stream=false，不发送 max_tokens 或 max_completion_tokens。
4. 禁止 thinking、reasoning_effort、response_format 和动态 schema，由供应商和模型使用自身默认生成上限。
5. 同一 parser 严格验证两行输出、官方类别名称/唯一性/分隔符和 Safety/Categories 配对；合法类别集合由服务端按固定目录确定性排序，乱序不得触发 format_repair。
6. 所有启用模型按数组顺序执行；每个模型创建自己的 timeout context。timeout_ms 保留 100ms 最小值、不设置业务最大值，所有 time.Duration 和 Payload TTL 运算必须检查溢出。
7. 无论前序 Block、达到门槛或失败，都继续后续模型。
8. 模型输入只把内部优先级分隔符还原为两个换行，不分片、不截断。
9. 冻结 prompt hash、协议版本、模型数、门槛、config version 和 timeout。
10. 保存每模型 Safety、Categories、decision/action、latency、usage 和 error_code。
11. async Worker 在每个模型调用前刷新租约，并在长调用期间每 30 秒刷新；刷新失败立即取消调用并依赖 claim_version/reclaimer 安全接管。

### 4.3 聚合与同步门禁

门槛：

- any_block：1。
- majority_block：floor(N/2)+1。
- all_block：N。

error/timeout 不缩小 N。达到门槛即 Block；全部失败进入 retry/failed；未达门槛但部分失败为 Warn + partial_failure；无失败时未达门槛的 Block 或 Warn 聚合为 Warn，其余 Allow。

同步 blocking 的 partial failure 未达到门槛时必须返回 unavailable/invalid，不能按 Warn 放行。达到门槛时即使有部分失败仍 Block。

同步结果先调用 RecordBlocking 写 Job、可选 Event、必需 Outcome、State/Action，再返回网关决策。记录失败只增加稳定指标/日志，不再次扫描，也不反转门禁判定。

### 4.4 异步事务与重试

1. Enqueue 继续使用 staging → Redis SET → queued。
2. Payload TTL 按模型 timeout 总和、attempts、退避和安全余量计算；短任务沿用既有 30 分钟下限，不设置会让最大重试周期提前过期的硬上限。
3. Worker claim 后冻结本 attempt 配置。
4. 每个模型调用前用 id + processing + claim_version 刷新租约。
5. 第三方模型 HTTP 2xx 但 envelope、content 或两行协议无效时，在同一 timeout 内最多纠格式重试一次；固定输出协议仍位于 system 最后。
6. 每次失败调用进入内部诊断集合；继续执行后续模型。
7. 只有全部模型失败时才使用 Job retry/failed。
8. 完成、重试或失败事务同时写入失败调用诊断；完成事务再写可选 Event、唯一 Outcome、State 和 Action。
9. 提交后删除 Payload；失败依赖 TTL。
10. 自动停用提交后失效该用户鉴权缓存。

## 5. 严格协议检查表

parser 必须接受：

- 三种精确 Safety。
- Safe + None。
- 官方单类别。
- 多类别按官方固定顺序，以“, ”连接；相同合法类别乱序时规范化为固定顺序。
- CRLF。
- 最多一个末尾换行。

parser 必须拒绝：

- JSON、Markdown、解释、理由、前后缀和第三行。
- 未知、重复、错误大小写和错误分隔符类别。
- Safety 标签/值/顺序错误。
- Safe + 非 None。
- Controversial/Unsafe + None。
- 多余空白或两个末尾换行。

invalid response 进入稳定 GuardError detail code；不得宽松抽取子串或回退为 Safe。

## 6. 数据与处置事务

### 6.1 成功分类流水

每个成功分类 Job 以 job_id 唯一写一条 Outcome。store_pass_events=false 只影响 Event，不影响 Outcome。全部模型失败不写 Outcome。

Outcome 的 is_violation 只允许等于 decision=critical AND action=Block，并由数据库 CHECK 约束。

Job/Event/Outcome 写用户外键时使用“存在则关联、已物理删除则 NULL”。用户已删除时仍提交身份快照和 Outcome，但跳过 State/Action。

### 6.2 邮件窗口

- 仅在规则开启期间的新 Outcome 求值。
- rule_revision 变化时，每用户在下一条 Outcome 设置新边界并重新布防。
- 从边界后的最近 N 条 Outcome 按 request_created_at DESC、id DESC 取样。
- <M → >=M 创建一次 email_warning；持续 >=M 不重复；跌回 <M 重新布防。

### 6.3 累计停用

- 只在开关开启、本次违规、role=user 时增加 disable_violation_count。
- admin 不累计；disabled 用户不重复条件更新或发停用邮件。
- 达到 M 时条件更新 users.status=disabled，并写 account_disabled Action。
- 同一 Outcome 同时触发两条规则时，只创建停用动作并把邮件窗口设为未布防。
- Action 与 Outcome/State/users 在同一数据库事务中提交。

### 6.4 单账号启用重置

adminService.UpdateUser 检测普通用户 disabled→active 后开启 Ent 事务：

1. PromptAuditCounterResetter 先创建/锁 State。
2. 读取该用户最新 Outcome ID。
3. 清零停用累计、更新 reset outcome、写 counter_reset。
4. userRepository 复用当前事务更新 users。
5. 提交后执行既有鉴权缓存失效。

不得清空邮件窗口或删除历史。active→active、admin 或其他字段更新不得触发重置。

### 6.5 邮件 Outbox

Action 的管理员/用户收件人各自维护状态与 attempts。通知 Worker 只领取 pending/failed 收件人；已 sent 或 not_required 的收件人不得重发。

使用 Prompt Audit 专用事务通知事件和无原文模板。投递失败按收件人记录稳定 admin_email_delivery_failed 或 user_email_delivery_failed 并设置下一次时间；用户邮箱缺失记录 user_email_missing。失败不回滚账号停用，不重跑模型。

## 7. API 与前端实施

### 7.1 Config/Probe

Update DTO 新增 audit_prompt、aggregation_strategy、notifications、enforcement 和 endpoints[].adapter；不接受 prompt_contract。

Probe 必须使用固定无害 user 文本。第三方 Probe 使用当前草稿 audit_prompt，且必须验证严格两行协议。连接成功、HTTP 2xx 但 parser 失败时保留 HTTP status，并返回稳定协议错误。

管理员操作审计只记录开关、数量、聚合策略、阈值和“是否已配置”布尔值；不得记录 audit_prompt、管理员邮箱原文、Token 或完整 Base URL。

### 7.2 页面顺序

运行概览 → 已添加审核模型 → 第三方审核提示词 → 审计策略 → 阈值处置与通知 → 审核事件。

prompt_contract 使用 pre/code 只读展示，不能使用 textarea/contenteditable。buildUpdateRequest 和 dirty fingerprint 不含 prompt_contract。

PolicyPanel 根据启用模型数实时计算门槛。EndpointPool 只通过上移/下移重排数组，不增加拖拽依赖。

UsersView 不增加新入口或第二次 API 请求。

### 7.3 运行态和详情

Runtime 必须展示：

- 每模型顺序、启用状态、adapter/model/timeout 和最近 probe。
- 每模型请求、Pass/Flag/Critical/error、usage、P50/P95。
- 整条审核 total、partial_failure、P50/P95。
- 聚合策略、模型快照数、门槛、协议版本和 audit_prompt hash。
- Outcome、违规、提醒、停用、邮件失败累计。

Event 详情展示每模型脱敏结构化结果，不展示完整模型响应或 reasoning content。

## 8. 测试与验证

后端单元测试至少覆盖：

- 严格 parser 的正反例。
- Qwen/第三方请求消息、字段禁用、固定协议顺序和 usage。
- 1/2/3/4 模型三种门槛。
- endpoint 顺序、disabled 跳过、Block/error 后继续。
- 完整长文本不分片、不截断。
- 独立 timeout 和 error 不缩小分母。
- 每模型明细与 partial failure。
- Outcome 唯一、Pass 无 Event 仍有 Outcome、全部失败无 Outcome。
- 邮件边沿、跌回重布防、停用累计、admin/disabled、防重复动作。
- 单账号事务重置不影响邮件窗口和历史。
- 分收件人重试与邮件失败不回滚。

集成测试至少覆盖按 181→182→224 顺序执行迁移、完成事务、并发 State 行锁、删除 Event/Job 后 Outcome 保留、重启后 Outbox 续投。

前端测试至少覆盖 endpoint 排序、adapter、只读固定协议、dirty/save 排除、三种聚合门槛、处置开关、Probe 草稿、运行态和每模型详情、用户启用提示。

执行项目既有 go test、unit tag、API contract、OpenSpec validate；前端依赖未安装时不得自动安装，记录 typecheck/Vitest 未执行原因并等待明确依赖安装授权。

## 9. Definition of Done

- 配置、存储、运行态和执行顺序一致。
- Qwen 与第三方共用严格两行 parser。
- 模型输入不分片、不截断；所有启用模型均执行。
- 三种门槛、同步/异步 partial failure 语义正确。
- Event 有每模型明细，Outcome/State/Action/邮件不含敏感正文。
- 邮件窗口、自动停用、用户启用重置和鉴权失效闭环完整。
- 配置页、运行态、事件详情和用户成功提示同步。
- 相关后端测试通过；前端与数据库未执行项有明确原因。
- 最终 git diff 不包含无关重构、凭据、生成缓存或依赖安装产物。
