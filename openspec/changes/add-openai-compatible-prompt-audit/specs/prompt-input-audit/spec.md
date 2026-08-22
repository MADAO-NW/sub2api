## ADDED Requirements

### Requirement: 提示词审计必须保持独立且默认关闭
系统 SHALL 在现有 Content Moderation 之外运行独立 Prompt Audit，引擎 MUST 使用独立配置、任务、事件、成功分类流水、处置状态和动作表，并 MUST 默认关闭。现有 Moderations、关键词、Hash、邮件、封号和 content_moderation_logs 语义 MUST NOT 改变。

#### Scenario: 升级后未启用
- **WHEN** 管理员尚未启用 Prompt Audit
- **THEN** 系统 MUST NOT 创建 Prompt Audit Job、Outcome、Event 或调用审核模型
- **THEN** 原网关和 Content Moderation 行为 MUST 保持不变

#### Scenario: 两个引擎同时启用
- **WHEN** Content Moderation 与 Prompt Audit 同时运行
- **THEN** 两者 MUST 使用独立风险语义和事实表
- **THEN** Prompt Audit 只执行本 spec 定义的 Outcome/Action，不得写入 Content Moderation 计数或 Hash

### Requirement: 审核模型必须使用统一 adapter 与两行协议
Endpoint SHALL 支持 qwen3guard 和 openai_compatible_qwen 两类 adapter，并只通过 OpenAI-compatible Chat Completions 调用。所有模型返回 MUST 进入同一个严格 Qwen parser。

#### Scenario: 调用 Qwen3Guard
- **WHEN** endpoint.adapter=qwen3guard
- **THEN** 请求 MUST 只发送一条 user message、temperature=0、stream=false 和 seed=42
- **THEN** 请求 MUST NOT 发送 system、max_tokens、max_completion_tokens、thinking、reasoning_effort 或 response_format

#### Scenario: 调用第三方模型
- **WHEN** endpoint.adapter=openai_compatible_qwen
- **THEN** 请求 MUST 只发送一条 system 和一条 user
- **THEN** system MUST 按顺序包含 audit_prompt、后端固定角色规则或联合规则、可选纠格式提示、后端固定输出协议
- **THEN** 固定协议之后 MUST NOT 有动态文本
- **THEN** user MUST 为后端生成的带 source_role、turn_scope 和正文的片段或联合审核 JSON
- **THEN** 请求 MUST NOT 发送 seed、max_tokens、max_completion_tokens、thinking、reasoning_effort 或 response_format

#### Scenario: 第三方协议纠格式重试
- **WHEN** 第三方模型首次返回 HTTP 2xx 但 envelope、content 或固定两行协议无效
- **THEN** 系统 MUST 在同一个 endpoint timeout 内最多立即重试一次
- **THEN** 纠格式提示 MUST 位于 audit_prompt 与固定输出协议之间
- **THEN** 固定输出协议 MUST 继续作为 system 的最后一段
- **THEN** 重试 MUST NOT 增加或改变现有九类目录

#### Scenario: 客户端含 system/developer 指令
- **WHEN** 被审请求含客户端 system、developer、instructions、assistant 或 tool 文本
- **THEN** 这些文本 MUST 只作为审核模型 user message 中的不可信数据
- **THEN** 它们 MUST NOT 成为审核模型的 system message

### Requirement: 固定协议必须由后端单一来源提供
系统 SHALL 以版本化后端常量维护固定输出协议，并通过 GET config 的 prompt_contract 只读返回。管理员只可编辑 audit_prompt。

#### Scenario: 读取与保存配置
- **WHEN** 管理员读取配置
- **THEN** 响应 MUST 包含 prompt_contract.version 和 prompt_contract.fixed_output_prompt
- **WHEN** 管理员保存配置
- **THEN** Update DTO MUST NOT 接受或持久化 prompt_contract
- **THEN** 第三方模型启用且 audit_prompt 为空时 MUST 返回稳定校验错误

### Requirement: 两行输出必须严格解析
parser SHALL 只接受第一行精确 Safety 标签和值，以及第二行精确 Categories 标签。模型输出协议 MUST 要求官方类别按固定顺序并用“, ”连接；parser 在类别名称、唯一性和分隔符校验通过后 MUST 按固定目录确定性排序。只允许 CRLF 归一和最多一个末尾换行。

#### Scenario: 合法安全结果
- **WHEN** 输出为 Safety: Safe 与 Categories: None
- **THEN** 结果 MUST 为 Pass/Allow

#### Scenario: 合法争议或不安全结果
- **WHEN** Safety 为 Controversial 或 Unsafe 且类别均为官方类别
- **THEN** 系统 MUST 复用既有 Qwen scanner 映射为平台 decision/action

#### Scenario: 合法类别顺序不同
- **WHEN** 多个合法类别未按固定目录顺序返回
- **THEN** parser MUST 在服务端按固定目录重新排序
- **THEN** 系统 MUST NOT 触发 format_repair 或把该模型记为失败

#### Scenario: 协议外输出
- **WHEN** 输出为 JSON、Markdown、带解释/标题/前后缀/第三行、未知/重复/乱序/大小写错误类别、错误分隔符，或 Safety/Categories 配对非法
- **THEN** parser MUST 返回 prompt_guard_invalid_response 与稳定 detail code
- **THEN** 系统 MUST NOT 宽松抽取子串或默认 Safe

### Requirement: 配置必须保留模型顺序并支持三种聚合
配置 SHALL 固定 strategy=ordered_all，并允许 aggregation_strategy 为 any_block、majority_block 或 all_block。Endpoint MUST 包含 adapter 和独立 timeout_ms，不得包含 input_limit 或全局 evaluation timeout。timeout_ms MUST 以毫秒为单位、不得小于 100，系统 MUST NOT 设置业务最大值，但 MUST 拒绝无法由运行时安全表示的数值。

#### Scenario: 保存模型列表
- **WHEN** 管理员提交 endpoint 数组
- **THEN** 后端 MUST 按原数组顺序保存、加载和执行
- **THEN** 后端 MUST NOT 按 ID、名称、adapter 或健康状态排序

#### Scenario: 保存长模型超时
- **WHEN** 管理员提交 timeout_ms=300000 或其他处于运行时可表示范围内的整数
- **THEN** 前后端 MUST 接受并原样保存
- **THEN** 系统 MUST NOT 应用固定 30000ms 上限

#### Scenario: 保存处置配置
- **WHEN** 邮件提醒开启
- **THEN** N 与 M MUST 大于 0 且 M<=N
- **WHEN** 自动停用开启
- **THEN** 累计阈值 MUST 大于 0
- **WHEN** 任一规则开启
- **THEN** notifications.admin_email MUST 非空且格式有效

### Requirement: Qwen 必须继续审核一次现有完整 Prompt
系统 SHALL 复用现有 PromptSnapshot 的 ScanText、FullPrompt、PromptHash 和最新 user 前置规则。qwen3guard endpoint MUST 对 BlockingLatestTurnOnly 选定范围的现有完整文本只调用一次，不得按角色包装、拆分或查询片段历史。

#### Scenario: 长文本超过 Event 快照上限
- **WHEN** scanText 长于 Event full_prompt 的存储上限
- **THEN** Event MAY 按既有边界保存快照
- **THEN** Qwen MUST 仍接收完整 scanText

#### Scenario: BlockingLatestTurnOnly 默认与窄范围
- **WHEN** blocking_latest_turn_only=false 或未配置
- **THEN** blocking 与 async MUST 审核完整请求范围
- **WHEN** blocking_latest_turn_only=true 且存在 user 文本
- **THEN** blocking MUST 只保留最后连续 user 与其之前最近连续 assistant/model
- **WHEN** 请求没有 user 文本
- **THEN** blocking MUST 回退完整范围
- **THEN** async MUST 始终审核完整请求

### Requirement: 第三方模型必须按可信角色片段审核并形成一票
系统 SHALL 从同一协议提取结果保留 source_role、逻辑消息原始顺序和 turn_scope。只有 openai_compatible_qwen SHALL 按角色片段审核；正文角色声明 MUST NOT 覆盖网关确定的角色。每个第三方 endpoint 最终 MUST 只形成一个模型级结果和一票。

#### Scenario: 所有片段 Pass
- **WHEN** 某第三方 endpoint 的全部角色片段结果均为 Pass/Allow
- **THEN** 该 endpoint MUST 直接形成 Pass/Allow
- **THEN** 系统 MUST NOT 执行联合审核

#### Scenario: 片段风险需要联合审核
- **WHEN** 直接影响当前任务的片段没有 Critical，但任一直接片段为 Flag，或任一上下文片段非 Pass
- **THEN** 同一 endpoint MUST 对直接影响片段和非 Pass 上下文最多执行一次联合审核
- **THEN** 联合结果 MUST 成为该 endpoint 的唯一模型级结果

#### Scenario: 直接影响片段 Critical
- **WHEN** 当前生效 system/developer 或当前 user 片段为 Critical/Block
- **THEN** 该 endpoint MUST 直接形成 Critical/Block
- **THEN** 联合审核 MUST NOT 降低该结论

#### Scenario: 前序模型已阻断或失败
- **WHEN** 某模型 Block、已达到聚合门槛、error 或 timeout
- **THEN** 后续启用模型仍 MUST 按顺序执行
- **THEN** Qwen 在当前 attempt 中 MUST 最多调用一次
- **THEN** 每个第三方 endpoint 的每个唯一片段键 MUST 最多调用一次，并最多追加一次联合审核

### Requirement: 模型 timeout 与异步租约必须相互独立
每个 endpoint.timeout_ms SHALL 只控制该模型的一次调用。异步 Worker MUST 在每个模型调用前以 Job ID、processing 状态和 claim_version 刷新租约，并在单次调用持续期间以短于 processing 回收窗口的固定间隔继续刷新。

#### Scenario: 首模型耗尽 timeout
- **WHEN** 首模型超时且后续模型 timeout 更长
- **THEN** 后续模型 MUST 获得自己的完整 timeout
- **THEN** 首模型耗时 MUST NOT 作为共享 deadline 扣减后续模型

#### Scenario: claim_version 已失效
- **WHEN** Worker 在下一模型前刷新租约得到 0 行
- **THEN** Worker MUST 停止后续调用并丢弃旧 attempt 结果

#### Scenario: 单模型调用超过 processing 回收窗口
- **WHEN** 模型 timeout 大于 90 秒且调用仍在进行
- **THEN** Worker MUST 周期性刷新租约
- **THEN** reclaimer MUST NOT 重领该任务
- **WHEN** 调用期间任一次租约刷新失败
- **THEN** Worker MUST 取消当前调用且不得写 done/retry/failed

### Requirement: 聚合必须使用冻结分母和确定性门槛
设 N 为冻结启用模型数，B 为有效 Critical+Block 数，E 为 error/timeout 数。any_block 门槛为 1，majority_block 为 floor(N/2)+1，all_block 为 N。错误模型 MUST NOT 从 N 中移除。

#### Scenario: 达到阻断门槛
- **WHEN** B 达到门槛
- **THEN** 最终结果 MUST 为 Critical/Block
- **THEN** E>0 时仍 MUST 标记 partial_failure=true

#### Scenario: 部分失败且未达门槛
- **WHEN** B 未达门槛且 0<E<N
- **THEN** 异步最终结果 MUST 为 Flag/Warn 并标记 partial_failure
- **THEN** 错误 MUST NOT 降低门槛

#### Scenario: 全部失败
- **WHEN** E=N
- **THEN** 系统 MUST 不生成成功分类流水
- **THEN** 异步 Job MUST 进入现有 retry/failed

### Requirement: 异步任务必须可靠保存临时完整载荷
系统 SHALL 继续使用 PostgreSQL Job 与 Redis Payload，并采用 staging→SET→queued 发布。新 Payload MUST 版本化保存角色、逻辑消息顺序和正文，Worker MUST 能消费旧纯文本 Payload 并按整份模式处理。Payload TTL MUST 按 Qwen 一次及第三方片段数加最多一次联合审核的 timeout 总和、attempt、退避和安全余量动态计算；短于既有 30 分钟默认值时使用 30 分钟，且不得以硬上限导致最大重试周期内提前过期。

#### Scenario: Redis 写入失败
- **WHEN** staging Job 已创建但 Payload SET 失败
- **THEN** Job MUST 失败或等待 staging 回收
- **THEN** 主模型请求 MUST 继续，不得 fail-closed

#### Scenario: 队列已满
- **WHEN** active jobs 达到 queue_capacity
- **THEN** 准入锁内 MUST 拒绝新 Job 并记录稳定 dropped reason
- **THEN** 主模型请求 MUST 不受影响

### Requirement: 每次成功分类必须写唯一 Outcome
系统 SHALL 以 prompt_audit_outcomes 记录每次成功分类，job_id MUST 唯一。Outcome 是邮件窗口和累计停用的唯一计数事实源，且 MUST 不保存 Prompt、预览、audit_prompt、固定协议全文、凭据、Base URL 或模型完整响应。

#### Scenario: Pass 且不保存安全 Event
- **WHEN** 最终 Pass/Allow 且 store_pass_events=false
- **THEN** 系统 MUST 不创建 Event
- **THEN** 系统仍 MUST 创建一条 Outcome

#### Scenario: Event 或 Job 被管理员删除
- **WHEN** 对应 Event/Job 被删除
- **THEN** Outcome MUST 保留
- **THEN** 邮件窗口与累计停用计数 MUST 不改变

#### Scenario: 分类完成前用户已物理删除
- **WHEN** 模型成功分类但原 user_id 已不存在
- **THEN** 系统 MUST 以空 user_id 保留 Outcome 和身份快照
- **THEN** 系统 MUST NOT 创建该用户的 State 或 Action

#### Scenario: 违规判定
- **WHEN** Outcome.decision=critical 且 action=Block
- **THEN** is_violation MUST 为 true
- **THEN** 其他所有组合 MUST 为 false

### Requirement: 完整历史结果必须按冻结配置复用
系统 SHALL 在 blocking 与 async 模型调用前查询全站历史 Outcome。只有 prompt_hash、evaluation_input_hash、evaluation_contract_version、role_contract_hash、配置版本、审核提示词 Hash、固定协议版本、聚合策略、启用模型数和阻断门槛全部一致，且来源为非 partial_failure 的原始 pass、flag 或 critical 完整结果时才允许复用。

#### Scenario: 命中历史完整结果
- **WHEN** 当前 Prompt 和冻结配置命中可复用 Outcome
- **THEN** 系统 MUST 不调用任何审核模型
- **THEN** 系统 MUST 仍为当前请求创建 Job、Outcome 和按配置可选的 Event
- **THEN** 当前 Outcome.reused_from_outcome_id MUST 指向原始模型评估 Outcome
- **THEN** 当前用户的邮件、累计停用和鉴权缓存失效 MUST 正常执行

#### Scenario: 历史结果不可复用或查询失败
- **WHEN** 历史结果失败、partial_failure、已经来自历史复用或冻结配置不一致
- **THEN** 系统 MUST 正常执行 Qwen 完整审核与第三方角色片段审核
- **WHEN** 历史查询自身失败
- **THEN** 系统 MUST 记录稳定回退日志并继续正常模型评估

### Requirement: 第三方片段结果必须按 endpoint 和审核契约复用
完整 Outcome 未命中时，系统 SHALL 一次批量查询全部第三方 endpoint 的唯一片段键。匹配 MUST 包含正文 Hash、policy role、turn scope、endpoint/adapter、config version、审核提示词 Hash、角色提示词 Hash、评估契约版本和固定协议版本；不同 endpoint MUST NOT 共享结果。Qwen 和联合审核结果 MUST NOT 进入片段缓存。

#### Scenario: 片段历史命中
- **WHEN** 某第三方 endpoint 的片段键命中原始成功分类
- **THEN** 系统 MUST 跳过该 endpoint 的该片段调用
- **THEN** 必要使用关系 MUST 直接指向原始片段结果 ID
- **THEN** 系统 MUST NOT 以复用结果再创建片段复用链

#### Scenario: 片段查询失败
- **WHEN** 片段批量历史查询失败
- **THEN** 系统 MUST 记录稳定回退日志并把全部片段视为未命中
- **THEN** blocking fail-closed 与最终聚合语义 MUST NOT 改变

### Requirement: 最终聚合必须始终以 endpoint 为投票粒度
Qwen 完整结果和每个第三方 endpoint 汇总结果 SHALL 各占一票，片段数量和历史命中数量 MUST NOT 改变权重。最终结果 MUST 继续使用 any_block、majority_block 或 all_block 的现有冻结分母与门槛。

#### Scenario: 第三方全部 Pass 但 Qwen Flag 或 Critical
- **WHEN** 所有第三方 endpoint 均 Pass 且 Qwen 返回 Flag/Warn
- **THEN** 三种策略的最终结果 MUST 为 Flag/Warn
- **WHEN** 所有第三方 endpoint 均 Pass 且 Qwen 返回 Critical/Block
- **THEN** any_block MUST 为 Critical/Block
- **THEN** majority_block 与 all_block MUST 按现有门槛处理，未达门槛时为 Flag/Warn

### Requirement: Event 必须保存每模型脱敏明细
prompt_audit_events SHALL 保存可选 full_prompt 和 model_results。model_results MUST 包含冻结聚合元数据及每模型 sequence、endpoint_id、adapter、model、Safety、Categories、decision/action、latency、可选 usage 和稳定 error_code。

#### Scenario: 管理员复核多模型事件
- **WHEN** 一次评估执行多个模型
- **THEN** Event MUST 按执行顺序保存每模型结构化结果
- **THEN** Event MUST NOT 保存模型完整响应或 reasoning content

### Requirement: 所有失败模型调用必须保存数据库诊断
系统 SHALL 通过 prompt_audit_model_attempts 保存所有失败模型调用。诊断 MUST 与 Job 状态事务一致，并 MUST NOT 进入日志、管理端 API 或前端。

#### Scenario: 协议失败后纠格式成功
- **WHEN** 第一次调用协议无效且第二次调用成功
- **THEN** 第一次失败调用 MUST 保存
- **THEN** 最终结果 MUST 按第二次有效分类正常写入 Event/Outcome

#### Scenario: 阻断模式全部失败
- **WHEN** 阻断模式所有模型均失败
- **THEN** 系统 MUST 创建 failed Job 和失败调用诊断
- **THEN** 系统 MUST NOT 创建 Event 或 Outcome

#### Scenario: 响应正文到期
- **WHEN** 失败调用响应正文超过 30 天
- **THEN** 后台任务 MUST 清空响应正文并保留 hash、大小、截断标记和错误元数据

### Requirement: 邮件提醒必须按最近窗口边沿触发
email_warning SHALL 只对规则开启期间的新 Outcome 求值。开关、N 或 M 变化 MUST 递增服务端 rule_revision，并从每用户下一条 Outcome 建立新边界。

#### Scenario: 窗口越过阈值
- **WHEN** 边界后最近 N 条 Outcome 中违规数从 <M 变为 >=M
- **THEN** 系统 MUST 创建一个唯一 email_warning Action
- **THEN** 持续 >=M 时 MUST NOT 重复创建

#### Scenario: 窗口重新布防
- **WHEN** 后续最近 N 条窗口跌回 <M
- **THEN** 用户邮件规则 MUST 重新布防
- **THEN** 再次越过阈值时 MAY 创建新 Action

### Requirement: 自动停用必须按用户累计并保护管理员
account_disable SHALL 只在开关开启期间、当前 Outcome 违规且 role=user 时增加用户 State 的累计。关闭开关 MUST 暂停累计而不清零。

#### Scenario: 达到累计阈值
- **WHEN** 普通 active 用户累计达到 M
- **THEN** 系统 MUST 在同一事务中条件更新用户为 disabled，并创建唯一 account_disabled Action
- **THEN** 提交后 MUST 失效该用户鉴权缓存

#### Scenario: 管理员或已停用用户违规
- **WHEN** role=admin
- **THEN** 系统 MUST 不累计且不得自动停用
- **WHEN** 用户已 disabled
- **THEN** 系统 MUST 不重复停用或重复创建停用 Action

#### Scenario: 同一 Outcome 同时达到两条阈值
- **WHEN** 同一违规同时满足普通提醒与自动停用
- **THEN** 系统 MUST 只创建 account_disabled
- **THEN** 邮件窗口 MUST 设为未布防

### Requirement: 单账号重新启用必须事务性重置停用累计
现有 PUT /api/v1/admin/users/:id SHALL 是唯一恢复入口。普通用户 disabled→active 时 MUST 在同一事务中先锁 Prompt Audit State、重置累计并写 counter_reset，再更新 users。

#### Scenario: 重新启用普通用户
- **WHEN** 管理员把一个普通用户从 disabled 改为 active
- **THEN** disable_violation_count MUST 清零
- **THEN** disable_reset_outcome_id MUST 更新为该用户当时最新 Outcome ID
- **THEN** 邮件窗口、历史 Event、Outcome 和 Action MUST 保留

#### Scenario: 重复 active 更新
- **WHEN** 用户原状态已经 active
- **THEN** 系统 MUST NOT 再写 counter_reset

### Requirement: 邮件必须通过持久 Action Outbox 分收件人投递
系统 SHALL 在业务事务提交后异步投递邮件。管理员和用户收件人 MUST 各自维护 pending/sent/failed/not_required 状态；已成功收件人不得因另一个失败而重试。

#### Scenario: 账号停用成功
- **WHEN** account_disabled Action 已提交
- **THEN** 系统 MUST 分别通知配置的管理员邮箱和用户邮箱
- **THEN** 该通知 MUST 不受普通 email_warning 开关影响

#### Scenario: 某一收件人失败
- **WHEN** 管理员邮件成功而用户邮件失败
- **THEN** 后续 MUST 只重试用户收件人
- **THEN** 邮件失败 MUST 不回滚 Outcome、Event 或账号停用

#### Scenario: 用户邮箱缺失
- **WHEN** account_disabled Action 找不到用户邮箱快照或当前邮箱
- **THEN** 系统 MUST 把用户收件人标为 not_required 并记录稳定 user_email_missing
- **THEN** 管理员收件人 MUST 继续投递

#### Scenario: 邮件内容检查
- **WHEN** 测试捕获邮件变量
- **THEN** 邮件 MUST NOT 包含 Prompt、预览、audit_prompt、固定协议全文、Token、Base URL、模型完整响应或 reasoning content
- **THEN** 邮件 MUST 使用 Prompt Audit 专用事实文案，不得把管理员误写为违规请求人

### Requirement: 运行态必须展示每模型、整条审核和处置统计
Runtime SHALL 返回每模型顺序/开关/probe、请求与分类数、错误、usage、P50/P95；整条 evaluation total/partial_failure/P50/P95；聚合策略、启用模型快照数、门槛、协议版本、audit_prompt hash；Outcome、违规、提醒、停用和邮件失败累计。

#### Scenario: 管理员查询运行态
- **WHEN** Runtime API 成功
- **THEN** 所有模型 MUST 按配置顺序返回
- **THEN** 统计 MUST 来自实际扫描与持久处置事实
- **THEN** 响应 MUST NOT 包含 audit_prompt 原文、Token 或模型完整响应

### Requirement: 管理员事件删除必须保留独立处置事实
系统 SHALL 继续支持列表、详情、单条/批量/筛选删除与认证预览。删除 Event 后只清理符合条件的孤立 Job，不得删除 Outcome、State 或 Action。

#### Scenario: 确认筛选删除
- **WHEN** 管理员提交相同筛选、有效 confirmation_token、snapshot_max_id 和 confirm=true
- **THEN** 系统 MUST 只删除预览高水位内匹配的 Event
- **THEN** 新 Event 及所有 Outcome/State/Action MUST 保留
