## ADDED Requirements

### Requirement: 同步提示词门禁必须由显式配置启用
系统 SHALL 使用 enabled 与 blocking_enabled 表达 off、async_audit 和 blocking。缺失 blocking_enabled 的旧配置 MUST 归一为 false；enabled=false 且 blocking_enabled=true MUST 被拒绝。

#### Scenario: 异步审计
- **WHEN** enabled=true 且 blocking_enabled=false
- **THEN** 主请求 MUST 不等待模型分类
- **THEN** DB、Redis 或模型故障 MUST 不改变客户端结果

#### Scenario: 同步阻止
- **WHEN** enabled=true 且 blocking_enabled=true
- **THEN** 请求 MUST 在账号选择、计费和上游前等待 ordered-all 结果
- **THEN** 未达阻断门槛的 partial failure MUST fail-closed

### Requirement: 安全审计协调器必须保持两个引擎独立
Coordinator SHALL 把可信请求分别交给既有 Content Moderation 与 Prompt Audit，并使用稳定响应优先级。两者 MUST 不共用分类、事实表或副作用。

#### Scenario: 两个引擎同时 Block
- **WHEN** Content Moderation 与 Prompt Guard 都阻断
- **THEN** 客户端 MUST 继续收到既有 Content Moderation 响应
- **THEN** Prompt Audit MUST 仍按独立 Job/Event/Outcome 规则记录

#### Scenario: 只有 Prompt Guard Block
- **WHEN** 既有审核允许且 Prompt 聚合达到门槛
- **THEN** 客户端 MUST 收到 403 prompt_guard_blocked

### Requirement: 同步门禁必须位于外部副作用之前
系统 MUST 在鉴权、body limit 和基本协议校验之后，在账号选择、用户/账号并发 slot、计费资格、预扣、usage、上游连接/写入和 SSE 首字节之前完成同步结果。

#### Scenario: Block 或 fail-closed
- **WHEN** 同步结果为 Block、Unavailable 或 Invalid
- **THEN** 账号选择、计费/预扣与上游调用次数 MUST 全部为 0
- **THEN** SSE MUST 未发送 header 或任何字节

### Requirement: 同步门禁必须覆盖所有用户文本入口
系统 SHALL 覆盖现有 Content Moderation 已接入的 Chat Completions、Responses、Claude Messages、Gemini、Images/Grok 媒体文本入口和 Responses WebSocket 每轮 response.create，并通过结构测试防止旁路。

#### Scenario: HTTP 协议入口
- **WHEN** 任一受支持 HTTP 入口收到用户文本
- **THEN** 系统 MUST 使用同一 PromptSnapshot 与 ordered-all evaluator
- **THEN** 拒绝 MUST 使用该协议既有错误 envelope

#### Scenario: WebSocket 后续轮次
- **WHEN** 已建立 Responses WebSocket 后收到新的 response.create
- **THEN** 系统 MUST 对本轮输入重新审核
- **THEN** 前一轮结果 MUST NOT 复用于本轮

### Requirement: 同步评估必须执行所有启用模型
系统 SHALL 按 endpoint 数组顺序执行所有启用模型，并为每个模型使用独立 timeout_ms。模型顺序 MUST NOT 代表权重或故障切换优先级。

#### Scenario: 首模型已 Block
- **WHEN** 首模型返回 Critical/Block
- **THEN** evaluator MUST 继续调用所有后续启用模型
- **THEN** 每个模型 MUST 在本 evaluation 中最多调用一次

#### Scenario: 首模型失败
- **WHEN** 首模型 error 或 timeout
- **THEN** evaluator MUST 记录该模型错误并继续后续模型
- **THEN** 后续模型 MUST 获得自己的完整 timeout

#### Scenario: bulkhead 饱和
- **WHEN** 全局或目标节点 bulkhead 无法接纳调用
- **THEN** 该调用 MUST 快速形成稳定模型错误
- **THEN** 系统 MUST 不无限等待

### Requirement: 同步聚合必须使用冻结模型数
系统 SHALL 在 evaluation 开始时冻结 N、aggregation_strategy 和阻断门槛。error/timeout MUST 不缩小 N。

#### Scenario: 任一阻断
- **WHEN** aggregation_strategy=any_block 且至少一个有效结果 Block
- **THEN** 最终 MUST Block

#### Scenario: 多数阻断
- **WHEN** aggregation_strategy=majority_block
- **THEN** 只有 B>=floor(N/2)+1 时最终 Block

#### Scenario: 全体阻断
- **WHEN** aggregation_strategy=all_block
- **THEN** 只有 N 个启用模型均有效 Block 时最终 Block
- **THEN** 任一模型失败 MUST 使门槛未达并在同步模式 fail-closed

#### Scenario: 达到门槛且部分失败
- **WHEN** B 已达到门槛且仍有模型失败
- **THEN** 最终 MUST Block
- **THEN** 记录 MUST 标记 partial_failure=true

#### Scenario: 未达门槛且部分失败
- **WHEN** B 未达门槛且至少一个模型失败
- **THEN** 同步请求 MUST 返回 prompt_guard_unavailable 或 prompt_guard_invalid_response
- **THEN** 系统 MUST NOT 按 Warn 部分放行

### Requirement: 同步结果必须先记录且不得重复扫描
系统 SHALL 把一次 evaluation 的聚合结果与每模型明细交给 RecordBlocking。记录路径 MUST NOT 再调用模型；一次成功分类 MUST 写唯一 Outcome，并按 store_pass_events 决定 Event。

#### Scenario: 同步 Block
- **WHEN** evaluator 得到 Block
- **THEN** RecordBlocking MUST 在一个事务中写 done Job、可选 Event、Outcome、State/Action
- **THEN** 模型调用次数 MUST 不因记录而增加

#### Scenario: 记录失败
- **WHEN** 已确定同步结果但数据库记录失败
- **THEN** 系统 MUST 记录 prompt_guard.result_record_failed
- **THEN** 已确定 Allow/Block MUST 不被反转

### Requirement: HTTP 与 WebSocket 拒绝必须保持协议兼容
同步 Guard MUST 只暴露稳定 code/reason、通用消息和 request ID。响应 MUST 不包含 Prompt、类别详情、模型结果、节点地址或凭据。

#### Scenario: HTTP Block
- **WHEN** 最终 Block
- **THEN** HTTP 状态 MUST 为 403 且 code 为 prompt_guard_blocked

#### Scenario: HTTP partial/all failure
- **WHEN** 未达到门槛且存在模型错误，或所有模型失败
- **THEN** HTTP 状态 MUST 为 503
- **THEN** code MUST 按错误类型为 prompt_guard_unavailable 或 prompt_guard_invalid_response

#### Scenario: Gemini Block
- **WHEN** Gemini 入口 Block
- **THEN** Google envelope 的 error.code MUST 保持数值 403
- **THEN** ErrorInfo.reason MUST 为 prompt_guard_blocked

#### Scenario: WebSocket 拒绝
- **WHEN** response.create 被 Block
- **THEN** close code MUST 为 4403，reason 为 prompt_guard_blocked
- **WHEN** 结果 Unavailable/Invalid
- **THEN** close code MUST 为 1013，并使用对应稳定 reason

### Requirement: 配置必须以版本化顺序快照发布
系统 SHALL 使用 config_version CAS 保存完整配置，保存成功后原子安装本实例快照并发布只含版本的 Redis invalidation。快照 MUST 保留 endpoint 顺序、adapter、独立 timeout、audit_prompt hash、协议版本和聚合门槛。

#### Scenario: 并发管理员保存
- **WHEN** 第二个保存仍携带旧 expected_config_version
- **THEN** 后端 MUST 返回 409 prompt_audit_config_conflict
- **THEN** 不得覆盖已提交配置或重排 endpoint

#### Scenario: 冷启动无有效快照
- **WHEN** 已知 blocking 期望开启但配置无法加载
- **THEN** 适用请求 MUST fail-closed
- **THEN** Runtime MUST 显示 degraded/error，而不是 off/healthy

### Requirement: 单账号自动停用必须在提交后失效鉴权缓存
同步和异步完成事务 SHALL 在实际把普通用户从 active 更新为 disabled 后返回该 user ID，并在事务提交后复用既有鉴权缓存失效端口。

#### Scenario: 自动停用已提交
- **WHEN** 条件更新 users.status 成功
- **THEN** 当前 API Key 的后续鉴权 MUST 不再继续使用旧 active 缓存
- **THEN** 邮件失败 MUST 不恢复用户状态

### Requirement: Guard 关键路径必须可观测且不得泄密
系统 SHALL 输出稳定结构化事件和总体/每模型/evaluation 指标。日志 MUST 允许聚合策略、模型数、门槛和 partial_failure，但 MUST 禁止 input_limit、Prompt、audit_prompt、固定协议全文、Token、Authorization、完整 Base URL/query 与模型完整响应。

#### Scenario: 同步阻断日志
- **WHEN** 请求被 Prompt Guard Block
- **THEN** 日志 MUST 包含可关联 ID、config_version、decision/action、模型数、门槛、partial_failure、latency 和稳定 error_code
- **THEN** 日志 MUST 明确 upstream_dispatched=false 与 billing_preconsumed=false
