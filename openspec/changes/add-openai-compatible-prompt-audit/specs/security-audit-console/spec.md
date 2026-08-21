## ADDED Requirements

### Requirement: 管理台必须保留安全审计分组与独立页面
控制台 SHALL 在“安全审计”分组中保留现有内容审核，并提供 /admin/prompt-audit。risk_control_enabled=false 时按既有 feature policy 隐藏/停用入口，但 MUST 不删除配置或历史事实。

#### Scenario: 管理员查看导航
- **WHEN** 管理员登录且 risk_control_enabled=true
- **THEN** 安全审计分组 MUST 同时包含内容审核与提示词审计
- **THEN** /admin/risk-control 原页面与功能 MUST 保持兼容

### Requirement: 配置页必须按最终业务顺序组织
Prompt Audit 配置区 SHALL 依次展示运行概览、已添加审核模型、第三方模型审核提示词、审计策略、阈值处置与通知；审核事件继续位于同一工作区的独立页签。

#### Scenario: 初次加载
- **WHEN** 管理员打开页面
- **THEN** 配置、Runtime、分组和 Event MUST 独立加载
- **THEN** 某一接口失败 MUST 不导致其他区域白屏

#### Scenario: 草稿未保存
- **WHEN** 管理员修改可编辑配置
- **THEN** 页面 MUST 显示未保存状态
- **THEN** Runtime MUST 继续显示服务端 active/expected version，而不是草稿

### Requirement: 审核模型列表必须支持 adapter、顺序与独立 timeout
EndpointPool SHALL 展示顺序、开关、名称、模型、adapter、timeout、凭据状态和 probe，并支持新增、编辑、删除、上移、下移。页面 MUST 不提供 input_limit、Token 上限、思考等级、response schema 或拖拽依赖。

#### Scenario: 上移或下移
- **WHEN** 管理员点击上移/下移
- **THEN** 页面 MUST 只重排 endpoint 数组
- **THEN** 其他字段 MUST 保持不变
- **THEN** 新模型 MUST 默认追加到列表尾部

#### Scenario: 编辑凭据
- **WHEN** 已保存节点拥有 Token
- **THEN** 输入框 MUST 为空并显示 has_token/token_status
- **THEN** 空输入保存 MUST 保留密文，显式 clear_token 才能清除
- **THEN** Token MUST 不进入 localStorage、sessionStorage、URL、console 或持久前端状态

#### Scenario: 选择 adapter
- **WHEN** 管理员编辑节点
- **THEN** adapter 文案 MUST 为“Qwen3Guard”或“第三方 OpenAI-compatible（Qwen 两行格式）”

#### Scenario: 新增与编辑 adapter 默认值
- **WHEN** 管理员新增模型
- **THEN** adapter MUST 默认选择 openai_compatible_qwen
- **WHEN** 管理员编辑已有模型
- **THEN** adapter MUST 回显该模型已保存的有效值；旧数据缺失或无效时 MAY 回退 openai_compatible_qwen

### Requirement: 页面必须区分可编辑审核提示词与只读固定协议
AuditPromptPanel SHALL 使用可编辑 textarea 绑定 audit_prompt，并使用不可编辑 pre/code 展示后端 prompt_contract.fixed_output_prompt。前端 MUST 不硬编码另一份固定协议。

#### Scenario: 第三方提示词为空
- **WHEN** 至少一个启用模型使用 openai_compatible_qwen 且 audit_prompt 为空
- **THEN** 页面 MUST 显示可行动的校验错误
- **THEN** 后端保存和 Probe 仍 MUST 做最终校验

#### Scenario: 固定协议变化
- **WHEN** GET config 返回新的 prompt_contract
- **THEN** 页面 MUST 更新只读展示
- **THEN** dirty fingerprint MUST 不变化
- **THEN** buildUpdateRequest MUST 不包含 prompt_contract

### Requirement: 页面必须配置三种聚合并实时显示门槛
PolicyPanel SHALL 支持 any_block、majority_block 和 all_block，并根据当前启用模型数实时展示 N 与门槛。页面 MUST 说明所有启用模型按顺序执行，顺序不代表权重且达到门槛后不会早停。

#### Scenario: 选择多数阻断
- **WHEN** 有 4 个启用模型且管理员选择 majority_block
- **THEN** 页面 MUST 显示阻断门槛 3

#### Scenario: 禁用一个模型
- **WHEN** 启用模型数从 4 变为 3
- **THEN** 页面 MUST 立即把多数阻断门槛更新为 2

### Requirement: 页面必须支持阈值处置与通知
EnforcementPanel SHALL 提供管理员邮箱、普通邮件提醒独立开关及最近 N/违规 M、自动停用独立开关及累计 M。文案 MUST 区分最近窗口与“自上次单账号启用重置后累计”。

#### Scenario: 查看普通提醒
- **WHEN** 管理员开启 email_warning
- **THEN** 页面 MUST 说明只在最近窗口越过阈值边沿时提醒

#### Scenario: 查看自动停用
- **WHEN** 管理员开启 account_disable
- **THEN** 页面 MUST 说明累计口径和单账号重置
- **THEN** 页面 MUST 说明停用邮件不受普通提醒开关影响

### Requirement: 开启 blocking 必须明确确认
enabled、blocking_enabled、blocking_latest_turn_only 与 store_pass_events SHALL 保持独立草稿字段。关闭 enabled MUST 同时关闭并禁用 blocking；从 false 开启 blocking MUST 二次确认 fail-closed 风险。

#### Scenario: 开启同步门禁
- **WHEN** 管理员开启 blocking
- **THEN** 确认文案 MUST 说明请求等待所有启用模型，Block 或未达门槛的模型失败不会访问上游

### Requirement: 保存与 Probe 必须使用当前草稿且不得泄密
统一保存动作 SHALL 提交完整规范化 Update DTO，并在成功后以 Public DTO 重建草稿和清除明文 Token。Probe 第三方模型时 MUST 同时提交当前草稿 audit_prompt。

#### Scenario: 保存成功
- **WHEN** PUT config 成功
- **THEN** 页面 MUST 显示新 config_version 与已同步状态
- **THEN** 已提交 Token MUST 从组件状态与渲染 HTML 中消失

#### Scenario: 配置冲突
- **WHEN** 后端返回 409 prompt_audit_config_conflict
- **THEN** 页面 MUST 保留本地草稿并提示服务端已变化
- **THEN** 页面 MUST 不自动覆盖新服务端配置

#### Scenario: Probe 输出协议错误
- **WHEN** 第三方模型连接成功但两行输出非法
- **THEN** 页面 MUST 展示实际 HTTP status 与稳定协议错误
- **THEN** 页面 MUST 不把它显示为网络连接失败

### Requirement: Runtime 必须展示每模型与整条评估
RuntimeOverview SHALL 展示每模型顺序、启用状态、adapter/model、timeout、probe、请求、Pass/Flag/Critical/error、输入/输出/reasoning Token 和 P50/P95；还 SHALL 展示整条 evaluation total/partial failure/P50/P95、聚合策略、模型快照数、门槛、协议版本、audit_prompt hash 以及 Outcome/违规/提醒/停用/邮件失败累计。

#### Scenario: 查看 ordered-all 状态
- **WHEN** Runtime 返回多个模型
- **THEN** 页面 MUST 按后端 sequence 展示
- **THEN** 页面 MUST 不再把 failover 作为模型执行说明

### Requirement: Event 详情必须展示每模型脱敏结果
EventDetailDialog SHALL 展示完整管理员复核 Prompt、最终聚合摘要、风险摘要和 model_results。每模型行 MUST 包含输入模式、片段数/命中数/联合摘要、Safety、Categories、decision/action、latency、usage 与 error_code；技术信息还 SHALL 展示评估契约、完整/片段/联合调用数及必要的第三方片段来源，但 MUST 不展示模型完整响应或 reasoning content。

#### Scenario: 部分模型失败
- **WHEN** Event.model_results.aggregation.partial_failure=true
- **THEN** 技术信息 MUST 明确标识部分失败、模型数和门槛
- **THEN** 失败模型 MUST 展示稳定 error_code，成功模型仍展示分类

#### Scenario: 复用历史结果
- **WHEN** Event.model_results.aggregation.reused_from_outcome_id 有值
- **THEN** 技术信息 MUST 展示来源 Outcome ID
- **THEN** 页面 MUST 说明本次未重新调用任何审核模型，而不是展示空的每模型表格

#### Scenario: 查看第三方片段来源
- **WHEN** Event 包含第三方片段使用关系
- **THEN** 页面 MUST 展示 endpoint、片段顺序、source_role、turn_scope、decision/action、categories
- **THEN** 历史命中 MUST 标识原始片段结果 ID

#### Scenario: 完整 Prompt 复核
- **WHEN** Event 拥有 full_prompt
- **THEN** 页面 MAY 向管理员展示该敏感文本并提供明确保密提示
- **THEN** 页面 MUST 不把它复制到 Runtime、邮件或普通日志

### Requirement: 用户启用必须复用现有单账号入口
UsersView SHALL 继续使用普通用户行的“启用”按钮和 PUT /api/v1/admin/users/:id，不得增加第二个 Prompt Audit 重置请求或批量入口。

#### Scenario: 普通用户启用成功
- **WHEN** 后端完成 disabled→active 与停用累计重置
- **THEN** 页面 MUST 显示统一成功提示，说明累计已重置
- **THEN** 页面 MUST 只发送一次用户更新请求

### Requirement: Event 删除必须防误操作且不暗示删除 Outcome
页面 SHALL 保留单条、选中批量和按筛选删除。筛选删除使用服务端预览、snapshot_max_id、filter_hash、confirmation_token 与 confirm=true；筛选变化必须废弃旧预览。

#### Scenario: 确认筛选删除
- **WHEN** 管理员确认有效预览
- **THEN** 页面 MUST 只提交 Event 删除契约
- **THEN** 文案 MUST 不声称 Outcome、State 或 Action 被删除

### Requirement: 管理操作审计必须使用安全摘要
配置写入、Probe 和 Event 删除 SHALL 复用现有管理员审计。配置摘要 MAY 包含开关、config version、endpoint/启用/第三方模型数量、聚合策略、分类/分组数量、规则开关和阈值，但 MUST 不包含 audit_prompt、固定协议全文、管理员邮箱原文、Token 或完整 Base URL。

#### Scenario: 配置更新
- **WHEN** 管理员保存配置
- **THEN** 审计 MUST 能说明模型数、聚合和处置开关
- **THEN** 审计 JSON MUST 不包含任何敏感正文或收件地址

### Requirement: 页面必须满足响应式、可访问和双语要求
新增组件、输入、radio、switch、按钮、表格和 Dialog SHALL 有可访问名称，并使用对称 zh/en i18n。窄屏必须可重排或滚动而不遮挡保存和事件操作。

#### Scenario: 国际化结构校验
- **WHEN** 运行 locale 对称测试
- **THEN** promptAudit 的 zh/en 顶层与新增操作键 MUST 对称
