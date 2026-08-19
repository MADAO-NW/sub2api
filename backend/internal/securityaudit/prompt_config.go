package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/mail"
	"sort"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	DefaultWorkerCount         = 4
	MaxWorkerCount             = 32
	DefaultQueueCapacity       = 32768
	MaxQueueCapacity           = 100000
	DefaultTimeoutMS     int64 = 3000
	MinTimeoutMS         int64 = 100
	DefaultPayloadTTL          = 30 * time.Minute
	// maxRepresentableTimeoutMS 仅限制 Go time.Duration 可安全表示的毫秒值，不是业务上限。
	maxRepresentableTimeoutMS int64 = math.MaxInt64 / int64(time.Millisecond)
)

type SecretEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// ConfigStore is the injectable boundary between hot-path prompt auditing and
// the concrete settings/PostgreSQL/Redis-backed configuration manager.
type ConfigStore interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Active() (ActiveConfig, bool)
	EffectiveMode() Mode
	// BlockingActivationDegraded is true when storage intent requires blocking
	// but no usable blocking snapshot is active (cold start or failed reload).
	// It must stay false when blocking is not intended, even if config is
	// untrusted—otherwise default-off deployments fail closed for all traffic.
	BlockingActivationDegraded() bool
	Public() (PublicConfig, error)
	Save(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error)
	RuntimeState() (expected int64, active int64, loadedAt *time.Time, loadError string)
	Encrypt(value string) (string, error)
	Decrypt(value string) (string, error)
}

type StorageEndpoint struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Adapter         string `json:"adapter"`
	Protocol        string `json:"protocol"`
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	TokenCiphertext string `json:"token_ciphertext,omitempty"`
	TimeoutMS       int64  `json:"timeout_ms"`
	Enabled         bool   `json:"enabled"`
}

type NotificationConfig struct {
	AdminEmail string `json:"admin_email"`
}

type EmailWarningConfig struct {
	Enabled            bool  `json:"enabled"`
	RuleRevision       int64 `json:"rule_revision"`
	LookbackCount      int   `json:"lookback_count"`
	ViolationThreshold int   `json:"violation_threshold"`
}

type AccountDisableConfig struct {
	Enabled            bool `json:"enabled"`
	ViolationThreshold int  `json:"violation_threshold"`
}

type EnforcementConfig struct {
	EmailWarning   EmailWarningConfig   `json:"email_warning"`
	AccountDisable AccountDisableConfig `json:"account_disable"`
}

type EmailWarningUpdate struct {
	Enabled            bool `json:"enabled"`
	LookbackCount      int  `json:"lookback_count"`
	ViolationThreshold int  `json:"violation_threshold"`
}

type EnforcementUpdate struct {
	EmailWarning   EmailWarningUpdate   `json:"email_warning"`
	AccountDisable AccountDisableConfig `json:"account_disable"`
}

type storageConfig struct {
	Enabled                bool               `json:"enabled"`
	BlockingEnabled        bool               `json:"blocking_enabled"`
	BlockingLatestTurnOnly bool               `json:"blocking_latest_turn_only"`
	StorePassEvents        bool               `json:"store_pass_events"`
	Strategy               string             `json:"strategy"`
	AggregationStrategy    string             `json:"aggregation_strategy"`
	AuditPrompt            string             `json:"audit_prompt"`
	WorkerCount            int                `json:"worker_count"`
	QueueCapacity          int                `json:"queue_capacity"`
	Scanners               []string           `json:"scanners"`
	AllGroups              bool               `json:"all_groups"`
	GroupIDs               []int64            `json:"group_ids"`
	Notifications          NotificationConfig `json:"notifications"`
	Enforcement            EnforcementConfig  `json:"enforcement"`
	Endpoints              []StorageEndpoint  `json:"endpoints"`
	ConfigVersion          int64              `json:"config_version"`
	UpdatedAt              time.Time          `json:"updated_at"`
	UpdatedBy              int64              `json:"updated_by"`
	ChangeSummary          string             `json:"change_summary"`
}

type ActiveEndpoint struct {
	ID        string
	Name      string
	Adapter   string
	Protocol  string
	BaseURL   string
	Model     string
	Token     string
	TimeoutMS int64
	Enabled   bool
	// TokenInvalid marks an endpoint whose persisted token ciphertext cannot be
	// decrypted with the current encryption key (key changed or auto-generated
	// on restart). The endpoint is kept visible for admins but excluded from
	// runtime use until the token is re-entered or cleared (issue #4887).
	TokenInvalid bool
}

type ActiveConfig struct {
	RiskControlEnabled     bool
	Enabled                bool
	BlockingEnabled        bool
	BlockingLatestTurnOnly bool
	StorePassEvents        bool
	Strategy               string
	AggregationStrategy    string
	AuditPrompt            string
	WorkerCount            int
	QueueCapacity          int
	Scanners               []string
	AllGroups              bool
	GroupIDs               []int64
	Notifications          NotificationConfig
	Enforcement            EnforcementConfig
	Endpoints              []ActiveEndpoint
	ConfigVersion          int64
	UpdatedAt              time.Time
	UpdatedBy              int64
	ChangeSummary          string
}

type PublicEndpoint struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Adapter     string `json:"adapter"`
	Protocol    string `json:"protocol"`
	BaseURL     string `json:"base_url"`
	Model       string `json:"model"`
	TimeoutMS   int64  `json:"timeout_ms"`
	Enabled     bool   `json:"enabled"`
	HasToken    bool   `json:"has_token"`
	TokenStatus string `json:"token_status"`
}

type PublicConfig struct {
	Enabled                bool               `json:"enabled"`
	BlockingEnabled        bool               `json:"blocking_enabled"`
	BlockingLatestTurnOnly bool               `json:"blocking_latest_turn_only"`
	StorePassEvents        bool               `json:"store_pass_events"`
	EffectiveMode          Mode               `json:"effective_mode"`
	Strategy               string             `json:"strategy"`
	AggregationStrategy    string             `json:"aggregation_strategy"`
	AuditPrompt            string             `json:"audit_prompt"`
	WorkerCount            int                `json:"worker_count"`
	QueueCapacity          int                `json:"queue_capacity"`
	Scanners               []string           `json:"scanners"`
	AllGroups              bool               `json:"all_groups"`
	GroupIDs               []int64            `json:"group_ids"`
	Notifications          NotificationConfig `json:"notifications"`
	Enforcement            EnforcementConfig  `json:"enforcement"`
	Endpoints              []PublicEndpoint   `json:"endpoints"`
	PromptContract         PromptContract     `json:"prompt_contract"`
	ConfigVersion          int64              `json:"config_version"`
	UpdatedAt              time.Time          `json:"updated_at"`
	UpdatedBy              int64              `json:"updated_by"`
	ChangeSummary          string             `json:"change_summary"`
}

type UpdateEndpoint struct {
	ID         string `json:"id" binding:"required"`
	Name       string `json:"name" binding:"required"`
	Adapter    string `json:"adapter" binding:"required"`
	Protocol   string `json:"protocol"`
	BaseURL    string `json:"base_url" binding:"required"`
	Model      string `json:"model"`
	Token      string `json:"token,omitempty"`
	ClearToken bool   `json:"clear_token"`
	TimeoutMS  int64  `json:"timeout_ms"`
	Enabled    bool   `json:"enabled"`
}

type UpdateConfigRequest struct {
	ExpectedConfigVersion  int64              `json:"expected_config_version" binding:"required"`
	Enabled                bool               `json:"enabled"`
	BlockingEnabled        bool               `json:"blocking_enabled"`
	BlockingLatestTurnOnly bool               `json:"blocking_latest_turn_only"`
	StorePassEvents        bool               `json:"store_pass_events"`
	Strategy               string             `json:"strategy"`
	AggregationStrategy    string             `json:"aggregation_strategy"`
	AuditPrompt            string             `json:"audit_prompt"`
	WorkerCount            int                `json:"worker_count"`
	QueueCapacity          int                `json:"queue_capacity"`
	Scanners               []string           `json:"scanners"`
	AllGroups              bool               `json:"all_groups"`
	GroupIDs               []int64            `json:"group_ids"`
	Notifications          NotificationConfig `json:"notifications"`
	Enforcement            EnforcementUpdate  `json:"enforcement"`
	Endpoints              []UpdateEndpoint   `json:"endpoints"`
}

func DefaultStorageConfig() storageConfig {
	return storageConfig{
		Enabled:                false,
		BlockingEnabled:        false,
		BlockingLatestTurnOnly: false,
		StorePassEvents:        false,
		Strategy:               StrategyOrderedAll,
		AggregationStrategy:    AggregationAnyBlock,
		AuditPrompt:            DefaultAuditPrompt,
		WorkerCount:            DefaultWorkerCount,
		QueueCapacity:          DefaultQueueCapacity,
		Scanners:               append([]string(nil), AllScannerIDs...),
		AllGroups:              true,
		GroupIDs:               []int64{},
		Notifications:          NotificationConfig{},
		Enforcement: EnforcementConfig{
			EmailWarning: EmailWarningConfig{RuleRevision: 1},
		},
		Endpoints:     []StorageEndpoint{},
		ConfigVersion: 1,
	}
}

func ParseStorageConfig(raw string) (storageConfig, error) {
	cfg := DefaultStorageConfig()
	if strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return storageConfig{}, fmt.Errorf("decode prompt audit config: %w", err)
	}
	normalizeStorageConfig(&cfg)
	if err := validateStorageConfig(cfg); err != nil {
		return storageConfig{}, err
	}
	return cfg, nil
}

func normalizeStorageConfig(cfg *storageConfig) {
	if cfg == nil {
		return
	}
	if cfg.ConfigVersion < 1 {
		cfg.ConfigVersion = 1
	}
	if strings.TrimSpace(cfg.Strategy) == "" {
		cfg.Strategy = StrategyOrderedAll
	}
	if strings.TrimSpace(cfg.AggregationStrategy) == "" {
		cfg.AggregationStrategy = AggregationAnyBlock
	}
	if cfg.WorkerCount == 0 {
		cfg.WorkerCount = DefaultWorkerCount
	}
	if cfg.QueueCapacity == 0 {
		cfg.QueueCapacity = DefaultQueueCapacity
	}
	if len(cfg.Scanners) == 0 {
		cfg.Scanners = append([]string(nil), AllScannerIDs...)
	}
	cfg.Scanners = canonicalScannerIDs(cfg.Scanners)
	cfg.GroupIDs = canonicalInt64s(cfg.GroupIDs)
	cfg.Notifications.AdminEmail = strings.TrimSpace(cfg.Notifications.AdminEmail)
	if cfg.Enforcement.EmailWarning.RuleRevision < 1 {
		cfg.Enforcement.EmailWarning.RuleRevision = 1
	}
	// Preserve an invalid blocking-without-audit combination so validation can
	// reject it instead of silently changing administrator intent.
	for i := range cfg.Endpoints {
		ep := &cfg.Endpoints[i]
		ep.ID = strings.TrimSpace(ep.ID)
		ep.Name = strings.TrimSpace(ep.Name)
		ep.Adapter = strings.TrimSpace(ep.Adapter)
		if ep.Adapter == "" {
			ep.Adapter = AdapterQwen3Guard
		}
		ep.Protocol = strings.TrimSpace(ep.Protocol)
		if ep.Protocol == "" {
			ep.Protocol = "openai_compatible"
		}
		ep.BaseURL = strings.TrimSpace(ep.BaseURL)
		ep.Model = strings.TrimSpace(ep.Model)
		if ep.Model == "" {
			ep.Model = DefaultGuardModel
		}
		if ep.TimeoutMS == 0 {
			ep.TimeoutMS = DefaultTimeoutMS
		}
	}
}

func validateStorageConfig(cfg storageConfig) error {
	if cfg.BlockingEnabled && !cfg.Enabled {
		return infraerrors.BadRequest(ErrorCodeRequiresEnabled, "开启同步阻止前必须先启用提示词审计")
	}
	if cfg.Strategy != StrategyOrderedAll {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 ordered_all")
	}
	if !validAggregationStrategy(cfg.AggregationStrategy) {
		return infraerrors.BadRequest("prompt_audit_invalid_aggregation_strategy", "提示词审计聚合策略无效")
	}
	if cfg.WorkerCount < 1 || cfg.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if cfg.QueueCapacity < 1 || cfg.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if !cfg.AllGroups && len(cfg.GroupIDs) == 0 {
		return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
	}
	if len(cfg.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	seen := make(map[string]struct{}, len(cfg.Endpoints))
	enabled := 0
	enabledThirdParty := false
	enabledTimeouts := make([]int64, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		if ep.ID == "" || ep.Name == "" {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint", "审计节点 ID 和名称不能为空")
		}
		if _, ok := seen[ep.ID]; ok {
			return infraerrors.BadRequest("prompt_audit_duplicate_endpoint", "审计节点 ID 不能重复")
		}
		seen[ep.ID] = struct{}{}
		if ep.Adapter != AdapterQwen3Guard && ep.Adapter != AdapterOpenAICompatibleQwen {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_adapter", "审计节点 adapter 无效")
		}
		if ep.Protocol != "openai_compatible" {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_protocol", "审计节点仅支持 OpenAI 兼容协议")
		}
		if _, err := NormalizeBaseURL(ep.BaseURL); err != nil {
			return err
		}
		if err := validateTimeoutMS(ep.TimeoutMS); err != nil {
			return err
		}
		if ep.Enabled {
			enabled++
			enabledTimeouts = append(enabledTimeouts, ep.TimeoutMS)
			enabledThirdParty = enabledThirdParty || ep.Adapter == AdapterOpenAICompatibleQwen
		}
	}
	if cfg.Enabled && enabled == 0 {
		return infraerrors.BadRequest("prompt_audit_endpoint_required", "启用提示词审计前至少需要启用一个审计节点")
	}
	if enabledThirdParty && strings.TrimSpace(cfg.AuditPrompt) == "" {
		return infraerrors.BadRequest("prompt_audit_audit_prompt_required", "启用第三方审核模型时审核提示词不能为空")
	}
	if cfg.Enabled && !cfg.BlockingEnabled {
		if err := validateAsyncTimeoutBudget(enabledTimeouts); err != nil {
			return err
		}
	}
	if err := validateEnforcement(cfg.Notifications, cfg.Enforcement); err != nil {
		return err
	}
	return nil
}

func validateUpdateConfigRequest(req UpdateConfigRequest) error {
	if strings.TrimSpace(req.Strategy) != StrategyOrderedAll {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 ordered_all")
	}
	if !validAggregationStrategy(strings.TrimSpace(req.AggregationStrategy)) {
		return infraerrors.BadRequest("prompt_audit_invalid_aggregation_strategy", "提示词审计聚合策略无效")
	}
	if req.WorkerCount < 1 || req.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if req.QueueCapacity < 1 || req.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if len(req.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	for _, scanner := range req.Scanners {
		if _, ok := ScannerCatalog[NormalizeCategory(scanner)]; !ok {
			return infraerrors.BadRequest("prompt_audit_invalid_scanner", "提示词审计风险分类无效")
		}
	}
	if !req.AllGroups {
		if len(req.GroupIDs) == 0 {
			return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
		}
		for _, groupID := range req.GroupIDs {
			if groupID <= 0 {
				return infraerrors.BadRequest("prompt_audit_invalid_group", "提示词审计分组 ID 无效")
			}
		}
	}
	enabledThirdParty := false
	enabledTimeouts := make([]int64, 0, len(req.Endpoints))
	for _, endpoint := range req.Endpoints {
		if err := validateTimeoutMS(endpoint.TimeoutMS); err != nil {
			return err
		}
		if endpoint.Enabled && strings.TrimSpace(endpoint.Adapter) == AdapterOpenAICompatibleQwen {
			enabledThirdParty = true
		}
		if endpoint.Enabled {
			enabledTimeouts = append(enabledTimeouts, endpoint.TimeoutMS)
		}
	}
	if enabledThirdParty && strings.TrimSpace(req.AuditPrompt) == "" {
		return infraerrors.BadRequest("prompt_audit_audit_prompt_required", "启用第三方审核模型时审核提示词不能为空")
	}
	if req.Enabled && !req.BlockingEnabled {
		if err := validateAsyncTimeoutBudget(enabledTimeouts); err != nil {
			return err
		}
	}
	return nil
}

func validAggregationStrategy(strategy string) bool {
	return strategy == AggregationAnyBlock || strategy == AggregationMajorityBlock || strategy == AggregationAllBlock
}

func validateTimeoutMS(timeoutMS int64) error {
	if timeoutMS < MinTimeoutMS || timeoutMS > maxRepresentableTimeoutMS {
		return infraerrors.BadRequest("prompt_audit_invalid_timeout", "审计节点超时必须不少于 100 毫秒且处于系统可表示范围内")
	}
	return nil
}

func timeoutDuration(timeoutMS int64) (time.Duration, error) {
	if timeoutMS <= 0 {
		timeoutMS = DefaultTimeoutMS
	}
	if timeoutMS > maxRepresentableTimeoutMS {
		return 0, fmt.Errorf("prompt audit endpoint timeout exceeds duration range")
	}
	return time.Duration(timeoutMS) * time.Millisecond, nil
}

func validateAsyncTimeoutBudget(timeouts []int64) error {
	if _, err := timeoutBudgetTTL(timeouts, promptAuditMaxAttempts); err != nil {
		return infraerrors.BadRequest(
			"prompt_audit_invalid_timeout",
			"审计节点超时总预算超出系统可表示范围",
		)
	}
	return nil
}

func validateEnforcement(notifications NotificationConfig, enforcement EnforcementConfig) error {
	emailRule := enforcement.EmailWarning
	if emailRule.Enabled && (emailRule.LookbackCount <= 0 || emailRule.ViolationThreshold <= 0 || emailRule.ViolationThreshold > emailRule.LookbackCount) {
		return infraerrors.BadRequest("prompt_audit_invalid_email_warning_rule", "邮件提醒必须满足 N > 0、M > 0 且 M <= N")
	}
	disableRule := enforcement.AccountDisable
	if disableRule.Enabled && disableRule.ViolationThreshold <= 0 {
		return infraerrors.BadRequest("prompt_audit_invalid_account_disable_rule", "账号停用阈值必须大于 0")
	}
	if !emailRule.Enabled && !disableRule.Enabled {
		return nil
	}
	adminEmail := strings.TrimSpace(notifications.AdminEmail)
	address, err := mail.ParseAddress(adminEmail)
	if err != nil || address.Address != adminEmail {
		return infraerrors.BadRequest("prompt_audit_invalid_admin_email", "启用处置规则时必须填写有效的管理员邮箱")
	}
	return nil
}

func (cfg ActiveConfig) EffectiveMode() Mode {
	if !cfg.RiskControlEnabled || !cfg.Enabled {
		return ModeOff
	}
	if cfg.BlockingEnabled {
		return ModeBlocking
	}
	return ModeAsync
}

func (cfg ActiveConfig) IncludesGroup(groupID *int64) bool {
	if cfg.AllGroups {
		return true
	}
	if groupID == nil {
		return false
	}
	i := sort.Search(len(cfg.GroupIDs), func(i int) bool { return cfg.GroupIDs[i] >= *groupID })
	return i < len(cfg.GroupIDs) && cfg.GroupIDs[i] == *groupID
}

func (cfg ActiveConfig) EnabledEndpoints() []ActiveEndpoint {
	result := make([]ActiveEndpoint, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		if ep.Enabled {
			result = append(result, ep)
		}
	}
	return result
}

// InvalidTokenEndpointIDs lists endpoints whose stored token could not be
// decrypted with the current encryption key.
func (cfg ActiveConfig) InvalidTokenEndpointIDs() []string {
	ids := make([]string, 0)
	for _, ep := range cfg.Endpoints {
		if ep.TokenInvalid {
			ids = append(ids, ep.ID)
		}
	}
	return ids
}

func PublicFromStorage(cfg storageConfig, riskControlEnabled bool, invalidTokenEndpointIDs []string) PublicConfig {
	invalid := make(map[string]struct{}, len(invalidTokenEndpointIDs))
	for _, id := range invalidTokenEndpointIDs {
		invalid[id] = struct{}{}
	}
	scanners := append([]string{}, cfg.Scanners...)
	groupIDs := append([]int64{}, cfg.GroupIDs...)
	endpoints := make([]PublicEndpoint, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		hasToken := strings.TrimSpace(ep.TokenCiphertext) != ""
		status := "missing"
		if hasToken {
			status = "configured"
			if _, ok := invalid[ep.ID]; ok {
				status = "invalid"
			}
		}
		endpoints = append(endpoints, PublicEndpoint{
			ID: ep.ID, Name: ep.Name, Adapter: ep.Adapter, Protocol: ep.Protocol, BaseURL: ep.BaseURL,
			Model: ep.Model, TimeoutMS: ep.TimeoutMS,
			Enabled: ep.Enabled, HasToken: hasToken, TokenStatus: status,
		})
	}
	active := ActiveConfig{RiskControlEnabled: riskControlEnabled, Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled}
	return PublicConfig{
		Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled, BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly, StorePassEvents: cfg.StorePassEvents,
		EffectiveMode: active.EffectiveMode(), Strategy: cfg.Strategy, AggregationStrategy: cfg.AggregationStrategy,
		AuditPrompt: cfg.AuditPrompt, WorkerCount: cfg.WorkerCount,
		QueueCapacity: cfg.QueueCapacity, Scanners: scanners, AllGroups: cfg.AllGroups,
		GroupIDs: groupIDs, Notifications: cfg.Notifications, Enforcement: cfg.Enforcement,
		Endpoints: endpoints, PromptContract: currentPromptContract(), ConfigVersion: cfg.ConfigVersion,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
	}
}

func ActiveFromStorage(cfg storageConfig, riskControlEnabled bool, encryptor SecretEncryptor) (ActiveConfig, error) {
	active := ActiveConfig{
		RiskControlEnabled: riskControlEnabled, Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled,
		BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly,
		StorePassEvents:        cfg.StorePassEvents, Strategy: cfg.Strategy, AggregationStrategy: cfg.AggregationStrategy,
		AuditPrompt: cfg.AuditPrompt, WorkerCount: cfg.WorkerCount,
		QueueCapacity: cfg.QueueCapacity, Scanners: append([]string(nil), cfg.Scanners...), AllGroups: cfg.AllGroups,
		GroupIDs: append([]int64(nil), cfg.GroupIDs...), Notifications: cfg.Notifications, Enforcement: cfg.Enforcement,
		ConfigVersion: cfg.ConfigVersion,
		UpdatedAt:     cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
		Endpoints: make([]ActiveEndpoint, 0, len(cfg.Endpoints)),
	}
	for _, ep := range cfg.Endpoints {
		token := ""
		tokenInvalid := false
		if ep.TokenCiphertext != "" {
			if encryptor == nil {
				return ActiveConfig{}, fmt.Errorf("prompt audit secret encryptor unavailable")
			}
			plain, err := encryptor.Decrypt(ep.TokenCiphertext)
			if err != nil {
				// An undecryptable token (encryption key changed or regenerated)
				// must not take the whole config down: admins would otherwise be
				// locked out of the real config version and unable to recover
				// (issue #4887). Keep the ciphertext persisted, but exclude the
				// endpoint from runtime use until the token is re-entered.
				tokenInvalid = true
			} else {
				token = plain
			}
		}
		active.Endpoints = append(active.Endpoints, ActiveEndpoint{
			ID: ep.ID, Name: ep.Name, Adapter: ep.Adapter, Protocol: ep.Protocol, BaseURL: ep.BaseURL, Model: ep.Model,
			Token: token, TimeoutMS: ep.TimeoutMS,
			Enabled: ep.Enabled && !tokenInvalid, TokenInvalid: tokenInvalid,
		})
	}
	return active, nil
}

func changeSummary(cfg storageConfig) string {
	summary := struct {
		Enabled                bool   `json:"enabled"`
		BlockingEnabled        bool   `json:"blocking_enabled"`
		BlockingLatestTurnOnly bool   `json:"blocking_latest_turn_only"`
		StorePassEvents        bool   `json:"store_pass_events"`
		AggregationStrategy    string `json:"aggregation_strategy"`
		EmailWarningEnabled    bool   `json:"email_warning_enabled"`
		AccountDisableEnabled  bool   `json:"account_disable_enabled"`
		EndpointCount          int    `json:"endpoint_count"`
		ScannerCount           int    `json:"scanner_count"`
		AllGroups              bool   `json:"all_groups"`
		GroupCount             int    `json:"group_count"`
		GroupHash              string `json:"group_hash"`
	}{
		cfg.Enabled, cfg.BlockingEnabled, cfg.BlockingLatestTurnOnly, cfg.StorePassEvents,
		cfg.AggregationStrategy, cfg.Enforcement.EmailWarning.Enabled, cfg.Enforcement.AccountDisable.Enabled,
		len(cfg.Endpoints), len(cfg.Scanners), cfg.AllGroups, len(cfg.GroupIDs), "",
	}
	rawGroups, _ := json.Marshal(cfg.GroupIDs)
	digest := sha256.Sum256(rawGroups)
	summary.GroupHash = hex.EncodeToString(digest[:])
	raw, _ := json.Marshal(summary)
	return string(raw)
}

func canonicalInt64s(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func canonicalScannerIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		id := NormalizeCategory(value)
		if _, ok := ScannerCatalog[id]; ok {
			seen[id] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for _, id := range AllScannerIDs {
		if _, ok := seen[id]; ok {
			result = append(result, id)
		}
	}
	return result
}
