package securityaudit

import (
	"context"
	"time"
)

const (
	SettingKeyPromptAuditConfig = "prompt_audit_config"
	SettingKeyRiskControl       = "risk_control_enabled"

	ConfigInvalidationChannel = "sub2api:prompt_guard:config:invalidate"
	PayloadKeyPrefix          = "sub2api:prompt_audit:payload:"

	ErrorCodeBlocked               = "prompt_guard_blocked"
	ErrorCodeUnavailable           = "prompt_guard_unavailable"
	ErrorCodeInvalidResponse       = "prompt_guard_invalid_response"
	ErrorCodeConfigConflict        = "prompt_audit_config_conflict"
	ErrorCodeConfigUnavailable     = "prompt_audit_config_unavailable"
	ErrorCodeEncryptionKeyRequired = "prompt_audit_encryption_key_required"
	ErrorCodeRequiresEnabled       = "prompt_guard_requires_audit_enabled"

	DefaultGuardModel = "sileader/qwen3guard:0.6b"

	// EvaluationContractVersion 隔离角色分段、最终任务意图裁决和模型聚合语义不同的历史结果。
	EvaluationContractVersion = "qwen-whole-thirdparty-role-v2"
)

type Mode string

const (
	ModeOff      Mode = "off"
	ModeAsync    Mode = "async_audit"
	ModeBlocking Mode = "blocking"
)

type DecisionKind string

const (
	DecisionAllow       DecisionKind = "allow"
	DecisionFlag        DecisionKind = "flag"
	DecisionBlock       DecisionKind = "block"
	DecisionUnavailable DecisionKind = "unavailable"
	DecisionInvalid     DecisionKind = "invalid"
)

type EventDecision string

const (
	EventPass     EventDecision = "pass"
	EventFlag     EventDecision = "flag"
	EventCritical EventDecision = "critical"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Action string

const (
	ActionAllow Action = "Allow"
	ActionWarn  Action = "Warn"
	ActionBlock Action = "Block"
)

type Request struct {
	RequestID  string
	UserID     int64
	Username   string
	UserEmail  string
	APIKeyID   int64
	APIKeyName string
	GroupID    *int64
	GroupName  string
	Provider   string
	Endpoint   string
	Protocol   string
	Model      string
	Body       []byte
	Stage      string
}

func (r Request) Clone() Request {
	r.Body = append([]byte(nil), r.Body...)
	if r.GroupID != nil {
		id := *r.GroupID
		r.GroupID = &id
	}
	return r
}

type PromptSnapshot struct {
	RequestID           string `json:"request_id"`
	UserID              int64  `json:"user_id"`
	UsernameSnapshot    string `json:"username"`
	UserEmailSnapshot   string `json:"user_email"`
	APIKeyID            int64  `json:"api_key_id"`
	APIKeyNameSnapshot  string `json:"api_key_name"`
	GroupID             *int64 `json:"group_id,omitempty"`
	GroupName           string `json:"group_name"`
	Provider            string `json:"provider"`
	Endpoint            string `json:"endpoint"`
	Protocol            string `json:"protocol"`
	Model               string `json:"model"`
	PromptHash          string `json:"prompt_hash"`
	EvaluationInputHash string `json:"evaluation_input_hash,omitempty"`
	RedactedPreview     string `json:"redacted_preview"`
	FullPrompt          string `json:"full_prompt"`
	PromptLength        int    `json:"prompt_length"`
	MessageCount        int    `json:"message_count"`
	Stage               string `json:"stage"`

	ScanText        string                 `json:"-"`
	AuditSegments   []AuditSegment         `json:"-"`
	PayloadSegments []PromptPayloadSegment `json:"-"`
	LegacyPayload   bool                   `json:"-"`
}

func (s PromptSnapshot) Redacted() PromptSnapshot {
	s.ScanText = ""
	s.AuditSegments = nil
	s.PayloadSegments = nil
	return s
}

type AuditSegment struct {
	Order       int
	SourceRole  string
	PolicyRole  string
	TurnScope   string
	Content     string
	ContentHash string
}

type PromptPayloadSegment struct {
	MessageOrder int    `json:"message_order"`
	SourceRole   string `json:"source_role"`
	Text         string `json:"text"`
}

type NormalizedResult struct {
	Decision          EventDecision      `json:"decision"`
	RiskLevel         RiskLevel          `json:"risk_level"`
	Action            Action             `json:"action"`
	Safety            string             `json:"safety"`
	Categories        []string           `json:"categories"`
	MatchedScanners   []string           `json:"matched_scanners"`
	ScannerScores     map[string]float64 `json:"scanner_scores"`
	ScannerEvidence   map[string]string  `json:"scanner_evidence"`
	ScannerBackend    string             `json:"scanner_backend"`
	ScannerVersion    string             `json:"scanner_version"`
	GuardEndpointID   string             `json:"guard_endpoint_id"`
	PolicyID          string             `json:"policy_id"`
	PolicyVersion     int                `json:"policy_version"`
	ChunkTotal        int                `json:"chunk_total"`
	LatencyMS         int                `json:"latency_ms"`
	InputTokens       *int               `json:"input_tokens,omitempty"`
	OutputTokens      *int               `json:"output_tokens,omitempty"`
	ReasoningTokens   *int               `json:"reasoning_tokens,omitempty"`
	UnknownCategories []string           `json:"unknown_categories,omitempty"`
	ModelResults      ModelResults       `json:"-"`
	FailedAttempts    []ModelCallAttempt `json:"-"`
}

type ModelAggregation struct {
	Strategy                  string `json:"strategy"`
	EnabledModelCount         int    `json:"enabled_model_count"`
	BlockThreshold            int    `json:"block_threshold"`
	ConfigVersion             int64  `json:"config_version"`
	PromptContractVersion     string `json:"prompt_contract_version"`
	AuditPromptHash           string `json:"audit_prompt_hash"`
	PartialFailure            bool   `json:"partial_failure"`
	ReusedFromOutcomeID       *int64 `json:"reused_from_outcome_id,omitempty"`
	EvaluationInputHash       string `json:"evaluation_input_hash,omitempty"`
	EvaluationContractVersion string `json:"evaluation_contract_version,omitempty"`
	RoleContractHash          string `json:"role_contract_hash,omitempty"`
	ThirdPartySegmentTotal    int    `json:"third_party_segment_total,omitempty"`
	SegmentHistoryHitCount    int    `json:"segment_history_hit_count,omitempty"`
	WholeModelCallCount       int    `json:"whole_model_call_count,omitempty"`
	SegmentModelCallCount     int    `json:"segment_model_call_count,omitempty"`
	JointModelCallCount       int    `json:"joint_model_call_count,omitempty"`
}

type ModelJointEvaluation struct {
	Executed bool   `json:"executed"`
	Trigger  string `json:"trigger,omitempty"`
}

type ModelAuditResult struct {
	Sequence        int                   `json:"sequence"`
	EndpointID      string                `json:"endpoint_id"`
	Adapter         string                `json:"adapter"`
	Model           string                `json:"model"`
	Safety          string                `json:"safety"`
	Categories      []string              `json:"categories"`
	Decision        EventDecision         `json:"decision,omitempty"`
	Action          Action                `json:"action,omitempty"`
	LatencyMS       int                   `json:"latency_ms"`
	InputTokens     *int                  `json:"input_tokens,omitempty"`
	OutputTokens    *int                  `json:"output_tokens,omitempty"`
	ReasoningTokens *int                  `json:"reasoning_tokens,omitempty"`
	ErrorCode       string                `json:"error_code"`
	InputMode       string                `json:"input_mode,omitempty"`
	SegmentTotal    int                   `json:"segment_total,omitempty"`
	HistoryHitCount int                   `json:"history_hit_count,omitempty"`
	JointEvaluation *ModelJointEvaluation `json:"joint_evaluation,omitempty"`
}

type ModelCallAttempt struct {
	ModelSequence     int
	CallAttempt       int
	AttemptKind       string
	EndpointID        string
	Adapter           string
	Model             string
	HTTPStatus        int
	LatencyMS         int
	InputTokens       *int
	OutputTokens      *int
	ReasoningTokens   *int
	ErrorCode         string
	Retryable         bool
	ResponseBody      string
	ResponseSHA256    string
	ResponseBytes     int
	ResponseTruncated bool
}

type ModelResults struct {
	Aggregation       ModelAggregation     `json:"aggregation"`
	Models            []ModelAuditResult   `json:"models"`
	FailedAttempts    []ModelCallAttempt   `json:"-"`
	NewSegmentResults []SegmentAuditResult `json:"-"`
	SegmentUses       []SegmentResultUse   `json:"-"`
}

type SegmentReuseKey struct {
	LookupKey                 string
	ContentHash               string
	PolicyRole                string
	TurnScope                 string
	EndpointID                string
	Adapter                   string
	ConfigVersion             int64
	AuditPromptHash           string
	RolePromptHash            string
	EvaluationContractVersion string
	PromptContractVersion     string
}

type SegmentAuditResult struct {
	ID         int64
	ReuseKey   SegmentReuseKey
	SourceRole string
	Model      string
	Decision   EventDecision
	Action     Action
	Categories []string
}

type SegmentResultUse struct {
	EndpointID            string
	SegmentOrder          int
	SourceRole            string
	PolicyRole            string
	TurnScope             string
	LookupKey             string
	SourceSegmentResultID int64
}

type PromptAuditSegmentDetail struct {
	EndpointID                string        `json:"endpoint_id"`
	SegmentOrder              int           `json:"segment_order"`
	SourceRole                string        `json:"source_role"`
	PolicyRole                string        `json:"policy_role"`
	TurnScope                 string        `json:"turn_scope"`
	SourceSegmentResultID     int64         `json:"source_segment_result_id"`
	ReusedFromSegmentResultID *int64        `json:"reused_from_segment_result_id,omitempty"`
	Decision                  EventDecision `json:"decision"`
	Action                    Action        `json:"action"`
	Categories                []string      `json:"categories"`
}

type PromptDecision struct {
	Kind           DecisionKind      `json:"kind"`
	ErrorCode      string            `json:"error_code,omitempty"`
	Result         *NormalizedResult `json:"result,omitempty"`
	AllowNextStage bool              `json:"allow_next_stage"`
}

type LegacyDecision struct {
	Allowed    bool   `json:"allowed"`
	Blocked    bool   `json:"blocked"`
	Flagged    bool   `json:"flagged"`
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
	ErrorCode  string `json:"error_code"`
	Action     string `json:"action"`
}

type Decision struct {
	Kind           DecisionKind    `json:"kind"`
	HTTPStatus     int             `json:"http_status"`
	ErrorCode      string          `json:"error_code,omitempty"`
	ClientMessage  string          `json:"client_message,omitempty"`
	Legacy         *LegacyDecision `json:"legacy,omitempty"`
	Prompt         *PromptDecision `json:"prompt,omitempty"`
	AllowNextStage bool            `json:"allow_next_stage"`
}

type IssueSummary struct {
	Category      string  `json:"category"`
	ScannerID     string  `json:"scanner_id"`
	Title         string  `json:"title"`
	Description   string  `json:"description"`
	Severity      string  `json:"severity"`
	SeverityLabel string  `json:"severity_label"`
	Action        string  `json:"action"`
	ActionLabel   string  `json:"action_label"`
	Code          string  `json:"code"`
	Score         float64 `json:"score"`
	Evidence      string  `json:"evidence"`
	EvidenceHash  string  `json:"evidence_hash"`
	StartRune     *int    `json:"start_rune,omitempty"`
	EndRune       *int    `json:"end_rune,omitempty"`
}

type ProbeResult struct {
	OK           bool      `json:"ok"`
	Status       string    `json:"status"`
	ErrorCode    string    `json:"error_code,omitempty"`
	Message      string    `json:"message"`
	LatencyMS    int       `json:"latency_ms"`
	HTTPStatus   int       `json:"http_status"`
	Retryable    bool      `json:"retryable"`
	CheckedAt    time.Time `json:"checked_at"`
	TokenApplied bool      `json:"token_applied"`
}

type GuardMetricsSnapshot struct {
	Total        int64 `json:"total"`
	Allowed      int64 `json:"allowed"`
	Flagged      int64 `json:"flagged"`
	Blocked      int64 `json:"blocked"`
	Unavailable  int64 `json:"unavailable"`
	Invalid      int64 `json:"invalid"`
	Timeouts     int64 `json:"timeouts"`
	Failovers    int64 `json:"failovers"`
	BulkheadFull int64 `json:"bulkhead_full"`
	RecordFailed int64 `json:"record_failed"`
	LatencyCount int64 `json:"latency_count"`
	LatencyAvgMS int64 `json:"latency_avg_ms"`
	LatencyP50MS int64 `json:"latency_p50_ms"`
	LatencyP95MS int64 `json:"latency_p95_ms"`
	LatencyP99MS int64 `json:"latency_p99_ms"`
	LatencyMaxMS int64 `json:"latency_max_ms"`
}

type AuditMetricsSnapshot struct {
	Enqueued int64 `json:"enqueued"`
	Dropped  int64 `json:"dropped"`
}

type EndpointMetricsSnapshot struct {
	Requests        int64 `json:"requests"`
	Pass            int64 `json:"pass"`
	Flag            int64 `json:"flag"`
	Critical        int64 `json:"critical"`
	Errors          int64 `json:"errors"`
	InputTokens     int64 `json:"input_tokens"`
	OutputTokens    int64 `json:"output_tokens"`
	ReasoningTokens int64 `json:"reasoning_tokens"`
	LatencyP50MS    int64 `json:"latency_p50_ms"`
	LatencyP95MS    int64 `json:"latency_p95_ms"`
}

type EvaluationMetricsSnapshot struct {
	Total          int64 `json:"total"`
	PartialFailure int64 `json:"partial_failure"`
	LatencyP50MS   int64 `json:"latency_p50_ms"`
	LatencyP95MS   int64 `json:"latency_p95_ms"`
}

type RuntimeModelSnapshot struct {
	Sequence  int                     `json:"sequence"`
	ID        string                  `json:"id"`
	Name      string                  `json:"name"`
	Adapter   string                  `json:"adapter"`
	Model     string                  `json:"model"`
	Enabled   bool                    `json:"enabled"`
	TimeoutMS int64                   `json:"timeout_ms"`
	Probe     *ProbeResult            `json:"probe,omitempty"`
	Metrics   EndpointMetricsSnapshot `json:"metrics"`
}

type EnforcementRuntimeStats struct {
	OutcomesTotal     int64 `json:"outcomes_total"`
	ViolationsTotal   int64 `json:"violations_total"`
	WarningsTotal     int64 `json:"warnings_total"`
	DisabledTotal     int64 `json:"disabled_total"`
	MailFailuresTotal int64 `json:"mail_failures_total"`
}

type QueueStats struct {
	Staging    int64 `json:"staging"`
	Queued     int64 `json:"queued"`
	Processing int64 `json:"processing"`
	Retry      int64 `json:"retry"`
	Done       int64 `json:"done"`
	Failed     int64 `json:"failed"`
	Active     int64 `json:"active"`
}

type RuntimeSnapshot struct {
	ProcessStatus         string                    `json:"process_status"`
	EffectiveMode         Mode                      `json:"effective_mode"`
	ExpectedConfigVersion int64                     `json:"expected_config_version"`
	ActiveConfigVersion   int64                     `json:"active_config_version"`
	ConfigLoadedAt        *time.Time                `json:"config_loaded_at,omitempty"`
	ConfigLoadError       string                    `json:"config_load_error,omitempty"`
	WorkerTotal           int                       `json:"worker_total"`
	WorkerActive          int64                     `json:"worker_active"`
	WorkerHeartbeatAt     *time.Time                `json:"worker_heartbeat_at,omitempty"`
	QueueCapacity         int                       `json:"queue_capacity"`
	Queue                 QueueStats                `json:"queue"`
	ProcessedTotal        int64                     `json:"processed_total"`
	FailedTotal           int64                     `json:"failed_total"`
	EnqueuedTotal         int64                     `json:"enqueued_total"`
	DroppedTotal          int64                     `json:"dropped_total"`
	LastProcessedAt       *time.Time                `json:"last_processed_at,omitempty"`
	LastErrorCode         string                    `json:"last_error_code,omitempty"`
	LastErrorMessage      string                    `json:"last_error_message,omitempty"`
	DatabaseStatus        string                    `json:"database_status"`
	RedisStatus           string                    `json:"redis_status"`
	Endpoints             map[string]ProbeResult    `json:"endpoints"`
	Models                []RuntimeModelSnapshot    `json:"models"`
	AggregationStrategy   string                    `json:"aggregation_strategy"`
	EnabledModelCount     int                       `json:"enabled_model_count"`
	BlockThreshold        int                       `json:"block_threshold"`
	PromptContractVersion string                    `json:"prompt_contract_version"`
	AuditPromptHash       string                    `json:"audit_prompt_hash"`
	GuardMetrics          GuardMetricsSnapshot      `json:"guard_metrics"`
	EvaluationMetrics     EvaluationMetricsSnapshot `json:"evaluation_metrics"`
	Enforcement           EnforcementRuntimeStats   `json:"enforcement"`
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type Metrics interface {
	Snapshot() GuardMetricsSnapshot
	AuditSnapshot() AuditMetricsSnapshot
	Observe(kind DecisionKind, latency time.Duration)
	IncEnqueued()
	IncDropped()
	IncTimeout()
	IncFailover()
	IncBulkheadFull()
	IncRecordFailed()
	ObserveModel(result ModelAuditResult)
	ObserveEvaluation(aggregation ModelAggregation, latency time.Duration)
	ModelSnapshot(endpointIDs []string) map[string]EndpointMetricsSnapshot
	EvaluationSnapshot() EvaluationMetricsSnapshot
}

type PromptScanner interface {
	Scan(ctx context.Context, request ModelScanRequest) (*NormalizedResult, error)
}

type ModelScanRequest struct {
	Endpoint        ActiveEndpoint
	FullPrompt      string
	AuditPrompt     string
	RolePrompt      string
	EnabledScanners []string
}
