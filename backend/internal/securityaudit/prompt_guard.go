package securityaudit

import (
	"context"
	"errors"
	"sync"
	"time"

	appservice "github.com/Wei-Shaw/sub2api/internal/service"
)

type GuardEvaluator struct {
	scanner PromptScanner
	repo    JobRepository
	metrics Metrics
	clock   Clock
	cache   appservice.APIKeyAuthCacheInvalidator

	global       chan struct{}
	perNodeLimit int
	nodeMu       sync.Mutex
	nodes        map[string]chan struct{}
}

func NewGuardEvaluator(
	scanner PromptScanner,
	repo JobRepository,
	metrics Metrics,
	cache ...appservice.APIKeyAuthCacheInvalidator,
) *GuardEvaluator {
	evaluator := newGuardEvaluator(scanner, repo, metrics, 64, 16)
	if len(cache) > 0 {
		evaluator.cache = cache[0]
	}
	return evaluator
}

func newGuardEvaluator(scanner PromptScanner, repo JobRepository, metrics Metrics, globalLimit, perNodeLimit int) *GuardEvaluator {
	if globalLimit < 1 {
		globalLimit = 64
	}
	if perNodeLimit < 1 {
		perNodeLimit = 16
	}
	return &GuardEvaluator{scanner: scanner, repo: repo, metrics: metrics, clock: realClock{},
		global: make(chan struct{}, globalLimit), perNodeLimit: perNodeLimit, nodes: map[string]chan struct{}{}}
}

func (g *GuardEvaluator) Evaluate(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot) (*PromptDecision, error) {
	if g == nil || g.scanner == nil {
		if g != nil && g.metrics != nil {
			g.metrics.Observe(DecisionUnavailable, 0)
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", 0)
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	start := g.clock.Now()
	baseFields := snapshotLogFields(snapshot)
	baseFields["config_version"] = cfg.ConfigVersion
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 {
		if g.metrics != nil {
			g.metrics.Observe(DecisionUnavailable, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	select {
	case g.global <- struct{}{}:
		defer func() { <-g.global }()
	default:
		if g.metrics != nil {
			g.metrics.IncBulkheadFull()
			g.metrics.Observe(DecisionUnavailable, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	if snapshot.ScanText == "" {
		if g.metrics != nil {
			g.metrics.Observe(DecisionAllow, g.clock.Now().Sub(start))
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	LogInfo(EventEvaluationStarted, mergeLogFields(baseFields, map[string]any{
		"enabled_model_count": len(endpoints),
		"block_threshold":     CalculateBlockThreshold(cfg.AggregationStrategy, len(endpoints)),
		"status":              "started",
	}))
	aggregated, err := runOrderedModels(ctx, cfg, snapshot.ScanText, g.clock, g.metrics, nil, g.scanModel)
	if err != nil {
		kind := DecisionUnavailable
		if guardErrorCode(err) == ErrorCodeInvalidResponse {
			kind = DecisionInvalid
		}
		if g.metrics != nil {
			g.metrics.Observe(kind, g.clock.Now().Sub(start))
			var guardErr *GuardError
			if errors.As(err, &guardErr) && guardErr.Timeout {
				g.metrics.IncTimeout()
			}
		}
		logGuardFailure(snapshot, cfg, kind, guardErrorCode(err), "", g.clock.Now().Sub(start))
		if g.repo != nil {
			if recordErr := g.repo.RecordBlockingFailure(
				ctx, snapshot.Redacted(), cfg, modelErrorCode(err), modelAttemptsFromError(err),
			); recordErr != nil {
				if g.metrics != nil {
					g.metrics.IncRecordFailed()
				}
				LogWarn(EventResultRecordFailed, mergeLogFields(baseFields, map[string]any{
					"error_code": "result_record_failed", "stage": snapshot.Stage, "status": "failed",
				}))
			}
		}
		return nil, err
	}
	kind := DecisionAllow
	if aggregated.Action == ActionWarn {
		kind = DecisionFlag
	}
	if aggregated.Action == ActionBlock {
		kind = DecisionBlock
	}
	decision := &PromptDecision{Kind: kind, Result: aggregated, AllowNextStage: kind == DecisionAllow || kind == DecisionFlag}
	if kind == DecisionBlock {
		decision.ErrorCode = ErrorCodeBlocked
	}
	LogInfo(EventChunksAggregated, mergeLogFields(baseFields, map[string]any{
		"decision":   kind,
		"risk_level": aggregated.RiskLevel, "action": aggregated.Action,
		"enabled_model_count": aggregated.ModelResults.Aggregation.EnabledModelCount,
		"block_threshold":     aggregated.ModelResults.Aggregation.BlockThreshold,
		"partial_failure":     aggregated.ModelResults.Aggregation.PartialFailure,
		"latency_ms":          aggregated.LatencyMS, "guard_endpoint_id": aggregated.GuardEndpointID, "stage": snapshot.Stage,
		"status": "completed",
	}))
	if g.repo != nil {
		completion, recordErr := g.repo.RecordBlocking(ctx, snapshot.Redacted(), cfg, aggregated)
		if recordErr != nil {
			if g.metrics != nil {
				g.metrics.IncRecordFailed()
			}
			LogWarn(EventResultRecordFailed, mergeLogFields(baseFields, map[string]any{
				"decision": kind, "error_code": "result_record_failed", "stage": snapshot.Stage,
				"status": "failed",
			}))
		} else if completion != nil && completion.DisabledUserID > 0 && g.cache != nil {
			g.cache.InvalidateAuthCacheByUserID(ctx, completion.DisabledUserID)
		}
	}
	if aggregated.ModelResults.Aggregation.PartialFailure && kind != DecisionBlock {
		err := partialFailureError(aggregated.ModelResults)
		if g.metrics != nil {
			failureKind := DecisionUnavailable
			if guardErrorCode(err) == ErrorCodeInvalidResponse {
				failureKind = DecisionInvalid
			}
			g.metrics.Observe(failureKind, g.clock.Now().Sub(start))
			if modelResultsHaveError(aggregated.ModelResults, "model_timeout") {
				g.metrics.IncTimeout()
			}
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, guardErrorCode(err), aggregated.GuardEndpointID, g.clock.Now().Sub(start))
		return nil, err
	}
	if g.metrics != nil {
		g.metrics.Observe(kind, g.clock.Now().Sub(start))
	}
	if kind == DecisionBlock {
		LogWarn(EventGuardBlocked, mergeLogFields(baseFields, map[string]any{
			"guard_endpoint_id": aggregated.GuardEndpointID,
			"decision":          kind, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "chunk_total": aggregated.ChunkTotal,
			"latency_ms": aggregated.LatencyMS, "status": "blocked", "error_code": ErrorCodeBlocked,
			"stage": snapshot.Stage, "upstream_dispatched": false, "billing_preconsumed": false,
		}))
	} else {
		LogInfo(EventGuardAllowed, mergeLogFields(baseFields, map[string]any{
			"decision": kind, "risk_level": aggregated.RiskLevel, "action": aggregated.Action,
			"guard_endpoint_id": aggregated.GuardEndpointID, "chunk_total": aggregated.ChunkTotal,
			"latency_ms": aggregated.LatencyMS, "stage": snapshot.Stage, "status": "allowed",
		}))
	}
	return decision, nil
}

func logGuardFailure(snapshot PromptSnapshot, cfg ActiveConfig, kind DecisionKind, code, guardEndpointID string, latency time.Duration) {
	fields := snapshotLogFields(snapshot)
	fields["config_version"] = cfg.ConfigVersion
	LogWarn(EventGuardFailed, mergeLogFields(fields, map[string]any{
		"decision": kind, "guard_endpoint_id": guardEndpointID, "latency_ms": latency.Milliseconds(),
		"status": "failed", "error_code": code, "upstream_dispatched": false, "billing_preconsumed": false,
	}))
}

func (g *GuardEvaluator) scanModel(ctx context.Context, request ModelScanRequest) (*NormalizedResult, error) {
	semaphore := g.nodeSemaphore(request.Endpoint.ID)
	select {
	case semaphore <- struct{}{}:
		defer func() { <-semaphore }()
	case <-ctx.Done():
		return nil, &GuardError{
			Code: ErrorCodeUnavailable, DetailCode: "model_timeout", Retryable: true,
			Timeout: errors.Is(ctx.Err(), context.DeadlineExceeded), Cause: ctx.Err(),
		}
	default:
		if g.metrics != nil {
			g.metrics.IncBulkheadFull()
		}
		return nil, &GuardError{Code: ErrorCodeUnavailable, DetailCode: "model_bulkhead_full", Retryable: true}
	}
	return callPromptScanner(ctx, g.scanner, request)
}

func callPromptScanner(ctx context.Context, scanner PromptScanner, request ModelScanRequest) (result *NormalizedResult, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = &GuardError{Code: ErrorCodeUnavailable, Retryable: false}
		}
	}()
	return scanner.Scan(ctx, request)
}

func (g *GuardEvaluator) nodeSemaphore(id string) chan struct{} {
	g.nodeMu.Lock()
	defer g.nodeMu.Unlock()
	semaphore := g.nodes[id]
	if semaphore == nil {
		semaphore = make(chan struct{}, g.perNodeLimit)
		g.nodes[id] = semaphore
	}
	return semaphore
}

func guardErrorCode(err error) string {
	var guardErr *GuardError
	if errors.As(err, &guardErr) && guardErr.Code != "" {
		return guardErr.Code
	}
	return ErrorCodeUnavailable
}

func partialFailureError(results ModelResults) error {
	code := ErrorCodeUnavailable
	for _, model := range results.Models {
		if model.ErrorCode == ErrorCodeInvalidResponse ||
			model.ErrorCode == "invalid_line_count" || model.ErrorCode == "invalid_safety" ||
			model.ErrorCode == "invalid_categories" || model.ErrorCode == "invalid_category_order" ||
			model.ErrorCode == "invalid_safety_category_pair" || model.ErrorCode == "unexpected_output_wrapper" {
			code = ErrorCodeInvalidResponse
			break
		}
	}
	return &GuardError{Code: code, DetailCode: "partial_model_failure", Retryable: code == ErrorCodeUnavailable}
}

func modelResultsHaveError(results ModelResults, code string) bool {
	for _, model := range results.Models {
		if model.ErrorCode == code {
			return true
		}
	}
	return false
}

func pointerLogID(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
