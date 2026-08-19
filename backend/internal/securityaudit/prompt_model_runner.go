package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type beforeModelCall func(context.Context, ActiveEndpoint) error

type modelScannerCall func(context.Context, ModelScanRequest) (*NormalizedResult, error)

func runOrderedModels(
	ctx context.Context,
	cfg ActiveConfig,
	fullPrompt string,
	clock Clock,
	metrics Metrics,
	before beforeModelCall,
	scan modelScannerCall,
) (*NormalizedResult, error) {
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 || scan == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, DetailCode: "no_enabled_endpoint", Retryable: true}
	}
	if clock == nil {
		clock = realClock{}
	}
	fullPrompt = modelPromptFromScanText(fullPrompt)
	started := clock.Now()
	models := make([]ModelAuditResult, 0, len(endpoints))
	validResults := make([]*NormalizedResult, 0, len(endpoints))
	errorsByModel := make([]error, 0, len(endpoints))
	failedAttempts := make([]ModelCallAttempt, 0, len(endpoints))
	for index, endpoint := range endpoints {
		if before != nil {
			if err := before(ctx, endpoint); err != nil {
				return nil, err
			}
		}
		modelStarted := clock.Now()
		timeout, timeoutErr := timeoutDuration(endpoint.TimeoutMS)
		if timeoutErr != nil {
			return nil, &GuardError{
				Code: ErrorCodeInvalidResponse, DetailCode: "invalid_timeout", Cause: timeoutErr,
			}
		}
		modelCtx, cancel := context.WithTimeout(ctx, timeout)
		result, scanErr := scan(modelCtx, ModelScanRequest{
			Endpoint: endpoint, FullPrompt: fullPrompt, AuditPrompt: cfg.AuditPrompt,
			EnabledScanners: append([]string(nil), cfg.Scanners...),
		})
		cancel()
		if errors.Is(scanErr, ErrLeaseLost) {
			return nil, ErrLeaseLost
		}
		latencyMS := int(clock.Now().Sub(modelStarted).Milliseconds())
		detail := ModelAuditResult{
			Sequence: index + 1, EndpointID: endpoint.ID, Adapter: endpoint.Adapter,
			Model: endpoint.Model, LatencyMS: latencyMS, Categories: []string{},
		}
		if scanErr == nil && result == nil {
			scanErr = invalidGuardOutput("empty_model_result")
		}
		modelAttempts := []ModelCallAttempt{}
		if result != nil {
			modelAttempts = append(modelAttempts, result.FailedAttempts...)
			result.FailedAttempts = nil
		}
		var guardErr *GuardError
		if errors.As(scanErr, &guardErr) {
			modelAttempts = append(modelAttempts, guardErr.Attempts...)
		}
		for attemptIndex := range modelAttempts {
			modelAttempts[attemptIndex].ModelSequence = index + 1
			if modelAttempts[attemptIndex].EndpointID == "" {
				modelAttempts[attemptIndex].EndpointID = endpoint.ID
			}
			if modelAttempts[attemptIndex].Adapter == "" {
				modelAttempts[attemptIndex].Adapter = endpoint.Adapter
			}
			if modelAttempts[attemptIndex].Model == "" {
				modelAttempts[attemptIndex].Model = endpoint.Model
			}
		}
		failedAttempts = append(failedAttempts, modelAttempts...)
		if scanErr != nil {
			detail.ErrorCode = modelErrorCode(scanErr)
			models = append(models, detail)
			if metrics != nil {
				metrics.ObserveModel(detail)
			}
			errorsByModel = append(errorsByModel, scanErr)
			continue
		}
		result.LatencyMS = latencyMS
		detail.Safety = result.Safety
		detail.Categories = categoryLabels(result.Categories)
		detail.Decision = result.Decision
		detail.Action = result.Action
		detail.InputTokens = result.InputTokens
		detail.OutputTokens = result.OutputTokens
		detail.ReasoningTokens = result.ReasoningTokens
		models = append(models, detail)
		if metrics != nil {
			metrics.ObserveModel(detail)
		}
		validResults = append(validResults, result)
	}
	modelResults := ModelResults{
		Aggregation: ModelAggregation{
			Strategy: cfg.AggregationStrategy, EnabledModelCount: len(endpoints),
			BlockThreshold: CalculateBlockThreshold(cfg.AggregationStrategy, len(endpoints)),
			ConfigVersion:  cfg.ConfigVersion, PromptContractVersion: PromptContractVersion,
			AuditPromptHash: promptAuditHash(cfg.AuditPrompt), PartialFailure: len(errorsByModel) > 0,
		},
		Models: models, FailedAttempts: failedAttempts,
	}
	latency := clock.Now().Sub(started)
	if metrics != nil {
		metrics.ObserveEvaluation(modelResults.Aggregation, latency)
	}
	if len(validResults) == 0 {
		return nil, allModelsFailed(errorsByModel, failedAttempts)
	}
	aggregated := aggregateModelResults(validResults, modelResults, latency)
	return aggregated, nil
}

func modelPromptFromScanText(scanText string) string {
	return strings.ReplaceAll(scanText, promptAuditPrioritySeparator, "\n\n")
}

func CalculateBlockThreshold(strategy string, enabledModelCount int) int {
	if enabledModelCount <= 0 {
		return 0
	}
	switch strategy {
	case AggregationMajorityBlock:
		return enabledModelCount/2 + 1
	case AggregationAllBlock:
		return enabledModelCount
	default:
		return 1
	}
}

func aggregateModelResults(results []*NormalizedResult, modelResults ModelResults, latency time.Duration) *NormalizedResult {
	aggregated := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		Categories: []string{}, MatchedScanners: []string{}, ScannerScores: map[string]float64{},
		ScannerEvidence: map[string]string{}, ScannerBackend: "ordered-all-qwen-two-line",
		ScannerVersion: PromptContractVersion, PolicyID: modelResults.Aggregation.Strategy, PolicyVersion: 1,
		ChunkTotal: 1, LatencyMS: int(latency.Milliseconds()), ModelResults: modelResults,
	}
	categories := map[string]struct{}{}
	matched := map[string]struct{}{}
	blockCount := 0
	hasReview := false
	for _, result := range results {
		if result == nil {
			continue
		}
		if result.Action == ActionBlock && result.Decision == EventCritical {
			blockCount++
		}
		if result.Action == ActionWarn || result.Decision == EventFlag {
			hasReview = true
		}
		if aggregated.GuardEndpointID == "" || resultSeverity(result.Decision) > resultSeverity(aggregated.Decision) {
			aggregated.GuardEndpointID = result.GuardEndpointID
		}
		for _, category := range result.Categories {
			categories[category] = struct{}{}
		}
		for _, scanner := range result.MatchedScanners {
			matched[scanner] = struct{}{}
		}
		for scanner, score := range result.ScannerScores {
			if score > aggregated.ScannerScores[scanner] {
				aggregated.ScannerScores[scanner] = score
			}
		}
		for scanner, evidence := range result.ScannerEvidence {
			if _, exists := aggregated.ScannerEvidence[scanner]; !exists {
				aggregated.ScannerEvidence[scanner] = RedactPreview(evidence, 160)
			}
		}
	}
	aggregated.Categories = orderedScannerKeys(categories)
	aggregated.MatchedScanners = orderedScannerKeys(matched)
	threshold := modelResults.Aggregation.BlockThreshold
	switch {
	case blockCount >= threshold:
		aggregated.Decision, aggregated.RiskLevel, aggregated.Action, aggregated.Safety = EventCritical, RiskCritical, ActionBlock, "Unsafe"
	case modelResults.Aggregation.PartialFailure || blockCount > 0 || hasReview:
		aggregated.Decision, aggregated.RiskLevel, aggregated.Action, aggregated.Safety = EventFlag, RiskHigh, ActionWarn, "Controversial"
	}
	return aggregated
}

func allModelsFailed(modelErrors []error, attempts []ModelCallAttempt) error {
	retryable := false
	timeout := false
	unavailable := false
	detailCode := ""
	for _, modelErr := range modelErrors {
		var guardErr *GuardError
		if errors.As(modelErr, &guardErr) {
			retryable = retryable || guardErr.Retryable
			timeout = timeout || guardErr.Timeout
			if guardErr.Code == ErrorCodeUnavailable {
				unavailable = true
			}
		}
		currentDetail := modelErrorCode(modelErr)
		if detailCode == "" {
			detailCode = currentDetail
		} else if detailCode != currentDetail {
			detailCode = "all_models_failed"
		}
	}
	code := ErrorCodeInvalidResponse
	if retryable || unavailable {
		code = ErrorCodeUnavailable
	}
	if detailCode == "" {
		detailCode = "all_models_failed"
	}
	return &GuardError{
		Code: code, DetailCode: detailCode, Retryable: retryable, Timeout: timeout,
		Attempts: append([]ModelCallAttempt(nil), attempts...),
	}
}

func modelErrorCode(err error) string {
	var guardErr *GuardError
	if errors.As(err, &guardErr) {
		if guardErr.Timeout {
			return "model_timeout"
		}
		if guardErr.DetailCode != "" {
			return guardErr.DetailCode
		}
		if guardErr.Code != "" {
			return guardErr.Code
		}
	}
	return ErrorCodeUnavailable
}

func modelAttemptsFromError(err error) []ModelCallAttempt {
	var guardErr *GuardError
	if !errors.As(err, &guardErr) || len(guardErr.Attempts) == 0 {
		return nil
	}
	return append([]ModelCallAttempt(nil), guardErr.Attempts...)
}

func promptAuditHash(prompt string) string {
	digest := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(digest[:])
}

func categoryLabels(categoryIDs []string) []string {
	labels := make([]string, 0, len(categoryIDs))
	for _, categoryID := range categoryIDs {
		if definition, ok := ScannerCatalog[categoryID]; ok {
			labels = append(labels, definition.Label)
		}
	}
	return labels
}
