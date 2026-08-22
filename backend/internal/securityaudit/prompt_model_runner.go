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

type SegmentResultFinder interface {
	FindReusableSegments(context.Context, []SegmentReuseKey) (map[string]SegmentAuditResult, error)
}

func runOrderedModels(
	ctx context.Context,
	cfg ActiveConfig,
	snapshot PromptSnapshot,
	clock Clock,
	metrics Metrics,
	before beforeModelCall,
	scan modelScannerCall,
	segmentFinder SegmentResultFinder,
) (*NormalizedResult, error) {
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 || scan == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, DetailCode: "no_enabled_endpoint", Retryable: true}
	}
	if clock == nil {
		clock = realClock{}
	}
	fullPrompt := modelPromptFromScanText(snapshot.ScanText)
	started := clock.Now()
	models := make([]ModelAuditResult, 0, len(endpoints))
	validResults := make([]*NormalizedResult, 0, len(endpoints))
	errorsByModel := make([]error, 0, len(endpoints))
	failedAttempts := make([]ModelCallAttempt, 0, len(endpoints))
	newSegmentResults := make([]SegmentAuditResult, 0)
	segmentUses := make([]SegmentResultUse, 0)
	reusableSegments := map[string]SegmentAuditResult{}
	if !snapshot.LegacyPayload && len(snapshot.AuditSegments) > 0 && segmentFinder != nil {
		keysByID := map[string]SegmentReuseKey{}
		for _, endpoint := range endpoints {
			if endpoint.Adapter != AdapterOpenAICompatibleQwen {
				continue
			}
			for _, segment := range snapshot.AuditSegments {
				key := buildSegmentReuseKey(segment, endpoint, cfg)
				keysByID[key.LookupKey] = key
			}
		}
		keys := make([]SegmentReuseKey, 0, len(keysByID))
		for _, key := range keysByID {
			keys = append(keys, key)
		}
		if len(keys) > 0 {
			found, err := segmentFinder.FindReusableSegments(ctx, keys)
			if err != nil {
				LogWarn(EventProcessFailed, map[string]any{"status": "segment_history_lookup_fallback", "error_code": "segment_history_lookup_failed"})
			} else {
				reusableSegments = found
			}
		}
	}
	wholeModelCalls, segmentModelCalls, jointModelCalls, historyHits := 0, 0, 0, 0
	for index, endpoint := range endpoints {
		modelStarted := clock.Now()
		var result *NormalizedResult
		var scanErr error
		var modelAttempts []ModelCallAttempt
		inputMode := "whole_prompt"
		segmentTotal, endpointHistoryHits := 0, 0
		joint := (*ModelJointEvaluation)(nil)
		if endpoint.Adapter == AdapterOpenAICompatibleQwen && !snapshot.LegacyPayload && len(snapshot.AuditSegments) > 0 {
			inputMode = "role_segments"
			segmentTotal = len(snapshot.AuditSegments)
			var evaluation thirdPartyEndpointEvaluation
			evaluation, scanErr = evaluateThirdPartyEndpoint(
				ctx, cfg, endpoint, snapshot.AuditSegments, reusableSegments, before, scan,
			)
			result = evaluation.Result
			modelAttempts = evaluation.Attempts
			newSegmentResults = append(newSegmentResults, evaluation.NewResults...)
			segmentUses = append(segmentUses, evaluation.Uses...)
			endpointHistoryHits = evaluation.HistoryHits
			historyHits += evaluation.HistoryHits
			segmentModelCalls += evaluation.SegmentCalls
			jointModelCalls += evaluation.JointCalls
			joint = evaluation.Joint
		} else {
			wholeModelCalls++
			result, modelAttempts, scanErr = executeModelCall(ctx, cfg, endpoint, fullPrompt, "", before, scan)
		}
		if errors.Is(scanErr, ErrLeaseLost) {
			return nil, ErrLeaseLost
		}
		latencyMS := int(clock.Now().Sub(modelStarted).Milliseconds())
		detail := ModelAuditResult{
			Sequence: index + 1, EndpointID: endpoint.ID, Adapter: endpoint.Adapter,
			Model: endpoint.Model, LatencyMS: latencyMS, Categories: []string{}, InputMode: inputMode,
			SegmentTotal: segmentTotal, HistoryHitCount: endpointHistoryHits, JointEvaluation: joint,
		}
		if scanErr == nil && result == nil {
			scanErr = invalidGuardOutput("empty_model_result")
		}
		for attemptIndex := range modelAttempts {
			modelAttempts[attemptIndex].ModelSequence = index + 1
			modelAttempts[attemptIndex].CallAttempt = attemptIndex + 1
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
			EvaluationInputHash: snapshot.EvaluationInputHash, EvaluationContractVersion: EvaluationContractVersion,
			RoleContractHash: currentRoleContractHash(), ThirdPartySegmentTotal: len(snapshot.AuditSegments),
			SegmentHistoryHitCount: historyHits, WholeModelCallCount: wholeModelCalls,
			SegmentModelCallCount: segmentModelCalls, JointModelCallCount: jointModelCalls,
		},
		Models: models, FailedAttempts: failedAttempts,
		NewSegmentResults: newSegmentResults, SegmentUses: segmentUses,
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

type thirdPartyEndpointEvaluation struct {
	Result       *NormalizedResult
	Attempts     []ModelCallAttempt
	NewResults   []SegmentAuditResult
	Uses         []SegmentResultUse
	HistoryHits  int
	SegmentCalls int
	JointCalls   int
	Joint        *ModelJointEvaluation
}

func evaluateThirdPartyEndpoint(
	ctx context.Context,
	cfg ActiveConfig,
	endpoint ActiveEndpoint,
	segments []AuditSegment,
	reusable map[string]SegmentAuditResult,
	before beforeModelCall,
	scan modelScannerCall,
) (thirdPartyEndpointEvaluation, error) {
	evaluation := thirdPartyEndpointEvaluation{}
	resolved := make(map[string]SegmentAuditResult, len(segments))
	byOrder := make(map[int]SegmentAuditResult, len(segments))
	var inputTokens, outputTokens, reasoningTokens int
	var hasInputTokens, hasOutputTokens, hasReasoningTokens bool
	for _, segment := range segments {
		key := buildSegmentReuseKey(segment, endpoint, cfg)
		segmentResult, ok := resolved[key.LookupKey]
		if !ok {
			segmentResult, ok = reusable[key.LookupKey]
			if ok {
				evaluation.HistoryHits++
			} else {
				evaluation.SegmentCalls++
				modelResult, attempts, err := executeModelCall(
					ctx, cfg, endpoint, segmentPromptJSON(segment), rolePromptForSegment(segment), before, scan,
				)
				evaluation.Attempts = append(evaluation.Attempts, attempts...)
				if err != nil {
					return evaluation, err
				}
				addTokenUsage(&inputTokens, &hasInputTokens, modelResult.InputTokens)
				addTokenUsage(&outputTokens, &hasOutputTokens, modelResult.OutputTokens)
				addTokenUsage(&reasoningTokens, &hasReasoningTokens, modelResult.ReasoningTokens)
				segmentResult = SegmentAuditResult{
					ReuseKey: key, SourceRole: segment.SourceRole, Model: endpoint.Model,
					Decision: modelResult.Decision, Action: modelResult.Action,
					Categories: append([]string(nil), modelResult.Categories...),
				}
				evaluation.NewResults = append(evaluation.NewResults, segmentResult)
			}
			resolved[key.LookupKey] = segmentResult
		}
		byOrder[segment.Order] = segmentResult
	}

	allPass := true
	directCritical := false
	directCategories := map[string]struct{}{}
	jointSegments := make([]AuditSegment, 0, len(segments))
	jointTrigger := ""
	for _, segment := range segments {
		result := byOrder[segment.Order]
		if result.Decision != EventPass || result.Action != ActionAllow {
			allPass = false
		}
		direct := segmentDirectlyAffectsTask(segment)
		if direct && result.Decision == EventCritical && result.Action == ActionBlock {
			directCritical = true
			for _, category := range result.Categories {
				directCategories[category] = struct{}{}
			}
		}
		if direct || result.Decision != EventPass || result.Action != ActionAllow {
			jointSegments = append(jointSegments, segment)
		}
		if direct && result.Decision == EventFlag {
			jointTrigger = "direct_flag"
		} else if !direct && result.Decision != EventPass && jointTrigger == "" {
			jointTrigger = "context_risk"
		}
		if direct || result.Decision != EventPass || result.Action != ActionAllow {
			evaluation.Uses = append(evaluation.Uses, SegmentResultUse{
				EndpointID: endpoint.ID, SegmentOrder: segment.Order, SourceRole: segment.SourceRole,
				PolicyRole: segment.PolicyRole, TurnScope: segment.TurnScope, LookupKey: result.ReuseKey.LookupKey,
				SourceSegmentResultID: result.ID,
			})
		}
	}

	switch {
	case allPass:
		evaluation.Result = normalizedEndpointResult(endpoint.ID, EventPass, ActionAllow, nil)
	case directCritical:
		evaluation.Result = normalizedEndpointResult(endpoint.ID, EventCritical, ActionBlock, orderedScannerKeys(directCategories))
	default:
		evaluation.JointCalls = 1
		evaluation.Joint = &ModelJointEvaluation{Executed: true, Trigger: jointTrigger}
		jointResult, attempts, err := executeModelCall(
			ctx, cfg, endpoint, jointPromptJSON(jointSegments), roleJointRule, before, scan,
		)
		evaluation.Attempts = append(evaluation.Attempts, attempts...)
		if err != nil {
			return evaluation, err
		}
		addTokenUsage(&inputTokens, &hasInputTokens, jointResult.InputTokens)
		addTokenUsage(&outputTokens, &hasOutputTokens, jointResult.OutputTokens)
		addTokenUsage(&reasoningTokens, &hasReasoningTokens, jointResult.ReasoningTokens)
		evaluation.Result = jointResult
	}
	if evaluation.Result != nil {
		evaluation.Result.GuardEndpointID = endpoint.ID
		evaluation.Result.ChunkTotal = len(segments)
		evaluation.Result.InputTokens = tokenPointer(inputTokens, hasInputTokens)
		evaluation.Result.OutputTokens = tokenPointer(outputTokens, hasOutputTokens)
		evaluation.Result.ReasoningTokens = tokenPointer(reasoningTokens, hasReasoningTokens)
	}
	return evaluation, nil
}

func executeModelCall(
	ctx context.Context,
	cfg ActiveConfig,
	endpoint ActiveEndpoint,
	prompt string,
	rolePrompt string,
	before beforeModelCall,
	scan modelScannerCall,
) (*NormalizedResult, []ModelCallAttempt, error) {
	if before != nil {
		if err := before(ctx, endpoint); err != nil {
			return nil, nil, err
		}
	}
	timeout, err := timeoutDuration(endpoint.TimeoutMS)
	if err != nil {
		return nil, nil, &GuardError{Code: ErrorCodeInvalidResponse, DetailCode: "invalid_timeout", Cause: err}
	}
	modelCtx, cancel := context.WithTimeout(ctx, timeout)
	result, scanErr := scan(modelCtx, ModelScanRequest{
		Endpoint: endpoint, FullPrompt: prompt, AuditPrompt: cfg.AuditPrompt, RolePrompt: rolePrompt,
		EnabledScanners: append([]string(nil), cfg.Scanners...),
	})
	cancel()
	if scanErr == nil && result == nil {
		scanErr = invalidGuardOutput("empty_model_result")
	}
	attempts := make([]ModelCallAttempt, 0, 2)
	if result != nil {
		attempts = append(attempts, result.FailedAttempts...)
		result.FailedAttempts = nil
	}
	var guardErr *GuardError
	if errors.As(scanErr, &guardErr) {
		attempts = append(attempts, guardErr.Attempts...)
	}
	return result, attempts, scanErr
}

func normalizedEndpointResult(endpointID string, decision EventDecision, action Action, categories []string) *NormalizedResult {
	riskLevel, safety := RiskLow, "Safe"
	if decision == EventFlag {
		riskLevel, safety = RiskHigh, "Controversial"
	}
	if decision == EventCritical {
		riskLevel, safety = RiskCritical, "Unsafe"
	}
	return &NormalizedResult{
		Decision: decision, RiskLevel: riskLevel, Action: action, Safety: safety,
		Categories: append([]string(nil), categories...), MatchedScanners: append([]string(nil), categories...),
		ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{},
		ScannerBackend: "third-party-role-segments", ScannerVersion: PromptContractVersion,
		GuardEndpointID: endpointID, ChunkTotal: 1,
	}
}

func addTokenUsage(total *int, present *bool, value *int) {
	if value == nil {
		return
	}
	*total += *value
	*present = true
}

func tokenPointer(total int, present bool) *int {
	if !present {
		return nil
	}
	return &total
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
