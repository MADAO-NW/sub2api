package securityaudit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type scriptedScanner struct {
	mu      sync.Mutex
	calls   []string
	block   <-chan struct{}
	entered chan<- struct{}
}

func (s *scriptedScanner) Scan(ctx context.Context, request ModelScanRequest) (*NormalizedResult, error) {
	endpoint := request.Endpoint
	s.mu.Lock()
	s.calls = append(s.calls, endpoint.ID)
	s.mu.Unlock()
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: ctx.Err()}
		}
	}
	if endpoint.ID == "bad" {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
	}
	if endpoint.ID == "invalid" {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}
	return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe", ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}, GuardEndpointID: endpoint.ID}, nil
}

func guardConfig(endpoints ...ActiveEndpoint) ActiveConfig {
	for index := range endpoints {
		if endpoints[index].Adapter == "" {
			endpoints[index].Adapter = AdapterQwen3Guard
		}
	}
	return ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true,
		Strategy: StrategyOrderedAll, AggregationStrategy: AggregationAnyBlock,
		AuditPrompt: DefaultAuditPrompt, ConfigVersion: 2, Scanners: AllScannerIDs, Endpoints: endpoints,
	}
}

func TestGuardEvaluatorOrderedAllPartialFailureIsFailClosed(t *testing.T) {
	scanner := &scriptedScanner{}
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 4, 2)
	snapshot := PromptSnapshot{RequestID: "r", ScanText: "hello", PromptLength: 5}
	decision, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "bad", Enabled: true, TimeoutMS: 1000},
		ActiveEndpoint{ID: "good", Enabled: true, TimeoutMS: 1000},
	), snapshot)
	require.Error(t, err)
	require.Nil(t, decision)
	require.Equal(t, []string{"bad", "good"}, scanner.calls)
	_, err = evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "invalid", Enabled: true, TimeoutMS: 1000},
		ActiveEndpoint{ID: "good", Enabled: true, TimeoutMS: 1000},
	), snapshot)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.Equal(t, ErrorCodeInvalidResponse, guardErr.Code)
	snapshotMetrics := metrics.Snapshot()
	require.Equal(t, int64(2), snapshotMetrics.Total)
	require.Equal(t, int64(1), snapshotMetrics.Unavailable)
	require.Equal(t, int64(1), snapshotMetrics.Invalid)
}

func TestGuardEvaluatorGlobalBulkheadIsNonBlocking(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	scanner := &scriptedScanner{block: release, entered: entered}
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 1, 1)
	cfg := guardConfig(ActiveEndpoint{ID: "good", Enabled: true, TimeoutMS: 2000})
	done := make(chan error, 1)
	go func() {
		_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "one", PromptLength: 3})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first evaluation did not enter scanner")
	}
	start := time.Now()
	_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "two", PromptLength: 3})
	require.Error(t, err)
	require.Less(t, time.Since(start), 200*time.Millisecond)
	require.Equal(t, int64(1), metrics.Snapshot().BulkheadFull)
	close(release)
	require.NoError(t, <-done)
	snapshotMetrics := metrics.Snapshot()
	require.Equal(t, int64(2), snapshotMetrics.Total)
	require.Equal(t, int64(1), snapshotMetrics.Allowed)
	require.Equal(t, int64(1), snapshotMetrics.Unavailable)
}

func TestGuardEvaluatorPerNodeBulkheadIsNonBlocking(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	scanner := &scriptedScanner{block: release, entered: entered}
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 1)
	cfg := guardConfig(ActiveEndpoint{ID: "same-node", Enabled: true, TimeoutMS: 2000})
	done := make(chan error, 1)
	go func() {
		_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "one", PromptLength: 3})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first evaluation did not enter scanner")
	}
	started := time.Now()
	_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "two", PromptLength: 3})
	require.Error(t, err)
	require.Less(t, time.Since(started), 200*time.Millisecond)
	require.GreaterOrEqual(t, metrics.Snapshot().BulkheadFull, int64(1))
	close(release)
	require.NoError(t, <-done)
}

func TestGuardEvaluatorPartialModelFailureNeverAllows(t *testing.T) {
	scanner := PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		if endpoint.ID == "second" {
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Cause: errors.New("down")}
		}
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	})
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 2)
	_, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "first", Enabled: true, TimeoutMS: 1000},
		ActiveEndpoint{ID: "second", Enabled: true, TimeoutMS: 1000},
	), PromptSnapshot{ScanText: "abcdef", PromptLength: 6})
	require.Error(t, err)
}

func TestGuardEvaluatorScansCompletePromptOnce(t *testing.T) {
	latest := "请帮我编写一篇黄色小说 名字你来取"
	history := strings.Repeat("历史完整文本😀", DefaultFullPromptMaxRunes+10)
	seen := make([]string, 0, 4)
	scanner := PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, prompt string, _ []string) (*NormalizedResult, error) {
		seen = append(seen, prompt)
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	})
	evaluator := newGuardEvaluator(scanner, nil, NewAtomicMetrics(), 2, 2)
	_, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000},
	), PromptSnapshot{ScanText: latest + promptAuditPrioritySeparator + history, PromptLength: len([]rune(latest + history))})
	require.NoError(t, err)
	require.Equal(t, []string{latest + "\n\n" + history}, seen)
}

func TestGuardEvaluatorBlockStillExecutesRemainingModels(t *testing.T) {
	calls := 0
	scanner := PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		calls++
		return &NormalizedResult{
			Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
			Categories: []string{"jailbreak"}, MatchedScanners: []string{"jailbreak"},
			ScannerScores: map[string]float64{"jailbreak": 1}, ScannerEvidence: map[string]string{"jailbreak": "Jailbreak"},
		}, nil
	})
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 2)
	decision, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000},
		ActiveEndpoint{ID: "two", Enabled: true, TimeoutMS: 1000},
	), PromptSnapshot{ScanText: "abcdefghi", PromptLength: 9})
	require.NoError(t, err)
	require.Equal(t, DecisionBlock, decision.Kind)
	require.Equal(t, 2, calls)
	require.Equal(t, 2, decision.Result.ModelResults.Aggregation.EnabledModelCount)
	require.Equal(t, 1, decision.Result.ChunkTotal)
	require.Equal(t, int64(1), metrics.Snapshot().Blocked)
}

func TestGuardEvaluatorFlagIndependentTimeoutFailClosedAndContextCancel(t *testing.T) {
	t.Run("flag allows next stage", func(t *testing.T) {
		metrics := NewAtomicMetrics()
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return &NormalizedResult{Decision: EventFlag, RiskLevel: RiskMedium, Action: ActionWarn, Safety: "Controversial", Categories: []string{"violent"}, MatchedScanners: []string{"violent"}, ScannerScores: map[string]float64{"violent": .5}, ScannerEvidence: map[string]string{"violent": "Violent"}}, nil
		}), nil, metrics, 2, 2)
		decision, err := evaluator.Evaluate(context.Background(), guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000}), PromptSnapshot{ScanText: "review", PromptLength: 6})
		require.NoError(t, err)
		require.Equal(t, DecisionFlag, decision.Kind)
		require.True(t, decision.AllowNextStage)
		require.Equal(t, int64(1), metrics.Snapshot().Flagged)
	})

	t.Run("each model receives an independent timeout", func(t *testing.T) {
		calls := 0
		scanner := PromptScannerFunc(func(ctx context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
			calls++
			if endpoint.ID == "first" {
				<-ctx.Done()
				return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: ctx.Err()}
			}
			select {
			case <-time.After(60 * time.Millisecond):
				return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
			case <-ctx.Done():
				return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: ctx.Err()}
			}
		})
		metrics := NewAtomicMetrics()
		evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 2)
		started := time.Now()
		_, err := evaluator.Evaluate(context.Background(), guardConfig(
			ActiveEndpoint{ID: "first", Enabled: true, TimeoutMS: 40},
			ActiveEndpoint{ID: "second", Enabled: true, TimeoutMS: 200},
		), PromptSnapshot{ScanText: "deadline", PromptLength: 8})
		elapsed := time.Since(started)
		require.Error(t, err)
		require.Equal(t, 2, calls)
		require.Less(t, elapsed, 350*time.Millisecond)
		require.GreaterOrEqual(t, elapsed, 90*time.Millisecond)
		require.Equal(t, int64(1), metrics.Snapshot().Timeouts)
	})

	t.Run("canceled parent never allows", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		evaluator := newGuardEvaluator(PromptScannerFunc(func(ctx context.Context, _ ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
			<-ctx.Done()
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Cause: ctx.Err()}
		}), nil, NewAtomicMetrics(), 2, 2)
		decision, err := evaluator.Evaluate(ctx, guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000}), PromptSnapshot{ScanText: "cancel", PromptLength: 6})
		require.Error(t, err)
		require.Nil(t, decision)
	})
}

func TestGuardEvaluatorRecordsExistingResultOnceAndRecordFailureDoesNotChangeDecision(t *testing.T) {
	for _, recordErr := range []error{nil, errors.New("database unavailable")} {
		repo := &fakeJobRepository{recordBlockingErr: recordErr}
		metrics := NewAtomicMetrics()
		scannerCalls := 0
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			scannerCalls++
			return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}, ScannerScores: map[string]float64{"pii": 1}, ScannerEvidence: map[string]string{"pii": "PII"}}, nil
		}), repo, metrics, 2, 2)
		decision, err := evaluator.Evaluate(context.Background(), guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000}), PromptSnapshot{ScanText: "raw prompt", RedactedPreview: "raw***", PromptLength: 10})
		require.NoError(t, err)
		require.Equal(t, DecisionBlock, decision.Kind)
		require.Equal(t, 1, scannerCalls)
		require.Equal(t, 1, repo.recordBlockingCalls)
		require.Empty(t, repo.recordBlockingSnapshot.ScanText)
		require.Same(t, decision.Result, repo.recordBlockingResult)
		if recordErr != nil {
			require.Equal(t, int64(1), metrics.Snapshot().RecordFailed)
		} else {
			require.Zero(t, metrics.Snapshot().RecordFailed)
		}
	}
}

func TestGuardEvaluatorRecordsBlockingFailureJobWithModelAttempts(t *testing.T) {
	repo := &fakeJobRepository{}
	attempt := ModelCallAttempt{
		CallAttempt: 1, AttemptKind: "initial", ErrorCode: "invalid_line_count",
		ResponseBody: `{"invalid":"three lines"}`,
	}
	evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return nil, &GuardError{
			Code: ErrorCodeInvalidResponse, DetailCode: "invalid_line_count",
			Attempts: []ModelCallAttempt{attempt},
		}
	}), repo, NewAtomicMetrics(), 2, 2)

	decision, err := evaluator.Evaluate(
		context.Background(),
		guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000}),
		PromptSnapshot{ScanText: "input", RedactedPreview: "input", PromptLength: 5},
	)

	require.Error(t, err)
	require.Nil(t, decision)
	require.Zero(t, repo.recordBlockingCalls)
	require.Equal(t, 1, repo.recordBlockingFailureCalls)
	require.Equal(t, "invalid_line_count", repo.recordBlockingFailureCode)
	require.Len(t, repo.recordBlockingAttempts, 1)
	require.Equal(t, 1, repo.recordBlockingAttempts[0].ModelSequence)
	require.Equal(t, attempt.ResponseBody, repo.recordBlockingAttempts[0].ResponseBody)
}

func TestGuardEvaluatorNilResultAndScannerPanicBecomeStableFailures(t *testing.T) {
	tests := []struct {
		name string
		scan PromptScannerFunc
		code string
	}{
		{name: "nil result", scan: func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) { return nil, nil }, code: ErrorCodeInvalidResponse},
		{name: "panic", scan: func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			panic("raw prompt canary")
		}, code: ErrorCodeUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := newGuardEvaluator(tt.scan, nil, NewAtomicMetrics(), 2, 2)
			_, err := evaluator.Evaluate(context.Background(), guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000}), PromptSnapshot{ScanText: "input", PromptLength: 5})
			var guardErr *GuardError
			require.ErrorAs(t, err, &guardErr)
			require.Equal(t, tt.code, guardErr.Code)
			require.NotContains(t, err.Error(), "canary")
		})
	}
}

type PromptScannerFunc func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error)

func (f PromptScannerFunc) Scan(ctx context.Context, request ModelScanRequest) (*NormalizedResult, error) {
	return f(ctx, request.Endpoint, request.FullPrompt, request.EnabledScanners)
}
