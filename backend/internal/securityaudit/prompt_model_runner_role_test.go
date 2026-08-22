package securityaudit

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type segmentFinderFunc func(context.Context, []SegmentReuseKey) (map[string]SegmentAuditResult, error)

func (f segmentFinderFunc) FindReusableSegments(ctx context.Context, keys []SegmentReuseKey) (map[string]SegmentAuditResult, error) {
	return f(ctx, keys)
}

func roleRunnerSnapshot() PromptSnapshot {
	segments := []AuditSegment{
		{Order: 1, SourceRole: "system", PolicyRole: "system", TurnScope: "active", Content: "system policy", ContentHash: promptAuditHash("system policy")},
		{Order: 2, SourceRole: "assistant", PolicyRole: "assistant", TurnScope: "historical", Content: "previous answer", ContentHash: promptAuditHash("previous answer")},
		{Order: 3, SourceRole: "user", PolicyRole: "user", TurnScope: "current", Content: "current request", ContentHash: promptAuditHash("current request")},
	}
	return PromptSnapshot{
		ScanText:   "current request" + promptAuditPrioritySeparator + "system policy\n\nprevious answer",
		PromptHash: promptAuditHash("whole"), EvaluationInputHash: hashEvaluationInput(segments),
		AuditSegments: segments,
	}
}

func TestRunOrderedModelsKeepsQwenWholeAndThirdPartyAllPassWithoutJointCall(t *testing.T) {
	cfg := guardConfig(
		ActiveEndpoint{ID: "qwen", Adapter: AdapterQwen3Guard, Model: "qwen", Enabled: true, TimeoutMS: 1000},
		ActiveEndpoint{ID: "third", Adapter: AdapterOpenAICompatibleQwen, Model: "third", Enabled: true, TimeoutMS: 1000},
	)
	snapshot := roleRunnerSnapshot()
	var qwenPrompts []string
	var thirdPartyCalls []ModelScanRequest
	result, err := runOrderedModels(context.Background(), cfg, snapshot, nil, nil, nil, func(_ context.Context, request ModelScanRequest) (*NormalizedResult, error) {
		if request.Endpoint.Adapter == AdapterQwen3Guard {
			qwenPrompts = append(qwenPrompts, request.FullPrompt)
			require.Empty(t, request.RolePrompt)
		} else {
			thirdPartyCalls = append(thirdPartyCalls, request)
			require.NotEmpty(t, request.RolePrompt)
		}
		return normalizedEndpointResult(request.Endpoint.ID, EventPass, ActionAllow, nil), nil
	}, nil)
	require.NoError(t, err)
	require.Equal(t, EventPass, result.Decision)
	require.Equal(t, []string{"current request\n\nsystem policy\n\nprevious answer"}, qwenPrompts)
	require.Len(t, thirdPartyCalls, len(snapshot.AuditSegments))
	for _, call := range thirdPartyCalls {
		require.Contains(t, call.FullPrompt, `"source_role"`)
		require.NotContains(t, call.RolePrompt, "TASK JOINT EVALUATION")
	}
	require.Len(t, result.ModelResults.Models, 2)
	require.Equal(t, "whole_prompt", result.ModelResults.Models[0].InputMode)
	require.Equal(t, "role_segments", result.ModelResults.Models[1].InputMode)
	require.Equal(t, 1, result.ModelResults.Aggregation.WholeModelCallCount)
	require.Equal(t, len(snapshot.AuditSegments), result.ModelResults.Aggregation.SegmentModelCallCount)
	require.Zero(t, result.ModelResults.Aggregation.JointModelCallCount)
	require.Len(t, result.ModelResults.NewSegmentResults, len(snapshot.AuditSegments))
	require.Len(t, result.ModelResults.SegmentUses, 2)
}

func TestRunOrderedModelsAggregatesQwenAndThirdPartyAsOneVotePerEndpoint(t *testing.T) {
	tests := []struct {
		name, strategy string
		qwenDecision   EventDecision
		qwenAction     Action
		want           EventDecision
	}{
		{name: "Qwen Flag remains Flag", strategy: AggregationAnyBlock, qwenDecision: EventFlag, qwenAction: ActionWarn, want: EventFlag},
		{name: "Qwen Critical blocks any", strategy: AggregationAnyBlock, qwenDecision: EventCritical, qwenAction: ActionBlock, want: EventCritical},
		{name: "Qwen Critical does not reach majority", strategy: AggregationMajorityBlock, qwenDecision: EventCritical, qwenAction: ActionBlock, want: EventFlag},
		{name: "Qwen Critical does not reach all", strategy: AggregationAllBlock, qwenDecision: EventCritical, qwenAction: ActionBlock, want: EventFlag},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := guardConfig(
				ActiveEndpoint{ID: "qwen", Adapter: AdapterQwen3Guard, Enabled: true, TimeoutMS: 1000},
				ActiveEndpoint{ID: "third", Adapter: AdapterOpenAICompatibleQwen, Enabled: true, TimeoutMS: 1000},
			)
			cfg.AggregationStrategy = tt.strategy
			calls := 0
			result, err := runOrderedModels(context.Background(), cfg, roleRunnerSnapshot(), nil, nil, nil, func(_ context.Context, request ModelScanRequest) (*NormalizedResult, error) {
				calls++
				if request.Endpoint.ID == "qwen" {
					return normalizedEndpointResult("qwen", tt.qwenDecision, tt.qwenAction, []string{"pii"}), nil
				}
				return normalizedEndpointResult("third", EventPass, ActionAllow, nil), nil
			}, nil)
			require.NoError(t, err)
			require.Equal(t, tt.want, result.Decision)
			require.Len(t, result.ModelResults.Models, 2)
			require.Equal(t, 1+len(roleRunnerSnapshot().AuditSegments), calls)
		})
	}
}

func TestRunOrderedModelsUsesPerEndpointSegmentHistoryAndRecordsNecessaryRelationships(t *testing.T) {
	cfg := guardConfig(ActiveEndpoint{ID: "third", Adapter: AdapterOpenAICompatibleQwen, Model: "third", Enabled: true, TimeoutMS: 1000})
	snapshot := roleRunnerSnapshot()
	finder := segmentFinderFunc(func(_ context.Context, keys []SegmentReuseKey) (map[string]SegmentAuditResult, error) {
		found := make(map[string]SegmentAuditResult, len(keys))
		for index, key := range keys {
			found[key.LookupKey] = SegmentAuditResult{
				ID: int64(index + 10), ReuseKey: key, SourceRole: snapshot.AuditSegments[index].SourceRole,
				Model: "third", Decision: EventPass, Action: ActionAllow, Categories: []string{},
			}
		}
		return found, nil
	})
	result, err := runOrderedModels(context.Background(), cfg, snapshot, nil, nil, nil, func(context.Context, ModelScanRequest) (*NormalizedResult, error) {
		t.Fatal("all cached Pass fragments must not call the third-party model")
		return nil, nil
	}, finder)
	require.NoError(t, err)
	require.Equal(t, EventPass, result.Decision)
	require.Equal(t, len(snapshot.AuditSegments), result.ModelResults.Aggregation.SegmentHistoryHitCount)
	require.Zero(t, result.ModelResults.Aggregation.SegmentModelCallCount)
	require.Zero(t, result.ModelResults.Aggregation.JointModelCallCount)
	require.Empty(t, result.ModelResults.NewSegmentResults)
	require.Len(t, result.ModelResults.SegmentUses, 2)
	for _, use := range result.ModelResults.SegmentUses {
		require.NotZero(t, use.SourceSegmentResultID)
	}
}

func TestRunOrderedModelsRunsOneJointEvaluationForRiskyThirdPartyFragments(t *testing.T) {
	cfg := guardConfig(ActiveEndpoint{ID: "third", Adapter: AdapterOpenAICompatibleQwen, Model: "third", Enabled: true, TimeoutMS: 1000})
	segmentCalls, jointCalls := 0, 0
	result, err := runOrderedModels(context.Background(), cfg, roleRunnerSnapshot(), nil, nil, nil, func(_ context.Context, request ModelScanRequest) (*NormalizedResult, error) {
		if strings.Contains(request.RolePrompt, "TASK JOINT EVALUATION") {
			jointCalls++
			return normalizedEndpointResult("third", EventCritical, ActionBlock, []string{"jailbreak"}), nil
		}
		segmentCalls++
		if strings.Contains(request.FullPrompt, "previous answer") {
			return normalizedEndpointResult("third", EventFlag, ActionWarn, []string{"jailbreak"}), nil
		}
		return normalizedEndpointResult("third", EventPass, ActionAllow, nil), nil
	}, nil)
	require.NoError(t, err)
	require.Equal(t, EventCritical, result.Decision)
	require.Equal(t, len(roleRunnerSnapshot().AuditSegments), segmentCalls)
	require.Equal(t, 1, jointCalls)
	require.Len(t, result.ModelResults.Models, 1)
	require.Equal(t, 1, result.ModelResults.Aggregation.JointModelCallCount)
	require.True(t, result.ModelResults.Models[0].JointEvaluation.Executed)
}
