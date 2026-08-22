package securityaudit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseQwen3GuardStrictAndPolicy(t *testing.T) {
	tests := []struct {
		name, output string
		enabled      []string
		decision     EventDecision
		action       Action
		errorDetail  string
	}{
		{"safe", "Safety: Safe\nCategories: None", AllScannerIDs, EventPass, ActionAllow, ""},
		{"single trailing newline", "Safety: Safe\r\nCategories: None\r\n", AllScannerIDs, EventPass, ActionAllow, ""},
		{"controversial", "Safety: Controversial\nCategories: Violent", AllScannerIDs, EventFlag, ActionWarn, ""},
		{"controversial pii escalates", "Safety: Controversial\nCategories: PII", AllScannerIDs, EventCritical, ActionBlock, ""},
		{"unsafe", "Safety: Unsafe\nCategories: Jailbreak", AllScannerIDs, EventCritical, ActionBlock, ""},
		{"disabled unsafe warns", "Safety: Unsafe\nCategories: Violent", []string{"PII"}, EventFlag, ActionWarn, ""},
		{"unknown unsafe", "Safety: Unsafe\nCategories: Future Risk", AllScannerIDs, "", "", "invalid_categories"},
		{"extra explanation", "Safety: Safe\nCategories: None\nThis is safe", AllScannerIDs, "", "", "invalid_line_count"},
		{"extra trailing newline", "Safety: Safe\nCategories: None\n\n", AllScannerIDs, "", "", "invalid_line_count"},
		{"duplicate", "Safety: Safe\nSafety: Safe", AllScannerIDs, "", "", "invalid_categories"},
		{"duplicate categories", "Safety: Safe\nCategories: None\nCategories: PII", AllScannerIDs, "", "", "invalid_line_count"},
		{"missing categories", "Safety: Safe\n", AllScannerIDs, "", "", "invalid_line_count"},
		{"unknown safety", "Safety: Maybe\nCategories: PII", AllScannerIDs, "", "", "invalid_safety"},
		{"wrong case", "safety: Safe\nCategories: None", AllScannerIDs, "", "", "invalid_safety"},
		{"leading space", " Safety: Safe\nCategories: None", AllScannerIDs, "", "", "invalid_safety"},
		{"trailing space", "Safety: Safe \nCategories: None", AllScannerIDs, "", "", "invalid_safety"},
		{"wrong field order", "Categories: None\nSafety: Safe", AllScannerIDs, "", "", "invalid_safety"},
		{"wrong category case", "Safety: Unsafe\nCategories: pii", AllScannerIDs, "", "", "invalid_categories"},
		{"wrong separator", "Safety: Unsafe\nCategories: Violent,Jailbreak", AllScannerIDs, "", "", "invalid_categories"},
		{"out-of-order categories", "Safety: Unsafe\nCategories: Copyright Violation, Unethical Acts", AllScannerIDs, EventCritical, ActionBlock, ""},
		{"duplicate category", "Safety: Unsafe\nCategories: PII, PII", AllScannerIDs, "", "", "invalid_category_order"},
		{"safe with category", "Safety: Safe\nCategories: PII", AllScannerIDs, "", "", "invalid_safety_category_pair"},
		{"controversial none", "Safety: Controversial\nCategories: None", AllScannerIDs, "", "", "invalid_safety_category_pair"},
		{"unsafe none", "Safety: Unsafe\nCategories: None", AllScannerIDs, "", "", "invalid_safety_category_pair"},
		{"json", `{"Safety":"Safe","Categories":"None"}`, AllScannerIDs, "", "", "unexpected_output_wrapper"},
		{"markdown", "```\nSafety: Safe\nCategories: None\n```", AllScannerIDs, "", "", "unexpected_output_wrapper"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseQwen3Guard(tt.output, tt.enabled)
			if tt.errorDetail != "" {
				var guardErr *GuardError
				require.ErrorAs(t, err, &guardErr)
				require.Equal(t, ErrorCodeInvalidResponse, guardErr.Code)
				require.Equal(t, tt.errorDetail, guardErr.DetailCode)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.decision, result.Decision)
			require.Equal(t, tt.action, result.Action)
		})
	}
}

func TestBuildGuardPayloadAppliesRolePromptOnlyToThirdParty(t *testing.T) {
	third, err := buildGuardPayload(ModelScanRequest{
		Endpoint:    ActiveEndpoint{Adapter: AdapterOpenAICompatibleQwen, Model: "third"},
		FullPrompt:  `{"source_role":"user","content":"hello"}`,
		AuditPrompt: "audit policy", RolePrompt: "role rule",
	}, "")
	require.NoError(t, err)
	thirdMessages, ok := third["messages"].([]map[string]string)
	require.True(t, ok)
	require.Equal(t, "audit policy\n\nrole rule\n\n"+FixedOutputPrompt, thirdMessages[0]["content"])

	qwen, err := buildGuardPayload(ModelScanRequest{
		Endpoint:   ActiveEndpoint{Adapter: AdapterQwen3Guard, Model: "qwen"},
		FullPrompt: "complete prompt", AuditPrompt: "ignored", RolePrompt: "ignored",
	}, "")
	require.NoError(t, err)
	require.Equal(t, []map[string]string{{"role": "user", "content": "complete prompt"}}, qwen["messages"])
}

func TestParseQwen3GuardCanonicalizesCategoryOrder(t *testing.T) {
	result, err := ParseQwen3Guard(
		"Safety: Unsafe\nCategories: Copyright Violation, Unethical Acts",
		AllScannerIDs,
	)
	require.NoError(t, err)
	require.Equal(t, []string{"unethical_acts", "copyright_violation"}, result.Categories)
	require.Equal(t, []string{"unethical_acts", "copyright_violation"}, result.MatchedScanners)
	require.Equal(t, EventCritical, result.Decision)
	require.Equal(t, ActionBlock, result.Action)
}

func TestParseQwen3GuardRejectsAuxiliaryResponseFields(t *testing.T) {
	_, err := ParseQwen3Guard("Safety: Unsafe\nCategories: Jailbreak\nRefusal: No", AllScannerIDs)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.Equal(t, "invalid_line_count", guardErr.DetailCode)
}

func TestQwen3GuardOfficialCategoriesAndNormalizationAreStable(t *testing.T) {
	official := "Violent, Non-violent Illegal Acts, Sexual Content or Sexual Acts, PII, Suicide & Self-Harm, Unethical Acts, Politically Sensitive Topics, Copyright Violation, Jailbreak"
	require.Equal(t, strings.Split(official, ", "), qwenCategoryLabels)
	result, err := ParseQwen3Guard("Safety: Unsafe\nCategories: "+official, AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, AllScannerIDs, result.MatchedScanners)
	require.Empty(t, result.UnknownCategories)
	require.Equal(t, StrategyOrderedAll, result.PolicyID)
	require.Equal(t, 1, result.PolicyVersion)

	aliases := map[string]string{
		"violence": "violent", "non_violent_illegal_acts": "non_violent_illegal_acts",
		"sexual": "sexual_content_or_sexual_acts", "personal identifiable information": "pii",
		"suicide/self harm": "suicide_and_self_harm", "unethical": "unethical_acts",
		"political": "politically_sensitive_topics", "copyright": "copyright_violation",
		"prompt injection": "jailbreak",
	}
	for alias, canonical := range aliases {
		require.Equal(t, canonical, NormalizeCategory(alias), alias)
	}

	const canary = "PROMPT_CANARY_RAW_UNKNOWN_CATEGORY"
	_, err = ParseQwen3Guard("Safety: Unsafe\nCategories: "+canary, AllScannerIDs)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.Equal(t, "invalid_categories", guardErr.DetailCode)
}

func TestExtractOpenAIContentSupportsStringAndTextBlocks(t *testing.T) {
	content, err := extractOpenAIContent([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
	require.NoError(t, err)
	require.Equal(t, "Safety: Safe\nCategories: None", content)
	content, err = extractOpenAIContent([]byte(`{"choices":[{"message":{"content":[{"type":"text","text":"Safety: Safe"},{"type":"text","text":"Categories: None"}]}}]}`))
	require.NoError(t, err)
	require.Equal(t, "Safety: Safe\nCategories: None", content)
	for _, body := range []string{`{}`, `{"choices":[]}`, `{"choices":[{"message":{"content":null}}]}`} {
		_, err := extractOpenAIContent([]byte(body))
		require.Error(t, err)
	}
}

func TestAggregateModelResultsHonorsFrozenThreshold(t *testing.T) {
	for modelCount := 1; modelCount <= 4; modelCount++ {
		require.Equal(t, 1, CalculateBlockThreshold(AggregationAnyBlock, modelCount))
		require.Equal(t, modelCount/2+1, CalculateBlockThreshold(AggregationMajorityBlock, modelCount))
		require.Equal(t, modelCount, CalculateBlockThreshold(AggregationAllBlock, modelCount))
	}

	modelResults := ModelResults{Aggregation: ModelAggregation{
		Strategy: AggregationMajorityBlock, EnabledModelCount: 2, BlockThreshold: 2,
	}}
	result := aggregateModelResults([]*NormalizedResult{
		{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Categories: []string{"pii"}},
		{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Categories: []string{"jailbreak"}},
	}, modelResults, 0)
	require.Equal(t, EventFlag, result.Decision)
	require.Equal(t, ActionWarn, result.Action)
	require.Equal(t, []string{"pii", "jailbreak"}, result.Categories)
}

func TestAggregateDeduplicatesFactsAndUsesMostSevereEndpointMetadata(t *testing.T) {
	modelResults := ModelResults{Aggregation: ModelAggregation{
		Strategy: AggregationAnyBlock, EnabledModelCount: 2, BlockThreshold: 1,
	}}
	result := aggregateModelResults([]*NormalizedResult{
		{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}, ScannerScores: map[string]float64{"pii": 0}, ScannerEvidence: map[string]string{"pii": "first"}, GuardEndpointID: "safe-node", ScannerVersion: "safe-version", PolicyID: StrategyOrderedAll, PolicyVersion: 1},
		{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe", Categories: []string{"pii", "jailbreak"}, MatchedScanners: []string{"pii", "jailbreak"}, ScannerScores: map[string]float64{"pii": 1, "jailbreak": 1}, ScannerEvidence: map[string]string{"pii": "second", "jailbreak": "blocked"}, GuardEndpointID: "block-node", ScannerVersion: "block-version", PolicyID: StrategyOrderedAll, PolicyVersion: 2},
	}, modelResults, 7*time.Millisecond)
	require.Equal(t, []string{"pii", "jailbreak"}, result.Categories)
	require.Equal(t, []string{"pii", "jailbreak"}, result.MatchedScanners)
	require.Equal(t, "first", result.ScannerEvidence["pii"], "evidence is deterministically first-seen")
	require.Equal(t, "block-node", result.GuardEndpointID)
	require.Equal(t, PromptContractVersion, result.ScannerVersion)
	require.Equal(t, 1, result.PolicyVersion)
	require.Equal(t, 7, result.LatencyMS)
}

func TestIssueSummariesAreDeterministicRedactedDerivedDTOs(t *testing.T) {
	const canary = "PROMPT_CANARY_EVIDENCE_SECRET"
	result := NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock,
		Categories: []string{"jailbreak", "pii"}, MatchedScanners: []string{"pii"},
		ScannerScores: map[string]float64{"pii": 1}, ScannerEvidence: map[string]string{"pii": canary},
		UnknownCategories: []string{"unknown:0123456789abcdef"},
	}
	summaries := BuildIssueSummaries(result)
	require.Len(t, summaries, 3, "known categories are not hidden merely because policy disabled one")
	raw, err := json.Marshal(summaries)
	require.NoError(t, err)
	require.NotContains(t, string(raw), canary)
	for _, summary := range summaries {
		require.NotEmpty(t, summary.Title)
		require.NotEmpty(t, summary.Description)
		require.NotEmpty(t, summary.Code)
		require.NotEmpty(t, summary.EvidenceHash)
	}
}
