package securityaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type ScannerDefinition struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	LabelZH     string `json:"label_zh"`
	Description string `json:"description"`
}

var AllScannerIDs = []string{
	"violent",
	"non_violent_illegal_acts",
	"sexual_content_or_sexual_acts",
	"pii",
	"suicide_and_self_harm",
	"unethical_acts",
	"politically_sensitive_topics",
	"copyright_violation",
	"jailbreak",
}

var ScannerCatalog = map[string]ScannerDefinition{
	"violent":                       {ID: "violent", Label: "Violent", LabelZH: "暴力", Description: "Violence or threats of violence"},
	"non_violent_illegal_acts":      {ID: "non_violent_illegal_acts", Label: "Non-violent Illegal Acts", LabelZH: "非暴力违法行为", Description: "Non-violent illegal activity"},
	"sexual_content_or_sexual_acts": {ID: "sexual_content_or_sexual_acts", Label: "Sexual Content or Sexual Acts", LabelZH: "性内容或性行为", Description: "Sexual content or sexual acts"},
	"pii":                           {ID: "pii", Label: "PII", LabelZH: "个人敏感信息", Description: "Personal identifying information"},
	"suicide_and_self_harm":         {ID: "suicide_and_self_harm", Label: "Suicide & Self-Harm", LabelZH: "自杀与自残", Description: "Suicide or self-harm"},
	"unethical_acts":                {ID: "unethical_acts", Label: "Unethical Acts", LabelZH: "不道德行为", Description: "Unethical behavior"},
	"politically_sensitive_topics":  {ID: "politically_sensitive_topics", Label: "Politically Sensitive Topics", LabelZH: "政治敏感话题", Description: "Politically sensitive topics"},
	"copyright_violation":           {ID: "copyright_violation", Label: "Copyright Violation", LabelZH: "版权侵权", Description: "Copyright infringement"},
	"jailbreak":                     {ID: "jailbreak", Label: "Jailbreak", LabelZH: "越狱攻击", Description: "Prompt injection or jailbreak attempt"},
}

var categoryAliases = map[string]string{
	"violent": "violent", "violence": "violent",
	"non violent illegal acts": "non_violent_illegal_acts", "non-violent illegal acts": "non_violent_illegal_acts",
	"sexual content or sexual acts": "sexual_content_or_sexual_acts", "sexual": "sexual_content_or_sexual_acts",
	"pii": "pii", "personal identifying information": "pii", "personal identifiable information": "pii",
	"suicide self harm": "suicide_and_self_harm", "suicide and self harm": "suicide_and_self_harm", "suicide & self-harm": "suicide_and_self_harm",
	"unethical acts": "unethical_acts", "unethical": "unethical_acts",
	"politically sensitive topics": "politically_sensitive_topics", "political": "politically_sensitive_topics",
	"copyright violation": "copyright_violation", "copyright": "copyright_violation",
	"jailbreak": "jailbreak", "prompt injection": "jailbreak",
}

type GuardError struct {
	Code       string
	DetailCode string
	HTTPStatus int
	Retryable  bool
	Timeout    bool
	Cause      error
	Attempts   []ModelCallAttempt
}

func (e *GuardError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code
}

func (e *GuardError) Unwrap() error { return e.Cause }

func NormalizeCategory(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("_", " ", "&", " and ", "/", " ", "-", " ", "–", " ", "—", " ").Replace(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")
	if canonical, ok := categoryAliases[normalized]; ok {
		return canonical
	}
	return strings.ReplaceAll(normalized, " ", "_")
}

var qwenCategoryLabels = []string{
	"Violent",
	"Non-violent Illegal Acts",
	"Sexual Content or Sexual Acts",
	"PII",
	"Suicide & Self-Harm",
	"Unethical Acts",
	"Politically Sensitive Topics",
	"Copyright Violation",
	"Jailbreak",
}

var qwenCategoryIDs = map[string]string{
	"Violent":                       "violent",
	"Non-violent Illegal Acts":      "non_violent_illegal_acts",
	"Sexual Content or Sexual Acts": "sexual_content_or_sexual_acts",
	"PII":                           "pii",
	"Suicide & Self-Harm":           "suicide_and_self_harm",
	"Unethical Acts":                "unethical_acts",
	"Politically Sensitive Topics":  "politically_sensitive_topics",
	"Copyright Violation":           "copyright_violation",
	"Jailbreak":                     "jailbreak",
}

func ParseQwen3Guard(content string, enabledScanners []string) (*NormalizedResult, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if strings.Contains(content, "```") || strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		return nil, invalidGuardOutput("unexpected_output_wrapper")
	}
	content = strings.TrimSuffix(content, "\n")
	lines := strings.Split(content, "\n")
	if len(lines) != 2 || lines[0] == "" || lines[1] == "" {
		return nil, invalidGuardOutput("invalid_line_count")
	}
	safety := ""
	switch lines[0] {
	case "Safety: Safe":
		safety = "Safe"
	case "Safety: Controversial":
		safety = "Controversial"
	case "Safety: Unsafe":
		safety = "Unsafe"
	default:
		return nil, invalidGuardOutput("invalid_safety")
	}
	if !strings.HasPrefix(lines[1], "Categories: ") {
		return nil, invalidGuardOutput("invalid_categories")
	}
	categoryLine := strings.TrimPrefix(lines[1], "Categories: ")
	enabled := make(map[string]struct{}, len(enabledScanners))
	for _, scanner := range enabledScanners {
		enabled[NormalizeCategory(scanner)] = struct{}{}
	}
	knownList := make([]string, 0, len(qwenCategoryLabels))
	if categoryLine != "None" {
		rawCategories := strings.Split(categoryLine, ", ")
		if len(rawCategories) == 0 || strings.Join(rawCategories, ", ") != categoryLine {
			return nil, invalidGuardOutput("invalid_categories")
		}
		selected := make(map[string]struct{}, len(rawCategories))
		for _, raw := range rawCategories {
			if _, ok := qwenCategoryIDs[raw]; !ok {
				return nil, invalidGuardOutput("invalid_categories")
			}
			if _, exists := selected[raw]; exists {
				// 保留历史稳定错误码；合法乱序由服务端按固定目录规范化。
				return nil, invalidGuardOutput("invalid_category_order")
			}
			selected[raw] = struct{}{}
		}
		for _, label := range qwenCategoryLabels {
			if _, ok := selected[label]; ok {
				knownList = append(knownList, qwenCategoryIDs[label])
			}
		}
	}
	if (safety == "Safe") != (categoryLine == "None") {
		return nil, invalidGuardOutput("invalid_safety_category_pair")
	}
	matched := make([]string, 0, len(knownList))
	for _, category := range knownList {
		if _, ok := enabled[category]; ok {
			matched = append(matched, category)
		}
	}
	result := &NormalizedResult{
		Safety: safety, Categories: knownList, MatchedScanners: matched, UnknownCategories: []string{},
		ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{},
		ScannerBackend: "qwen-two-line", ScannerVersion: PromptContractVersion,
		PolicyID: StrategyOrderedAll, PolicyVersion: 1,
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow,
	}
	score := 0.0
	if safety == "Controversial" {
		score = 0.5
		result.Decision, result.RiskLevel, result.Action = EventFlag, RiskMedium, ActionWarn
	}
	if safety == "Unsafe" {
		score = 1
		if len(matched) > 0 {
			result.Decision, result.RiskLevel, result.Action = EventCritical, RiskCritical, ActionBlock
		} else {
			result.Decision, result.RiskLevel, result.Action = EventFlag, RiskHigh, ActionWarn
		}
	}
	for _, category := range matched {
		result.ScannerScores[category] = score
		result.ScannerEvidence[category] = ScannerCatalog[category].Label
		if safety == "Controversial" && isElevatedControversial(category) {
			result.Decision, result.RiskLevel, result.Action = EventCritical, RiskCritical, ActionBlock
		}
	}
	return result, nil
}

func invalidGuardOutput(detail string) *GuardError {
	return &GuardError{Code: ErrorCodeInvalidResponse, DetailCode: detail}
}

func isElevatedControversial(category string) bool {
	return category == "jailbreak" || category == "pii" || category == "suicide_and_self_harm"
}

type OpenAICompatibleScanner struct {
	clients sync.Map
}

func NewOpenAICompatibleScanner() *OpenAICompatibleScanner { return &OpenAICompatibleScanner{} }

func (s *OpenAICompatibleScanner) Scan(ctx context.Context, scanRequest ModelScanRequest) (*NormalizedResult, error) {
	endpoint := scanRequest.Endpoint
	timeout, err := timeoutDuration(endpoint.TimeoutMS)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, DetailCode: "invalid_timeout", Cause: err}
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := s.clientFor(endpoint)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: err}
	}
	requestURL, err := ChatCompletionsURL(endpoint.BaseURL)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: err}
	}
	payload, err := buildGuardPayload(scanRequest, "")
	if err != nil {
		return nil, err
	}
	result, err := s.scanOnce(scanCtx, client, requestURL, endpoint, scanRequest.EnabledScanners, payload, 1, "initial")
	if err == nil {
		return result, nil
	}
	var guardErr *GuardError
	if !errors.As(err, &guardErr) || guardErr.Code != ErrorCodeInvalidResponse ||
		endpoint.Adapter != AdapterOpenAICompatibleQwen ||
		guardErr.HTTPStatus < http.StatusOK || guardErr.HTTPStatus >= http.StatusMultipleChoices {
		return nil, err
	}
	failedAttempts := append([]ModelCallAttempt(nil), guardErr.Attempts...)
	attemptKind := "format_repair"
	repairCode := stableErrorCode(modelErrorCode(err))
	switch repairCode {
	case "invalid_response_envelope", "empty_response_content", "invalid_response_content", "response_too_large":
		attemptKind = "protocol_retry"
		repairCode = ""
	}
	repairPayload, payloadErr := buildGuardPayload(scanRequest, repairCode)
	if payloadErr != nil {
		return nil, payloadErr
	}
	repaired, repairErr := s.scanOnce(scanCtx, client, requestURL, endpoint, scanRequest.EnabledScanners, repairPayload, 2, attemptKind)
	if repairErr == nil {
		repaired.FailedAttempts = failedAttempts
		addAttemptUsage(repaired, failedAttempts)
		return repaired, nil
	}
	var repairGuardErr *GuardError
	if errors.As(repairErr, &repairGuardErr) {
		repairGuardErr.Attempts = append(failedAttempts, repairGuardErr.Attempts...)
	}
	return nil, repairErr
}

func buildGuardPayload(scanRequest ModelScanRequest, repairCode string) (map[string]any, error) {
	endpoint := scanRequest.Endpoint
	payload := map[string]any{
		"model":       endpoint.Model,
		"messages":    []map[string]string{{"role": "user", "content": scanRequest.FullPrompt}},
		"temperature": 0,
		"stream":      false,
	}
	switch endpoint.Adapter {
	case AdapterQwen3Guard:
		payload["seed"] = 42
	case AdapterOpenAICompatibleQwen:
		if strings.TrimSpace(scanRequest.AuditPrompt) == "" {
			return nil, &GuardError{Code: ErrorCodeUnavailable, DetailCode: "audit_prompt_required"}
		}
		systemPrompt := scanRequest.AuditPrompt
		if repairCode != "" {
			systemPrompt += "\n\n" + fmt.Sprintf(FormatRepairPrompt, repairCode)
		}
		systemPrompt += "\n\n" + FixedOutputPrompt
		payload["messages"] = []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": scanRequest.FullPrompt},
		}
	default:
		return nil, &GuardError{Code: ErrorCodeUnavailable, DetailCode: "invalid_adapter"}
	}
	return payload, nil
}

func (s *OpenAICompatibleScanner) scanOnce(
	ctx context.Context,
	client *http.Client,
	requestURL string,
	endpoint ActiveEndpoint,
	enabledScanners []string,
	payload map[string]any,
	callAttempt int,
	attemptKind string,
) (*NormalizedResult, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if endpoint.Token != "" {
		req.Header.Set("Authorization", "Bearer "+endpoint.Token)
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		timeout := errors.Is(err, context.DeadlineExceeded)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			timeout = true
		}
		guardErr := &GuardError{
			Code: ErrorCodeUnavailable, DetailCode: "model_request_failed",
			Retryable: true, Timeout: timeout, Cause: err,
		}
		if timeout {
			guardErr.DetailCode = "model_timeout"
		}
		guardErr.Attempts = []ModelCallAttempt{failedModelCallAttempt(
			endpoint, callAttempt, attemptKind, 0, time.Since(started), modelUsage{}, guardErr, nil, false,
		)}
		return nil, guardErr
	}
	defer func() { _ = resp.Body.Close() }()
	limited := io.LimitReader(resp.Body, maxGuardResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		guardErr := &GuardError{
			Code: ErrorCodeUnavailable, DetailCode: "response_read_failed",
			HTTPStatus: resp.StatusCode, Retryable: true, Cause: err,
		}
		guardErr.Attempts = []ModelCallAttempt{failedModelCallAttempt(
			endpoint, callAttempt, attemptKind, resp.StatusCode, time.Since(started), modelUsage{}, guardErr, responseBody, false,
		)}
		return nil, guardErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		guardErr := &GuardError{
			Code: ErrorCodeUnavailable, DetailCode: "http_status_error", HTTPStatus: resp.StatusCode,
			Retryable: resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
		}
		guardErr.Attempts = []ModelCallAttempt{failedModelCallAttempt(
			endpoint, callAttempt, attemptKind, resp.StatusCode, time.Since(started), modelUsage{}, guardErr, responseBody,
			int64(len(responseBody)) > maxGuardResponseBytes,
		)}
		return nil, guardErr
	}
	truncated := int64(len(responseBody)) > maxGuardResponseBytes
	if truncated {
		guardErr := &GuardError{
			Code: ErrorCodeInvalidResponse, DetailCode: "response_too_large", HTTPStatus: resp.StatusCode,
		}
		guardErr.Attempts = []ModelCallAttempt{failedModelCallAttempt(
			endpoint, callAttempt, attemptKind, resp.StatusCode, time.Since(started), modelUsage{}, guardErr, responseBody, true,
		)}
		return nil, guardErr
	}
	content, usage, err := extractOpenAIResponse(responseBody)
	if err != nil {
		guardErr := &GuardError{
			Code: ErrorCodeInvalidResponse, DetailCode: guardResponseErrorCode(err),
			HTTPStatus: resp.StatusCode, Cause: err,
		}
		guardErr.Attempts = []ModelCallAttempt{failedModelCallAttempt(
			endpoint, callAttempt, attemptKind, resp.StatusCode, time.Since(started), usage, guardErr, responseBody, false,
		)}
		return nil, guardErr
	}
	result, err := ParseQwen3Guard(content, enabledScanners)
	if err != nil {
		var guardErr *GuardError
		if errors.As(err, &guardErr) {
			guardErr.HTTPStatus = resp.StatusCode
			guardErr.Attempts = []ModelCallAttempt{failedModelCallAttempt(
				endpoint, callAttempt, attemptKind, resp.StatusCode, time.Since(started), usage, guardErr, responseBody, false,
			)}
		}
		return nil, err
	}
	result.GuardEndpointID = endpoint.ID
	result.ScannerVersion = endpoint.Model
	result.InputTokens = usage.InputTokens
	result.OutputTokens = usage.OutputTokens
	result.ReasoningTokens = usage.ReasoningTokens
	return result, nil
}

func failedModelCallAttempt(
	endpoint ActiveEndpoint,
	callAttempt int,
	attemptKind string,
	httpStatus int,
	latency time.Duration,
	usage modelUsage,
	guardErr *GuardError,
	responseBody []byte,
	truncated bool,
) ModelCallAttempt {
	captured := responseBody
	if int64(len(captured)) > maxGuardResponseBytes {
		captured = captured[:maxGuardResponseBytes]
	}
	body := strings.ReplaceAll(strings.ToValidUTF8(string(captured), "\uFFFD"), "\x00", "")
	responseHash := ""
	if len(captured) > 0 {
		digest := sha256.Sum256(captured)
		responseHash = fmt.Sprintf("%x", digest[:])
	}
	errorCode := ErrorCodeUnavailable
	retryable := false
	if guardErr != nil {
		errorCode = stableErrorCode(modelErrorCode(guardErr))
		retryable = guardErr.Retryable
	}
	return ModelCallAttempt{
		CallAttempt: callAttempt, AttemptKind: attemptKind,
		EndpointID: endpoint.ID, Adapter: endpoint.Adapter, Model: endpoint.Model,
		HTTPStatus: httpStatus, LatencyMS: int(latency.Milliseconds()),
		InputTokens: validTokenCount(usage.InputTokens), OutputTokens: validTokenCount(usage.OutputTokens),
		ReasoningTokens: validTokenCount(usage.ReasoningTokens),
		ErrorCode:       errorCode, Retryable: retryable,
		ResponseBody: body, ResponseSHA256: responseHash, ResponseBytes: len(responseBody),
		ResponseTruncated: truncated,
	}
}

func validTokenCount(value *int) *int {
	if value == nil || *value < 0 {
		return nil
	}
	result := *value
	return &result
}

func addAttemptUsage(result *NormalizedResult, attempts []ModelCallAttempt) {
	if result == nil {
		return
	}
	for _, attempt := range attempts {
		result.InputTokens = addTokenCount(result.InputTokens, attempt.InputTokens)
		result.OutputTokens = addTokenCount(result.OutputTokens, attempt.OutputTokens)
		result.ReasoningTokens = addTokenCount(result.ReasoningTokens, attempt.ReasoningTokens)
	}
}

func addTokenCount(current, additional *int) *int {
	if additional == nil {
		return current
	}
	total := *additional
	if current != nil {
		total += *current
	}
	return &total
}

func (s *OpenAICompatibleScanner) clientFor(endpoint ActiveEndpoint) (*http.Client, error) {
	key := fmt.Sprintf("%s|%s|%d", endpoint.ID, endpoint.BaseURL, endpoint.TimeoutMS)
	if cached, ok := s.clients.Load(key); ok {
		client, valid := cached.(*http.Client)
		if !valid {
			s.clients.Delete(key)
			return nil, errors.New("prompt guard client cache invalid")
		}
		return client, nil
	}
	client, err := NewSecureHTTPClient(endpoint)
	if err != nil {
		return nil, err
	}
	actual, _ := s.clients.LoadOrStore(key, client)
	actualClient, ok := actual.(*http.Client)
	if !ok {
		s.clients.Delete(key)
		return nil, errors.New("prompt guard client cache invalid")
	}
	return actualClient, nil
}

type modelUsage struct {
	InputTokens     *int
	OutputTokens    *int
	ReasoningTokens *int
}

type guardResponseError struct {
	code string
}

func (e *guardResponseError) Error() string { return e.code }

func extractOpenAIResponse(body []byte) (string, modelUsage, error) {
	var response struct {
		Choices []struct {
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens      *int `json:"prompt_tokens"`
			CompletionTokens  *int `json:"completion_tokens"`
			CompletionDetails struct {
				ReasoningTokens *int `json:"reasoning_tokens"`
			} `json:"completion_tokens_details"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Choices) == 0 {
		return "", modelUsage{}, &guardResponseError{code: "invalid_response_envelope"}
	}
	usage := modelUsage{
		InputTokens: response.Usage.PromptTokens, OutputTokens: response.Usage.CompletionTokens,
		ReasoningTokens: response.Usage.CompletionDetails.ReasoningTokens,
	}
	content := response.Choices[0].Message.Content
	switch typed := content.(type) {
	case string:
		if typed == "" {
			return "", usage, &guardResponseError{code: "empty_response_content"}
		}
		return typed, usage, nil
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			object, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := object["text"].(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		if len(parts) == 0 {
			return "", usage, &guardResponseError{code: "empty_response_content"}
		}
		return strings.Join(parts, "\n"), usage, nil
	default:
		return "", usage, &guardResponseError{code: "invalid_response_content"}
	}
}

func guardResponseErrorCode(err error) string {
	var responseErr *guardResponseError
	if errors.As(err, &responseErr) && responseErr.code != "" {
		return responseErr.code
	}
	return ErrorCodeInvalidResponse
}

func extractOpenAIContent(body []byte) (string, error) {
	content, _, err := extractOpenAIResponse(body)
	return content, err
}

func ScannerDefinitions() []ScannerDefinition {
	result := make([]ScannerDefinition, 0, len(AllScannerIDs))
	for _, id := range AllScannerIDs {
		result = append(result, ScannerCatalog[id])
	}
	sort.SliceStable(result, func(i, j int) bool { return i < j })
	return result
}
