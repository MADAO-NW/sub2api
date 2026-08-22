package securityaudit

import (
	"context"
	"errors"
	"time"
)

type Enqueuer struct {
	config  ConfigStore
	repo    JobRepository
	payload PayloadStore
	metrics Metrics
}

// promptAuditMaxAttempts 固定异步审计任务最多执行三次。
const promptAuditMaxAttempts = 3

func NewEnqueuer(config ConfigStore, repo JobRepository, payload PayloadStore, metrics ...Metrics) *Enqueuer {
	var metric Metrics
	if len(metrics) > 0 {
		metric = metrics[0]
	}
	return &Enqueuer{config: config, repo: repo, payload: payload, metrics: metric}
}

func (e *Enqueuer) Enqueue(ctx context.Context, req Request) error {
	if e == nil || e.config == nil || e.repo == nil || e.payload == nil {
		return errors.New("prompt audit enqueuer unavailable")
	}
	cfg, ok := e.config.Active()
	baseFields := requestLogFields(req)
	if !ok || cfg.EffectiveMode() != ModeAsync {
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": "mode_not_async"}))
		return nil
	}
	baseFields["config_version"] = cfg.ConfigVersion
	if !cfg.IncludesGroup(req.GroupID) {
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": "group_out_of_scope"}))
		return nil
	}
	if len(cfg.EnabledEndpoints()) == 0 {
		e.recordDropped()
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{"status": "dropped", "error_code": "no_enabled_endpoint"}))
		return nil
	}
	snapshot, err := ExtractPromptSnapshot(req)
	if errors.Is(err, ErrNoPromptText) {
		LogInfo(EventEnqueueSkipped, mergeLogFields(baseFields, map[string]any{"status": "skipped", "error_code": "no_user_text"}))
		return nil
	}
	if err != nil {
		e.recordDropped()
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{"status": "dropped", "error_code": "snapshot_invalid"}))
		return nil
	}
	ttl, err := payloadTTL(cfg, promptAuditMaxAttempts, len(snapshot.AuditSegments))
	if err != nil {
		e.recordDropped()
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{"status": "dropped", "error_code": "invalid_timeout_budget"}))
		return err
	}
	job, err := e.repo.CreateStagingWithCapacity(ctx, snapshot.Redacted(), cfg.ConfigVersion, promptAuditMaxAttempts, cfg.QueueCapacity)
	if err != nil {
		code := "database_unavailable"
		if errors.Is(err, ErrQueueFull) {
			code = "queue_full"
		}
		if errors.Is(err, ErrQueueAdmissionBusy) {
			code = "queue_admission_busy"
		}
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{
			"queue_capacity": cfg.QueueCapacity, "status": "dropped", "error_code": code,
		}))
		e.recordDropped()
		return err
	}
	payload, err := encodePromptAuditPayload(snapshot)
	if err != nil {
		_ = e.repo.MarkStagingFailed(ctx, job.ID, "payload_encode_failed", "payload encoding failed")
		e.recordDropped()
		return err
	}
	if err := e.payload.Set(ctx, job.ID, payload, ttl); err != nil {
		_ = e.repo.MarkStagingFailed(ctx, job.ID, "payload_store_failed", "payload store unavailable")
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{
			"job_id": job.ID, "status": "dropped", "error_code": "payload_store_failed",
		}))
		e.recordDropped()
		return err
	}
	if err := e.repo.PublishQueued(ctx, job.ID); err != nil {
		_ = e.payload.Delete(ctx, job.ID)
		_ = e.repo.MarkStagingFailed(ctx, job.ID, "queue_publish_failed", "queue publish failed")
		LogWarn(EventEnqueueDropped, mergeLogFields(baseFields, map[string]any{
			"job_id": job.ID, "status": "dropped", "error_code": "queue_publish_failed",
		}))
		e.recordDropped()
		return err
	}
	LogInfo(EventJobEnqueued, mergeLogFields(baseFields, map[string]any{
		"job_id":         job.ID,
		"queue_capacity": cfg.QueueCapacity, "status": "queued",
	}))
	if e.metrics != nil {
		e.metrics.IncEnqueued()
	}
	return nil
}

func payloadTTL(cfg ActiveConfig, maxAttempts int, segmentCounts ...int) (time.Duration, error) {
	segmentCount := 1
	if len(segmentCounts) > 0 && segmentCounts[0] > 0 {
		segmentCount = segmentCounts[0]
	}
	var perAttemptMS int64
	for _, endpoint := range cfg.EnabledEndpoints() {
		callCount := int64(1)
		if endpoint.Adapter == AdapterOpenAICompatibleQwen {
			callCount = int64(segmentCount) + 1
		}
		timeout := endpoint.TimeoutMS
		if timeout <= 0 {
			timeout = DefaultTimeoutMS
		}
		if callCount <= 0 || timeout > maxRepresentableTimeoutMS/callCount {
			return 0, errors.New("prompt audit timeout budget exceeds duration range")
		}
		endpointBudget := timeout * callCount
		if endpointBudget > maxRepresentableTimeoutMS-perAttemptMS {
			return 0, errors.New("prompt audit timeout budget exceeds duration range")
		}
		perAttemptMS += endpointBudget
	}
	return timeoutBudgetTTLFromPerAttempt(perAttemptMS, maxAttempts)
}

func timeoutBudgetTTL(timeouts []int64, maxAttempts int) (time.Duration, error) {
	var perAttemptMS int64
	for _, configuredTimeout := range timeouts {
		timeout := configuredTimeout
		if timeout <= 0 {
			timeout = DefaultTimeoutMS
		}
		if timeout > maxRepresentableTimeoutMS-perAttemptMS {
			return 0, errors.New("prompt audit timeout budget exceeds duration range")
		}
		perAttemptMS += timeout
	}
	return timeoutBudgetTTLFromPerAttempt(perAttemptMS, maxAttempts)
}

func timeoutBudgetTTLFromPerAttempt(perAttemptMS int64, maxAttempts int) (time.Duration, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if perAttemptMS > maxRepresentableTimeoutMS/int64(maxAttempts) {
		return 0, errors.New("prompt audit timeout budget exceeds duration range")
	}
	totalMS := int64(maxAttempts) * perAttemptMS
	for attempt := 1; attempt < maxAttempts; attempt++ {
		backoffMS := retryBackoff(attempt).Milliseconds()
		if backoffMS > maxRepresentableTimeoutMS-totalMS {
			return 0, errors.New("prompt audit timeout budget exceeds duration range")
		}
		totalMS += backoffMS
	}
	safetyMarginMS := (5 * time.Minute).Milliseconds()
	if safetyMarginMS > maxRepresentableTimeoutMS-totalMS {
		return 0, errors.New("prompt audit timeout budget exceeds duration range")
	}
	total := time.Duration(totalMS+safetyMarginMS) * time.Millisecond
	if total < DefaultPayloadTTL {
		return DefaultPayloadTTL, nil
	}
	return total, nil
}

func (e *Enqueuer) recordDropped() {
	if e != nil && e.metrics != nil {
		e.metrics.IncDropped()
	}
}
