package securityaudit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	appservice "github.com/Wei-Shaw/sub2api/internal/service"
)

// promptModelAttemptResponseRetention 固定失败模型响应正文保留 30 天。
const promptModelAttemptResponseRetention = 30 * 24 * time.Hour

// promptModelAttemptCleanupInterval 固定每小时执行一次失败响应正文清理。
const promptModelAttemptCleanupInterval = time.Hour

// promptModelAttemptCleanupBatchSize 限制单次清理的数据库更新量。
const promptModelAttemptCleanupBatchSize = 1000

// promptAuditLeaseHeartbeatInterval 保证长时间模型调用不会超过任务租约刷新窗口。
const promptAuditLeaseHeartbeatInterval = 30 * time.Second

// promptAuditLeaseRefreshTimeout 限制单次数据库租约刷新等待时间。
const promptAuditLeaseRefreshTimeout = 5 * time.Second

// promptAuditStagingTimeout 标记尚未完成 Payload 发布的 staging 任务失效时间。
const promptAuditStagingTimeout = 2 * time.Minute

// promptAuditProcessingLeaseTimeout 标记 processing 任务失去租约的时间。
const promptAuditProcessingLeaseTimeout = 90 * time.Second

type WorkerRuntime struct {
	active           atomic.Int64
	processed        atomic.Int64
	failed           atomic.Int64
	heartbeatNS      atomic.Int64
	lastProcessedNS  atomic.Int64
	lastErrorMu      sync.RWMutex
	lastErrorCode    string
	lastErrorMessage string
}

type Runner struct {
	config  ConfigStore
	repo    JobRepository
	payload PayloadStore
	scanner PromptScanner
	metrics Metrics
	cache   appservice.APIKeyAuthCacheInvalidator
	clock   Clock
	runtime WorkerRuntime

	leaseHeartbeatInterval time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewRunner(
	config ConfigStore,
	repo JobRepository,
	payload PayloadStore,
	scanner PromptScanner,
	metrics Metrics,
	cache ...appservice.APIKeyAuthCacheInvalidator,
) *Runner {
	runner := &Runner{
		config: config, repo: repo, payload: payload, scanner: scanner, metrics: metrics, clock: realClock{},
		leaseHeartbeatInterval: promptAuditLeaseHeartbeatInterval,
	}
	if len(cache) > 0 {
		runner.cache = cache[0]
	}
	return runner
}

func (r *Runner) Start(ctx context.Context) error {
	if r == nil || r.config == nil || r.repo == nil || r.payload == nil || r.scanner == nil {
		return errors.New("prompt audit worker dependencies unavailable")
	}
	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()
	if err := r.payload.Ping(runCtx); err != nil {
		r.setLastError("payload_store_unavailable", err.Error())
	}
	for workerID := 0; workerID < MaxWorkerCount; workerID++ {
		r.wg.Add(1)
		go r.worker(runCtx, workerID)
	}
	r.wg.Add(1)
	go r.reclaimer(runCtx)
	return nil
}

func (r *Runner) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	cancel := r.cancel
	r.cancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		LogWarn(EventProcessFailed, map[string]any{"status": "shutdown_timeout", "error_code": "worker_shutdown_timeout"})
		return ctx.Err()
	}
}

func (r *Runner) worker(ctx context.Context, workerID int) {
	defer r.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runtime.heartbeatNS.Store(r.clock.Now().UnixNano())
			for {
				cfg, ok := r.config.Active()
				if !ok || !cfg.RiskControlEnabled || !cfg.Enabled || workerID >= cfg.WorkerCount {
					break
				}
				job, claimed, err := r.repo.ClaimNextJob(ctx, r.clock.Now())
				if err != nil {
					r.setLastError("claim_job_failed", err.Error())
					break
				}
				if !claimed {
					break
				}
				r.runtime.active.Add(1)
				r.processSafely(ctx, workerID, cfg, job)
				r.runtime.active.Add(-1)
			}
		}
	}
}

func (r *Runner) processSafely(ctx context.Context, workerID int, cfg ActiveConfig, job *Job) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.runtime.failed.Add(1)
			// Panic values may contain scanner response fragments or prompt data.
			// Keep only a stable generic message in runtime state and logs.
			r.setLastError("worker_panic", "worker panic recovered")
			_ = r.repo.Fail(ctx, job.ID, job.ClaimVersion, job.Attempts, "worker_panic", "worker panic recovered", nil)
			LogError(EventProcessFailed, mergeLogFields(jobLogFields(job), map[string]any{"worker_id": workerID, "status": "failed", "error_code": "worker_panic"}))
		}
	}()
	if err := r.processJob(ctx, workerID, cfg, job); err != nil {
		r.runtime.failed.Add(1)
	} else {
		r.runtime.processed.Add(1)
		r.runtime.lastProcessedNS.Store(r.clock.Now().UnixNano())
	}
}

func (r *Runner) processJob(ctx context.Context, workerID int, cfg ActiveConfig, job *Job) error {
	baseFields := jobLogFields(job)
	LogInfo(EventAuditStarted, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "attempts": job.Attempts, "status": "processing"}))
	payload, err := r.payload.Get(ctx, job.ID)
	if err != nil {
		return r.finishFailure(ctx, job, &GuardError{Code: "payload_missing", Retryable: false, Cause: err})
	}
	// Job 行只保存脱敏元数据，完整 Prompt 与角色边界由短生命周期 Payload 恢复。
	if err := hydrateSnapshotFromPayload(&job.Snapshot, payload); err != nil {
		return r.finishFailure(ctx, job, &GuardError{Code: "payload_invalid", Retryable: false, Cause: err})
	}
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 {
		return r.finishFailure(ctx, job, &GuardError{Code: "no_enabled_endpoint", Retryable: true})
	}
	started := r.clock.Now()
	resultSource := "model"
	aggregated, lookupErr := r.repo.FindReusableResult(ctx, job.Snapshot, cfg)
	if lookupErr != nil {
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{
			"worker_id": workerID, "status": "history_lookup_fallback", "error_code": "history_lookup_failed",
		}))
	}
	if aggregated != nil {
		resultSource = "history"
	}
	if aggregated == nil {
		var segmentFinder SegmentResultFinder
		if finder, ok := r.repo.(SegmentResultFinder); ok {
			segmentFinder = finder
		}
		aggregated, err = runOrderedModels(
			ctx,
			cfg,
			job.Snapshot,
			r.clock,
			r.metrics,
			func(callCtx context.Context, _ ActiveEndpoint) error {
				return r.repo.RefreshLease(callCtx, job.ID, job.ClaimVersion, r.clock.Now())
			},
			func(callCtx context.Context, request ModelScanRequest) (*NormalizedResult, error) {
				return r.scanWithLeaseHeartbeat(ctx, callCtx, job, request)
			},
			segmentFinder,
		)
	}
	if err != nil {
		if errors.Is(err, ErrLeaseLost) {
			return err
		}
		r.observeAsyncFailure(err, r.clock.Now().Sub(started))
		return r.finishFailure(ctx, job, err)
	}
	if r.metrics != nil {
		r.metrics.Observe(decisionKindForResult(aggregated), r.clock.Now().Sub(started))
	}
	LogInfo(EventChunksAggregated, mergeLogFields(baseFields, map[string]any{
		"worker_id": workerID, "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel,
		"action":              aggregated.Action,
		"enabled_model_count": aggregated.ModelResults.Aggregation.EnabledModelCount,
		"block_threshold":     aggregated.ModelResults.Aggregation.BlockThreshold,
		"partial_failure":     aggregated.ModelResults.Aggregation.PartialFailure,
		"latency_ms":          aggregated.LatencyMS, "guard_endpoint_id": aggregated.GuardEndpointID, "status": "completed",
		"result_source":          resultSource,
		"reused_from_outcome_id": pointerLogID(aggregated.ModelResults.Aggregation.ReusedFromOutcomeID),
	}))
	completion, err := r.repo.Complete(ctx, job, aggregated, cfg)
	if err != nil {
		return err
	}
	var event *Event
	if completion != nil {
		event = completion.Event
		if completion.DisabledUserID > 0 && r.cache != nil {
			r.cache.InvalidateAuthCacheByUserID(ctx, completion.DisabledUserID)
		}
	}
	if deleteErr := r.payload.Delete(ctx, job.ID); deleteErr != nil {
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "status": "payload_delete_deferred", "error_code": "payload_delete_failed"}))
	}
	LogInfo(EventProcessed, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "event_id": eventID(event), "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "guard_endpoint_id": aggregated.GuardEndpointID, "latency_ms": aggregated.LatencyMS, "status": "done"}))
	if event != nil && aggregated.Decision != EventPass {
		LogWarn(EventFindingRecorded, mergeLogFields(baseFields, map[string]any{"worker_id": workerID, "event_id": event.ID, "decision": aggregated.Decision, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "guard_endpoint_id": aggregated.GuardEndpointID, "status": "recorded"}))
	}
	return nil
}

func (r *Runner) scanWithLeaseHeartbeat(
	workerCtx context.Context,
	modelCtx context.Context,
	job *Job,
	request ModelScanRequest,
) (*NormalizedResult, error) {
	interval := r.leaseHeartbeatInterval
	if interval <= 0 {
		interval = promptAuditLeaseHeartbeatInterval
	}
	scanCtx, cancelScan := context.WithCancel(modelCtx)
	defer cancelScan()
	heartbeatCtx, cancelHeartbeat := context.WithCancel(workerCtx)
	heartbeatDone := make(chan struct{})
	heartbeatErr := make(chan error, 1)
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				refreshCtx, cancelRefresh := context.WithTimeout(heartbeatCtx, promptAuditLeaseRefreshTimeout)
				err := r.repo.RefreshLease(refreshCtx, job.ID, job.ClaimVersion, r.clock.Now())
				cancelRefresh()
				if err != nil {
					if heartbeatCtx.Err() != nil {
						return
					}
					heartbeatErr <- err
					cancelScan()
					return
				}
			}
		}
	}()

	result, err := callPromptScanner(scanCtx, r.scanner, request)
	cancelHeartbeat()
	<-heartbeatDone
	select {
	case <-heartbeatErr:
		// 租约刷新失败后无法证明当前 Worker 仍拥有任务，交由回收器安全重领。
		return nil, ErrLeaseLost
	default:
		return result, err
	}
}

func (r *Runner) observeAsyncFailure(err error, latency time.Duration) {
	if r == nil || r.metrics == nil {
		return
	}
	kind := DecisionUnavailable
	if guardErrorCode(err) == ErrorCodeInvalidResponse {
		kind = DecisionInvalid
	}
	r.metrics.Observe(kind, latency)
	var guardErr *GuardError
	if errors.As(err, &guardErr) && guardErr.Timeout {
		r.metrics.IncTimeout()
	}
}

func decisionKindForResult(result *NormalizedResult) DecisionKind {
	if result == nil {
		return DecisionInvalid
	}
	switch result.Action {
	case ActionBlock:
		return DecisionBlock
	case ActionWarn:
		return DecisionFlag
	default:
		return DecisionAllow
	}
}

func (r *Runner) finishFailure(ctx context.Context, job *Job, err error) error {
	baseFields := jobLogFields(job)
	// Job 和运行态保留模型级稳定错误码，便于区分两行数、类别和字段格式错误。
	code := modelErrorCode(err)
	attempts := modelAttemptsFromError(err)
	retryable := false
	var guardErr *GuardError
	if errors.As(err, &guardErr) {
		retryable = guardErr.Retryable
	}
	if retryable && job.Attempts < job.MaxAttempts {
		next := r.clock.Now().Add(retryBackoff(job.Attempts))
		if updateErr := r.repo.Retry(
			ctx, job.ID, job.ClaimVersion, job.Attempts, next, code,
			"prompt guard temporarily unavailable", attempts,
		); updateErr != nil {
			return updateErr
		}
		LogWarn(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "retry", "error_code": code, "retryable": true}))
	} else {
		if updateErr := r.repo.Fail(
			ctx, job.ID, job.ClaimVersion, job.Attempts, code,
			"prompt guard processing failed", attempts,
		); updateErr != nil {
			return updateErr
		}
		_ = r.payload.Delete(ctx, job.ID)
		LogError(EventProcessFailed, mergeLogFields(baseFields, map[string]any{"attempts": job.Attempts, "max_attempts": job.MaxAttempts, "status": "failed", "error_code": code, "retryable": false}))
	}
	r.setLastError(code, err.Error())
	return err
}

func (r *Runner) reclaimer(ctx context.Context) {
	defer r.wg.Done()
	reclaimTicker := time.NewTicker(time.Minute)
	cleanupTicker := time.NewTicker(promptModelAttemptCleanupInterval)
	defer reclaimTicker.Stop()
	defer cleanupTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reclaimTicker.C:
			now := r.clock.Now()
			count, err := r.repo.ReclaimStale(
				ctx,
				now.Add(-promptAuditStagingTimeout),
				now.Add(-promptAuditProcessingLeaseTimeout),
				100,
			)
			if err != nil {
				r.setLastError("reclaim_failed", err.Error())
				continue
			}
			if count > 0 {
				LogWarn(EventProcessingReclaimed, map[string]any{"reclaimed_total": count, "status": "reclaimed"})
			}
		case <-cleanupTicker.C:
			_, err := r.repo.PurgeExpiredModelAttemptBodies(
				ctx,
				r.clock.Now().Add(-promptModelAttemptResponseRetention),
				promptModelAttemptCleanupBatchSize,
			)
			if err != nil {
				r.setLastError("model_attempt_cleanup_failed", err.Error())
			}
		}
	}
}

func (r *Runner) Snapshot() (active, processed, failed int64, heartbeat, lastProcessed *time.Time, code, message string) {
	if r == nil {
		return
	}
	active, processed, failed = r.runtime.active.Load(), r.runtime.processed.Load(), r.runtime.failed.Load()
	if ns := r.runtime.heartbeatNS.Load(); ns > 0 {
		value := time.Unix(0, ns).UTC()
		heartbeat = &value
	}
	if ns := r.runtime.lastProcessedNS.Load(); ns > 0 {
		value := time.Unix(0, ns).UTC()
		lastProcessed = &value
	}
	r.runtime.lastErrorMu.RLock()
	code, message = r.runtime.lastErrorCode, r.runtime.lastErrorMessage
	r.runtime.lastErrorMu.RUnlock()
	return
}

func (r *Runner) setLastError(code, _ string) {
	code, message := sanitizeStoredError(code)
	r.runtime.lastErrorMu.Lock()
	r.runtime.lastErrorCode = code
	r.runtime.lastErrorMessage = message
	r.runtime.lastErrorMu.Unlock()
}

func retryBackoff(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 5 * time.Second
	case 2:
		return 30 * time.Second
	default:
		return 2 * time.Minute
	}
}

func eventID(event *Event) int64 {
	if event == nil {
		return 0
	}
	return event.ID
}
