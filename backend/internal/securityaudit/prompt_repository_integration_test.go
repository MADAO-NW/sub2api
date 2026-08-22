package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	appservice "github.com/Wei-Shaw/sub2api/internal/service"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

const promptAuditPostgresTestEnv = "PROMPT_AUDIT_TEST_POSTGRES_DSN"

func openPromptAuditIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(promptAuditPostgresTestEnv))
	if dsn == "" {
		t.Skip(promptAuditPostgresTestEnv + " is not set")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(16)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx))
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			email VARCHAR(320) NOT NULL DEFAULT '',
			role VARCHAR(20) NOT NULL DEFAULT 'user',
			status VARCHAR(20) NOT NULL DEFAULT 'active',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS groups (id BIGSERIAL PRIMARY KEY);
		CREATE TABLE IF NOT EXISTS api_keys (id BIGSERIAL PRIMARY KEY);
		CREATE TABLE IF NOT EXISTS settings (
			key VARCHAR(255) PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	require.NoError(t, err)
	for _, name := range []string{
		"181_prompt_audit.sql",
		"182_prompt_audit_full_prompt.sql",
		"224_prompt_audit_enforcement.sql",
		"229_prompt_audit_result_reuse.sql",
	} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		require.NoError(t, err)
		// The migration runner can retry an interrupted deployment; the migration
		// must therefore be safe to execute more than once.
		_, err = db.ExecContext(ctx, string(migration))
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, string(migration))
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	resetPromptAuditIntegrationDB(t, db)
	return db
}

func TestPromptAuditReusesOnlyCompleteOriginalResultsFromMatchingConfig(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	cfg := integrationConfig(9, false)
	cfg.Endpoints = []ActiveEndpoint{{ID: "guard-1", Adapter: AdapterQwen3Guard, Enabled: true}}
	sourceUserID := insertIdentity(t, db, "users")
	currentUserID := insertIdentity(t, db, "users")

	for index, decision := range []EventDecision{EventPass, EventFlag, EventCritical} {
		snapshot := integrationSnapshot(fmt.Sprintf("reuse-%d", index))
		snapshot.UserID = sourceUserID
		result := integrationResult(decision)
		result.ModelResults.Aggregation.ConfigVersion = cfg.ConfigVersion
		if decision == EventFlag {
			result.RiskLevel, result.Action, result.Safety = RiskHigh, ActionWarn, "Controversial"
		}
		source, err := repo.RecordBlocking(ctx, snapshot, cfg, result)
		require.NoError(t, err)
		require.NotNil(t, source.Outcome)

		reused, err := repo.FindReusableResult(ctx, snapshot, cfg)
		require.NoError(t, err)
		require.NotNil(t, reused)
		require.Equal(t, decision, reused.Decision)
		require.NotNil(t, reused.ModelResults.Aggregation.ReusedFromOutcomeID)
		require.Equal(t, source.Outcome.ID, *reused.ModelResults.Aggregation.ReusedFromOutcomeID)

		current := integrationSnapshot(fmt.Sprintf("current-%d", index))
		current.UserID = currentUserID
		current.PromptHash = snapshot.PromptHash
		current.EvaluationInputHash = snapshot.EvaluationInputHash
		completion, err := repo.RecordBlocking(ctx, current, cfg, reused)
		require.NoError(t, err)
		require.NotNil(t, completion.Outcome.ReusedFromOutcomeID)
		require.Equal(t, source.Outcome.ID, *completion.Outcome.ReusedFromOutcomeID)

		again, err := repo.FindReusableResult(ctx, snapshot, cfg)
		require.NoError(t, err)
		require.NotNil(t, again)
		require.Equal(t, source.Outcome.ID, *again.ModelResults.Aggregation.ReusedFromOutcomeID)
	}

	partialSnapshot := integrationSnapshot("partial-reuse")
	partial := integrationResult(EventCritical)
	partial.ModelResults.Aggregation.ConfigVersion = cfg.ConfigVersion
	partial.ModelResults.Aggregation.PartialFailure = true
	_, err := repo.RecordBlocking(ctx, partialSnapshot, cfg, partial)
	require.NoError(t, err)
	reused, err := repo.FindReusableResult(ctx, partialSnapshot, cfg)
	require.NoError(t, err)
	require.Nil(t, reused)

	configSnapshot := integrationSnapshot("config-reuse")
	configResult := integrationResult(EventPass)
	configResult.ModelResults.Aggregation.ConfigVersion = cfg.ConfigVersion
	_, err = repo.RecordBlocking(ctx, configSnapshot, cfg, configResult)
	require.NoError(t, err)
	differentEvaluation := configSnapshot
	differentEvaluation.EvaluationInputHash = strings.Repeat("e", 64)
	reused, err = repo.FindReusableResult(ctx, differentEvaluation, cfg)
	require.NoError(t, err)
	require.Nil(t, reused)
	for name, mutate := range map[string]func(*ActiveConfig){
		"config version": func(changed *ActiveConfig) { changed.ConfigVersion++ },
		"audit prompt":   func(changed *ActiveConfig) { changed.AuditPrompt += "\nchanged" },
		"aggregation":    func(changed *ActiveConfig) { changed.AggregationStrategy = AggregationAllBlock },
		"enabled models": func(changed *ActiveConfig) {
			changed.Endpoints = append(changed.Endpoints, ActiveEndpoint{ID: "guard-2", Adapter: AdapterQwen3Guard, Enabled: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := cfg
			mutate(&changed)
			reused, lookupErr := repo.FindReusableResult(ctx, configSnapshot, changed)
			require.NoError(t, lookupErr)
			require.Nil(t, reused)
		})
	}
}

func TestPromptAuditPersistsAndReusesThirdPartySegmentResultsPerEndpoint(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	cfg := integrationConfig(1, true)
	endpoint := ActiveEndpoint{ID: "third-guard", Adapter: AdapterOpenAICompatibleQwen, Model: "third-model", Enabled: true, TimeoutMS: 1000}
	cfg.Endpoints = []ActiveEndpoint{endpoint}
	segment := AuditSegment{
		Order: 1, SourceRole: "user", PolicyRole: "user", TurnScope: "current",
		Content: "segment input", ContentHash: promptAuditHash("segment input"),
	}
	key := buildSegmentReuseKey(segment, endpoint, cfg)

	sourceSnapshot := integrationSnapshot("segment-source")
	sourceSnapshot.EvaluationInputHash = hashEvaluationInput([]AuditSegment{segment})
	sourceResult := integrationResult(EventPass)
	sourceResult.ModelResults.Aggregation.EvaluationInputHash = sourceSnapshot.EvaluationInputHash
	sourceResult.ModelResults.Models = []ModelAuditResult{{Sequence: 1, EndpointID: endpoint.ID, Adapter: endpoint.Adapter, Model: endpoint.Model}}
	sourceResult.ModelResults.NewSegmentResults = []SegmentAuditResult{{
		ReuseKey: key, SourceRole: segment.SourceRole, Model: endpoint.Model,
		Decision: EventPass, Action: ActionAllow, Categories: []string{},
	}}
	sourceResult.ModelResults.SegmentUses = []SegmentResultUse{{
		EndpointID: endpoint.ID, SegmentOrder: segment.Order, SourceRole: segment.SourceRole,
		PolicyRole: segment.PolicyRole, TurnScope: segment.TurnScope, LookupKey: key.LookupKey,
	}}
	source, err := repo.RecordBlocking(ctx, sourceSnapshot, cfg, sourceResult)
	require.NoError(t, err)
	require.NotNil(t, source.Event)

	found, err := repo.FindReusableSegments(ctx, []SegmentReuseKey{key})
	require.NoError(t, err)
	require.Contains(t, found, key.LookupKey)
	require.NotZero(t, found[key.LookupKey].ID)

	currentSnapshot := integrationSnapshot("segment-current")
	currentSnapshot.PromptHash = strings.Repeat("x", 64)
	currentSnapshot.EvaluationInputHash = hashEvaluationInput([]AuditSegment{segment})
	currentResult := integrationResult(EventPass)
	currentResult.ModelResults.Aggregation.EvaluationInputHash = currentSnapshot.EvaluationInputHash
	currentResult.ModelResults.Models = sourceResult.ModelResults.Models
	currentResult.ModelResults.SegmentUses = []SegmentResultUse{{
		EndpointID: endpoint.ID, SegmentOrder: segment.Order, SourceRole: segment.SourceRole,
		PolicyRole: segment.PolicyRole, TurnScope: segment.TurnScope, LookupKey: key.LookupKey,
		SourceSegmentResultID: found[key.LookupKey].ID,
	}}
	current, err := repo.RecordBlocking(ctx, currentSnapshot, cfg, currentResult)
	require.NoError(t, err)
	require.NotNil(t, current.Event)

	detail, err := repo.GetEvent(ctx, current.ID)
	require.NoError(t, err)
	require.Len(t, detail.Segments, 1)
	require.Equal(t, endpoint.ID, detail.Segments[0].EndpointID)
	require.NotNil(t, detail.Segments[0].ReusedFromSegmentResultID)
	require.Equal(t, found[key.LookupKey].ID, *detail.Segments[0].ReusedFromSegmentResultID)
}

func resetPromptAuditIntegrationDB(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`TRUNCATE TABLE prompt_audit_enforcement_states,prompt_audit_enforcement_actions,
		prompt_audit_model_attempts,prompt_audit_outcomes,prompt_audit_events,prompt_audit_jobs,api_keys,users,groups,settings
		RESTART IDENTITY CASCADE`)
	require.NoError(t, err)
}

func insertIdentity(t *testing.T, db *sql.DB, table string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, db.QueryRow(`INSERT INTO `+table+` DEFAULT VALUES RETURNING id`).Scan(&id))
	return id
}

func integrationSnapshot(seed string) PromptSnapshot {
	return PromptSnapshot{
		RequestID: "request-" + seed, UsernameSnapshot: "user-" + seed,
		UserEmailSnapshot: "user-" + seed + "@example.test", APIKeyNameSnapshot: "key-" + seed,
		GroupName: "group-" + seed, Provider: "openai", Endpoint: "/v1/chat/completions",
		Protocol: "openai_chat", Model: "gpt-test", PromptHash: strings.Repeat(seed[:1], 64),
		EvaluationInputHash: strings.Repeat(seed[len(seed)-1:], 64),
		RedactedPreview:     "redacted-" + seed, PromptLength: len([]rune(seed)), MessageCount: 1,
	}
}

func integrationResult(decision EventDecision) *NormalizedResult {
	result := &NormalizedResult{
		Decision: decision, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		Categories: []string{}, MatchedScanners: []string{}, ScannerScores: map[string]float64{},
		ScannerEvidence: map[string]string{}, ScannerBackend: "qwen3guard-openai",
		ScannerVersion: "test", GuardEndpointID: "guard-1", PolicyID: StrategyOrderedAll,
		PolicyVersion: 1, ChunkTotal: 1, LatencyMS: 2,
		ModelResults: ModelResults{
			Aggregation: ModelAggregation{
				Strategy: AggregationAnyBlock, EnabledModelCount: 1, BlockThreshold: 1,
				ConfigVersion: 1, PromptContractVersion: PromptContractVersion,
				AuditPromptHash: promptAuditHash(DefaultAuditPrompt), EvaluationInputHash: "",
				EvaluationContractVersion: EvaluationContractVersion, RoleContractHash: currentRoleContractHash(),
			},
			Models: []ModelAuditResult{{Sequence: 1, EndpointID: "guard-1", Adapter: AdapterQwen3Guard}},
		},
	}
	if decision != EventPass {
		result.RiskLevel = RiskCritical
		result.Action = ActionBlock
		result.Safety = "Unsafe"
		result.Categories = []string{"pii"}
		result.MatchedScanners = []string{"pii"}
		result.ScannerScores["pii"] = 1
		result.ScannerEvidence["pii"] = "redacted evidence"
	}
	return result
}

func integrationConfig(version int64, storePassEvents bool) ActiveConfig {
	return ActiveConfig{
		StorePassEvents: storePassEvents, Strategy: StrategyOrderedAll,
		AggregationStrategy: AggregationAnyBlock, AuditPrompt: DefaultAuditPrompt,
		ConfigVersion: version,
	}
}

func TestPromptAuditMigrationSchemaAndLeakageGate(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, `SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema='public' AND table_name IN (
			'prompt_audit_jobs','prompt_audit_events','prompt_audit_outcomes',
			'prompt_audit_segment_results','prompt_audit_outcome_segments'
		)`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	forbidden := []string{"raw_prompt", "raw_request", "payload", "token", "authorization", "credential", "ciphertext"}
	for rows.Next() {
		var tableName, columnName string
		require.NoError(t, rows.Scan(&tableName, &columnName))
		lower := strings.ToLower(columnName)
		for _, word := range forbidden {
			require.NotContainsf(t, lower, word, "%s.%s is a forbidden raw/credential column", tableName, columnName)
		}
	}
	require.NoError(t, rows.Err())
	var reuseColumnCount int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema='public' AND table_name='prompt_audit_outcomes'
		  AND column_name='reused_from_outcome_id'`).Scan(&reuseColumnCount))
	require.Equal(t, 1, reuseColumnCount)
	var segmentContentColumnCount int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema='public' AND table_name='prompt_audit_segment_results'
		  AND column_name IN ('content','prompt','full_prompt')`).Scan(&segmentContentColumnCount))
	require.Zero(t, segmentContentColumnCount)

	indexRows, err := db.QueryContext(ctx, `SELECT indexname FROM pg_indexes
		WHERE schemaname='public' AND tablename IN (
			'prompt_audit_jobs','prompt_audit_events','prompt_audit_outcomes',
			'prompt_audit_segment_results','prompt_audit_outcome_segments'
		)`)
	require.NoError(t, err)
	defer func() { _ = indexRows.Close() }()
	indexes := map[string]bool{}
	for indexRows.Next() {
		var name string
		require.NoError(t, indexRows.Scan(&name))
		indexes[name] = true
	}
	for _, name := range []string{
		"idx_prompt_audit_jobs_schedule", "idx_prompt_audit_jobs_request", "idx_prompt_audit_jobs_user_created",
		"idx_prompt_audit_jobs_api_key_created", "idx_prompt_audit_jobs_group_created", "idx_prompt_audit_jobs_prompt_hash",
		"idx_prompt_audit_jobs_created", "idx_prompt_audit_events_job", "idx_prompt_audit_events_request",
		"idx_prompt_audit_events_decision_created", "idx_prompt_audit_events_risk_created",
		"idx_prompt_audit_events_user_created", "idx_prompt_audit_events_api_key_created",
		"idx_prompt_audit_events_group_created", "idx_prompt_audit_events_prompt_hash", "idx_prompt_audit_events_created",
		"idx_prompt_audit_outcomes_role_reuse_lookup", "idx_prompt_audit_outcomes_reused_from",
		"idx_prompt_audit_segment_results_reuse", "idx_prompt_audit_segment_results_source",
		"idx_prompt_audit_outcome_segments_source",
	} {
		require.Truef(t, indexes[name], "missing index %s", name)
	}

	_, err = db.ExecContext(ctx, `INSERT INTO prompt_audit_jobs(status) VALUES ('unknown')`)
	require.Error(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO prompt_audit_jobs(prompt_length) VALUES (-1)`)
	require.Error(t, err)
	var jobID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO prompt_audit_jobs DEFAULT VALUES RETURNING id`).Scan(&jobID))
	_, err = db.ExecContext(ctx, `INSERT INTO prompt_audit_events(job_id,chunk_total) VALUES ($1,-1)`, jobID)
	require.Error(t, err)
}

func TestPromptAuditDatabasePersistsFullPromptOnEventsOnly(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	const promptCanary = "PROMPT_AUDIT_CANARY_SECRET_DO_NOT_PERSIST"
	request := Request{
		RequestID: "canary-request", Provider: "openai",
		Endpoint: "/v1/chat/completions", Protocol: "openai_chat", Model: "gpt-test", Stage: "http",
		Body: []byte(`{"messages":[{"role":"user","content":"` + promptCanary + `"}]}`),
	}
	snapshot, err := ExtractPromptSnapshot(request)
	require.NoError(t, err)
	require.NotContains(t, snapshot.RedactedPreview, promptCanary)
	require.Contains(t, snapshot.FullPrompt, promptCanary)
	event, err := repo.RecordBlocking(ctx, snapshot.Redacted(), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	// The event intentionally retains the full prompt for admin review; the
	// redacted preview and transient job row still never contain it.
	adminJSON, err := json.Marshal(event)
	require.NoError(t, err)
	require.Contains(t, string(adminJSON), promptCanary)
	require.NotContains(t, event.Snapshot.RedactedPreview, promptCanary)

	var storedFullPrompt string
	require.NoError(t, db.QueryRow(`SELECT full_prompt FROM prompt_audit_events WHERE id=$1`, event.ID).Scan(&storedFullPrompt))
	require.Contains(t, storedFullPrompt, promptCanary)

	detail, err := repo.GetEvent(ctx, event.ID)
	require.NoError(t, err)
	require.Contains(t, detail.Snapshot.FullPrompt, promptCanary)

	var jobJSON string
	require.NoError(t, db.QueryRow(`SELECT row_to_json(j)::text FROM prompt_audit_jobs j WHERE id=$1`, event.JobID).Scan(&jobJSON))
	require.NotContains(t, jobJSON, promptCanary)

	failedJob, err := repo.CreateStagingWithCapacity(ctx, integrationSnapshot("error"), 1, 3, 10)
	require.NoError(t, err)
	const errorCanary = "GUARD_RAW_RESPONSE_CANARY_SECRET"
	require.NoError(t, repo.MarkStagingFailed(ctx, failedJob.ID, "payload_store_failed", "raw guard body: "+errorCanary))
	var code, message string
	require.NoError(t, db.QueryRow(`SELECT last_error_code,last_error_message FROM prompt_audit_jobs WHERE id=$1`, failedJob.ID).Scan(&code, &message))
	require.Equal(t, "payload_store_failed", code)
	require.Equal(t, stableErrorMessage(code), message)
	require.NotContains(t, message, errorCanary)
	require.LessOrEqual(t, len([]rune(message)), 160)
}

func TestPromptAuditPersistsFailedModelAttemptsAcrossCompletionAndFailure(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	tokenCount := 7
	failedAttempt := ModelCallAttempt{
		ModelSequence: 1, CallAttempt: 1, AttemptKind: "initial",
		EndpointID: "guard-one", Adapter: AdapterOpenAICompatibleQwen, Model: "guard-model",
		HTTPStatus: http.StatusOK, LatencyMS: 25, InputTokens: &tokenCount,
		ErrorCode: "invalid_line_count", ResponseBody: `{"invalid":"three lines"}`,
		ResponseSHA256: strings.Repeat("a", 64), ResponseBytes: 25,
	}

	result := integrationResult(EventCritical)
	result.ModelResults.FailedAttempts = []ModelCallAttempt{failedAttempt}
	completion, err := repo.RecordBlocking(ctx, integrationSnapshot("attempt-complete"), integrationConfig(1, true), result)
	require.NoError(t, err)
	require.NotNil(t, completion.Event)

	var storedBody, storedCode string
	var jobAttempt, modelSequence, callAttempt int
	require.NoError(t, db.QueryRow(`
		SELECT job_attempt,model_sequence,call_attempt,error_code,response_body
		FROM prompt_audit_model_attempts WHERE job_id=$1`, completion.Event.JobID).
		Scan(&jobAttempt, &modelSequence, &callAttempt, &storedCode, &storedBody))
	require.Equal(t, []int{1, 1, 1}, []int{jobAttempt, modelSequence, callAttempt})
	require.Equal(t, "invalid_line_count", storedCode)
	require.Equal(t, failedAttempt.ResponseBody, storedBody)

	asyncJob, err := repo.CreateStagingWithCapacity(ctx, integrationSnapshot("attempt-fail"), 1, 3, 10)
	require.NoError(t, err)
	require.NoError(t, repo.PublishQueued(ctx, asyncJob.ID))
	claimed, ok, err := repo.ClaimNextJob(ctx, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, asyncJob.ID, claimed.ID)
	require.NoError(t, repo.Fail(
		ctx, claimed.ID, claimed.ClaimVersion, claimed.Attempts,
		"invalid_line_count", "not persisted", []ModelCallAttempt{failedAttempt},
	))
	var status string
	require.NoError(t, db.QueryRow(`SELECT status FROM prompt_audit_jobs WHERE id=$1`, claimed.ID).Scan(&status))
	require.Equal(t, "failed", status)
	require.NoError(t, db.QueryRow(`
		SELECT response_body FROM prompt_audit_model_attempts WHERE job_id=$1`, claimed.ID).Scan(&storedBody))
	require.Equal(t, failedAttempt.ResponseBody, storedBody)
}

func TestPromptAuditBlockingFailureAttemptIdempotencyCascadeAndBodyRetention(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	snapshot := integrationSnapshot("blocking-failed")
	attempt := ModelCallAttempt{
		ModelSequence: 1, CallAttempt: 1, AttemptKind: "initial",
		EndpointID: "guard-one", Adapter: AdapterOpenAICompatibleQwen, Model: "guard-model",
		HTTPStatus: http.StatusOK, ErrorCode: "invalid_line_count",
		ResponseBody:   `{"choices":[{"message":{"content":"extra"}}]}`,
		ResponseSHA256: strings.Repeat("b", 64), ResponseBytes: 49,
	}
	require.NoError(t, repo.RecordBlockingFailure(
		ctx, snapshot, integrationConfig(1, true), "invalid_line_count", []ModelCallAttempt{attempt},
	))

	var jobID int64
	var status string
	require.NoError(t, db.QueryRow(`
		SELECT id,status FROM prompt_audit_jobs WHERE request_id=$1`, snapshot.RequestID).Scan(&jobID, &status))
	require.Equal(t, "failed", status)
	var eventCount, outcomeCount, attemptCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_events WHERE job_id=$1`, jobID).Scan(&eventCount))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_outcomes WHERE job_id=$1`, jobID).Scan(&outcomeCount))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_model_attempts WHERE job_id=$1`, jobID).Scan(&attemptCount))
	require.Zero(t, eventCount)
	require.Zero(t, outcomeCount)
	require.Equal(t, 1, attemptCount)

	require.NoError(t, insertModelAttempts(ctx, db, jobID, 1, []ModelCallAttempt{attempt}))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_model_attempts WHERE job_id=$1`, jobID).Scan(&attemptCount))
	require.Equal(t, 1, attemptCount)

	_, err := db.Exec(`
		UPDATE prompt_audit_model_attempts
		SET created_at=NOW()-INTERVAL '31 days'
		WHERE job_id=$1`, jobID)
	require.NoError(t, err)
	purged, err := repo.PurgeExpiredModelAttemptBodies(ctx, time.Now().Add(-30*24*time.Hour), 100)
	require.NoError(t, err)
	require.Equal(t, int64(1), purged)
	var body, hash string
	var purgedAt sql.NullTime
	require.NoError(t, db.QueryRow(`
		SELECT response_body,response_sha256,response_purged_at
		FROM prompt_audit_model_attempts WHERE job_id=$1`, jobID).Scan(&body, &hash, &purgedAt))
	require.Empty(t, body)
	require.Equal(t, attempt.ResponseSHA256, hash)
	require.True(t, purgedAt.Valid)

	_, err = db.Exec(`DELETE FROM prompt_audit_jobs WHERE id=$1`, jobID)
	require.NoError(t, err)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_model_attempts WHERE job_id=$1`, jobID).Scan(&attemptCount))
	require.Zero(t, attemptCount)
}

func TestPromptAuditRepositoryAdmissionClaimFencingAndEventTransaction(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()

	start := make(chan struct{})
	type admissionResult struct {
		job *Job
		err error
	}
	results := make(chan admissionResult, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			job, err := repo.CreateStagingWithCapacity(ctx, integrationSnapshot(string(rune('a'+index))), 1, 3, 1)
			results <- admissionResult{job: job, err: err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var accepted *Job
	rejected := 0
	for result := range results {
		if result.err == nil {
			require.Nil(t, accepted)
			accepted = result.job
			continue
		}
		require.True(t, errors.Is(result.err, ErrQueueFull) || errors.Is(result.err, ErrQueueAdmissionBusy))
		rejected++
	}
	require.NotNil(t, accepted)
	require.Equal(t, 1, rejected)
	stats, err := repo.QueueStats(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), stats.Active)
	require.NoError(t, repo.PublishQueued(ctx, accepted.ID))

	claimStart := make(chan struct{})
	claims := make(chan *Job, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-claimStart
			job, claimed, claimErr := repo.ClaimNextJob(ctx, time.Now().Add(time.Second))
			require.NoError(t, claimErr)
			if claimed {
				claims <- job
			}
		}()
	}
	close(claimStart)
	wg.Wait()
	close(claims)
	claimedJobs := make([]*Job, 0, 1)
	for job := range claims {
		claimedJobs = append(claimedJobs, job)
	}
	require.Len(t, claimedJobs, 1)
	firstClaim := claimedJobs[0]
	require.Equal(t, int64(1), firstClaim.ClaimVersion)

	reclaimed, err := repo.ReclaimStale(ctx, time.Now().Add(time.Hour), time.Now().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), reclaimed)
	secondClaim, claimed, err := repo.ClaimNextJob(ctx, time.Now().Add(time.Second))
	require.NoError(t, err)
	require.True(t, claimed)
	require.Greater(t, secondClaim.ClaimVersion, firstClaim.ClaimVersion)
	require.ErrorIs(t, repo.RefreshLease(ctx, firstClaim.ID, firstClaim.ClaimVersion, time.Now()), ErrLeaseLost)
	_, err = repo.Complete(ctx, firstClaim, integrationResult(EventCritical), integrationConfig(1, true))
	require.ErrorIs(t, err, ErrLeaseLost)

	event, err := repo.Complete(ctx, secondClaim, integrationResult(EventCritical), integrationConfig(1, true))
	require.NoError(t, err)
	require.NotNil(t, event)
	var status string
	var eventCount int
	require.NoError(t, db.QueryRow(`SELECT status FROM prompt_audit_jobs WHERE id=$1`, secondClaim.ID).Scan(&status))
	require.Equal(t, "done", status)
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_events WHERE job_id=$1`, secondClaim.ID).Scan(&eventCount))
	require.Equal(t, 1, eventCount)
	var outcomeCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_outcomes WHERE job_id=$1`, secondClaim.ID).Scan(&outcomeCount))
	require.Equal(t, 1, outcomeCount)

	staging, err := repo.CreateStagingWithCapacity(ctx, integrationSnapshot("stale"), 1, 3, 10)
	require.NoError(t, err)
	reclaimed, err = repo.ReclaimStale(ctx, time.Now().Add(time.Hour), time.Now().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), reclaimed)
	require.NoError(t, db.QueryRow(`SELECT status FROM prompt_audit_jobs WHERE id=$1`, staging.ID).Scan(&status))
	require.Equal(t, "failed", status)
}

func TestPromptAuditRepositoryForeignKeysFiltersAndStableIdentitySnapshots(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	userID := insertIdentity(t, db, "users")
	apiKeyID := insertIdentity(t, db, "api_keys")
	groupID := insertIdentity(t, db, "groups")
	snapshot := integrationSnapshot("identity")
	snapshot.UserID, snapshot.APIKeyID, snapshot.GroupID = userID, apiKeyID, &groupID
	event, err := repo.RecordBlocking(ctx, snapshot, integrationConfig(7, true), integrationResult(EventCritical))
	require.NoError(t, err)
	require.NotNil(t, event)

	start, end := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	page, err := repo.ListEvents(ctx, EventFilter{
		Decision: string(EventCritical), RiskLevel: string(RiskCritical), Endpoint: snapshot.Endpoint,
		GroupID: &groupID, UserID: &userID, APIKeyID: &apiKeyID, RequestID: snapshot.RequestID,
		PromptHash: snapshot.PromptHash, Keyword: snapshot.UsernameSnapshot, StartAt: &start, EndAt: &end,
	}, 1, 10)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	require.Len(t, page.Items, 1)
	require.NotEmpty(t, page.Items[0].IssueSummaries)
	require.Equal(t, snapshot.UsernameSnapshot, page.Items[0].Snapshot.UsernameSnapshot)
	require.Equal(t, snapshot.UserEmailSnapshot, page.Items[0].Snapshot.UserEmailSnapshot)
	require.Equal(t, snapshot.APIKeyNameSnapshot, page.Items[0].Snapshot.APIKeyNameSnapshot)

	_, err = db.Exec(`DELETE FROM users WHERE id=$1`, userID)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM api_keys WHERE id=$1`, apiKeyID)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM groups WHERE id=$1`, groupID)
	require.NoError(t, err)
	stored, err := repo.GetEvent(ctx, event.ID)
	require.NoError(t, err)
	require.Zero(t, stored.Snapshot.UserID)
	require.Zero(t, stored.Snapshot.APIKeyID)
	require.Nil(t, stored.Snapshot.GroupID)
	require.Equal(t, snapshot.UsernameSnapshot, stored.Snapshot.UsernameSnapshot)
	require.Equal(t, snapshot.UserEmailSnapshot, stored.Snapshot.UserEmailSnapshot)
	require.Equal(t, snapshot.APIKeyNameSnapshot, stored.Snapshot.APIKeyNameSnapshot)

	_, err = db.Exec(`DELETE FROM prompt_audit_jobs WHERE id=$1`, event.JobID)
	require.NoError(t, err)
	_, err = repo.GetEvent(ctx, event.ID)
	require.ErrorIs(t, err, ErrEventNotFound)
}

func TestPromptAuditRepositoryHighWaterAndSafeDeletion(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	first, err := repo.RecordBlocking(ctx, integrationSnapshot("first"), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	second, err := repo.RecordBlocking(ctx, integrationSnapshot("second"), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	start, end := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	filter := EventFilter{Decision: string(EventCritical), StartAt: &start, EndAt: &end}
	preview, err := repo.PreviewDelete(ctx, filter)
	require.NoError(t, err)
	require.Equal(t, int64(2), preview.MatchedCount)
	require.Equal(t, second.ID, preview.SnapshotMaxID)
	require.Equal(t, FilterHash(preview.FilterSummary, preview.SnapshotMaxID), preview.FilterHash)

	newer, err := repo.RecordBlocking(ctx, integrationSnapshot("newer"), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	result, err := repo.DeleteEventsByFilter(ctx, filter, preview.SnapshotMaxID, 1)
	require.NoError(t, err)
	require.Equal(t, int64(2), result.DeletedEvents)
	require.Equal(t, int64(2), result.DeletedJobs)
	for _, outcomeID := range []int64{first.Outcome.ID, second.Outcome.ID} {
		var outcomeCount int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_outcomes WHERE id=$1`, outcomeID).Scan(&outcomeCount))
		require.Equal(t, 1, outcomeCount, "event/job deletion must not change the outcome fact")
	}
	_, err = repo.GetEvent(ctx, first.ID)
	require.ErrorIs(t, err, ErrEventNotFound)
	_, err = repo.GetEvent(ctx, second.ID)
	require.ErrorIs(t, err, ErrEventNotFound)
	_, err = repo.GetEvent(ctx, newer.ID)
	require.NoError(t, err, "an event created after preview must survive high-water deletion")

	processingEvent, err := repo.RecordBlocking(ctx, integrationSnapshot("processing"), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE prompt_audit_jobs SET status='processing' WHERE id=$1`, processingEvent.JobID)
	require.NoError(t, err)
	deleteResult, err := repo.DeleteEvent(ctx, processingEvent.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleteResult.DeletedEvents)
	require.Zero(t, deleteResult.DeletedJobs)
	var remaining int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_jobs WHERE id=$1`, processingEvent.JobID).Scan(&remaining))
	require.Equal(t, 1, remaining, "processing jobs must not be deleted as orphans")

	batchOne, err := repo.RecordBlocking(ctx, integrationSnapshot("batch-one"), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	batchTwo, err := repo.RecordBlocking(ctx, integrationSnapshot("batch-two"), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	ids := []int64{batchTwo.ID, batchOne.ID, batchOne.ID}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	batchResult, err := repo.DeleteEventsByIDs(ctx, ids)
	require.NoError(t, err)
	require.Equal(t, int64(2), batchResult.DeletedEvents)
}

func TestPromptAuditOutcomeExistsWithoutPassEvent(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)

	completion, err := repo.RecordBlocking(
		context.Background(),
		integrationSnapshot("safe-outcome"),
		integrationConfig(3, false),
		integrationResult(EventPass),
	)

	require.NoError(t, err)
	require.Nil(t, completion.Event)
	require.NotNil(t, completion.Outcome)
	require.False(t, completion.Outcome.IsViolation)
	var eventCount, outcomeCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_events WHERE job_id=$1`, completion.Outcome.JobID).Scan(&eventCount))
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM prompt_audit_outcomes WHERE job_id=$1`, completion.Outcome.JobID).Scan(&outcomeCount))
	require.Zero(t, eventCount)
	require.Equal(t, 1, outcomeCount)
}

func TestPromptAuditDeletedUserStillKeepsOutcomeWithoutUserAction(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	var deletedUserID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('deleted-before-complete@example.test','user','active') RETURNING id`).
		Scan(&deletedUserID))
	_, err := db.Exec(`DELETE FROM users WHERE id=$1`, deletedUserID)
	require.NoError(t, err)

	snapshot := integrationSnapshot("deleted-user")
	snapshot.UserID = deletedUserID
	snapshot.UsernameSnapshot = "deleted-user"
	snapshot.UserEmailSnapshot = "deleted-before-complete@example.test"
	config := integrationConfig(1, true)
	config.Notifications.AdminEmail = "security@example.test"
	config.Enforcement.EmailWarning = EmailWarningConfig{
		Enabled: true, RuleRevision: 1, LookbackCount: 2, ViolationThreshold: 1,
	}
	config.Enforcement.AccountDisable = AccountDisableConfig{Enabled: true, ViolationThreshold: 1}

	completion, err := repo.RecordBlocking(ctx, snapshot, config, integrationResult(EventCritical))

	require.NoError(t, err)
	require.NotNil(t, completion.Event)
	require.NotNil(t, completion.Outcome)
	require.Zero(t, completion.Outcome.UserID)
	require.Equal(t, "deleted-user", completion.Outcome.UsernameSnapshot)
	var outcomeUserID sql.NullInt64
	require.NoError(t, db.QueryRow(`
		SELECT user_id FROM prompt_audit_outcomes WHERE id=$1`, completion.Outcome.ID).Scan(&outcomeUserID))
	require.False(t, outcomeUserID.Valid)
	var stateCount, actionCount int
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_states WHERE user_id=$1`, deletedUserID).Scan(&stateCount))
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_actions WHERE user_id=$1`, deletedUserID).Scan(&actionCount))
	require.Zero(t, stateCount)
	require.Zero(t, actionCount)
}

func TestPromptAuditEmailWindowEdgeAndAccountDisablePriority(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()

	var warningUserID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('warning@example.test','user','active') RETURNING id`).
		Scan(&warningUserID))
	warningConfig := integrationConfig(1, false)
	warningConfig.Notifications.AdminEmail = "security@example.test"
	warningConfig.Enforcement.EmailWarning = EmailWarningConfig{
		Enabled: true, RuleRevision: 1, LookbackCount: 3, ViolationThreshold: 2,
	}
	const promptCanary = "ENFORCEMENT_PROMPT_CANARY_DO_NOT_COPY"
	record := func(seed string, userID int64, cfg ActiveConfig, decision EventDecision) *CompletionResult {
		t.Helper()
		snapshot := integrationSnapshot(seed)
		snapshot.UserID = userID
		snapshot.FullPrompt = promptCanary + "-" + seed
		completion, err := repo.RecordBlocking(ctx, snapshot, cfg, integrationResult(decision))
		require.NoError(t, err)
		return completion
	}
	record("warning-v1", warningUserID, warningConfig, EventCritical)
	record("warning-v2", warningUserID, warningConfig, EventCritical)
	record("warning-v3", warningUserID, warningConfig, EventCritical)
	var warningCount int
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_actions
		WHERE user_id=$1 AND action_type='email_warning'`, warningUserID).Scan(&warningCount))
	require.Equal(t, 1, warningCount, "remaining above the threshold must not repeat the warning")

	record("warning-p1", warningUserID, warningConfig, EventPass)
	record("warning-p2", warningUserID, warningConfig, EventPass)
	record("warning-v4", warningUserID, warningConfig, EventCritical)
	record("warning-v5", warningUserID, warningConfig, EventCritical)
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_actions
		WHERE user_id=$1 AND action_type='email_warning'`, warningUserID).Scan(&warningCount))
	require.Equal(t, 2, warningCount, "dropping below the threshold must re-arm the edge")

	var disabledUserID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('disabled@example.test','user','active') RETURNING id`).
		Scan(&disabledUserID))
	disableConfig := integrationConfig(1, false)
	disableConfig.Notifications.AdminEmail = "security@example.test"
	disableConfig.Enforcement.EmailWarning = EmailWarningConfig{
		Enabled: true, RuleRevision: 1, LookbackCount: 2, ViolationThreshold: 2,
	}
	disableConfig.Enforcement.AccountDisable = AccountDisableConfig{Enabled: true, ViolationThreshold: 2}
	record("disable-v1", disabledUserID, disableConfig, EventCritical)
	second := record("disable-v2", disabledUserID, disableConfig, EventCritical)
	require.Equal(t, disabledUserID, second.DisabledUserID)
	var status string
	require.NoError(t, db.QueryRow(`SELECT status FROM users WHERE id=$1`, disabledUserID).Scan(&status))
	require.Equal(t, "disabled", status)
	var emailActions, disableActions int
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FILTER (WHERE action_type='email_warning'),
			COUNT(*) FILTER (WHERE action_type='account_disabled')
		FROM prompt_audit_enforcement_actions WHERE user_id=$1`, disabledUserID).
		Scan(&emailActions, &disableActions))
	require.Zero(t, emailActions, "the same outcome must prefer account_disabled")
	require.Equal(t, 1, disableActions)

	third := record("disable-v3", disabledUserID, disableConfig, EventCritical)
	require.Zero(t, third.DisabledUserID)
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_actions
		WHERE user_id=$1 AND action_type='account_disabled'`, disabledUserID).Scan(&disableActions))
	require.Equal(t, 1, disableActions, "an already-disabled user must not create another disable action")

	var outcomeJSON, actionJSON, stateJSON string
	require.NoError(t, db.QueryRow(`
		SELECT row_to_json(o)::text FROM prompt_audit_outcomes o WHERE id=$1`, second.Outcome.ID).Scan(&outcomeJSON))
	require.NoError(t, db.QueryRow(`
		SELECT row_to_json(a)::text FROM prompt_audit_enforcement_actions a
		WHERE user_id=$1 AND action_type='account_disabled'`, disabledUserID).Scan(&actionJSON))
	require.NoError(t, db.QueryRow(`
		SELECT row_to_json(s)::text FROM prompt_audit_enforcement_states s WHERE user_id=$1`, disabledUserID).Scan(&stateJSON))
	for _, stored := range []string{outcomeJSON, actionJSON, stateJSON} {
		require.NotContains(t, stored, promptCanary)
		require.NotContains(t, stored, DefaultAuditPrompt)
		require.NotContains(t, stored, FixedOutputPrompt)
	}
}

func TestPromptAuditSingleUserReenableResetsOnlyDisableCounter(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()

	var userID, otherUserID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('reset@example.test','user','active') RETURNING id`).
		Scan(&userID))
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('other-reset@example.test','user','active') RETURNING id`).
		Scan(&otherUserID))
	config := integrationConfig(1, false)
	config.Notifications.AdminEmail = "security@example.test"
	config.Enforcement.EmailWarning = EmailWarningConfig{
		Enabled: true, RuleRevision: 1, LookbackCount: 3, ViolationThreshold: 2,
	}
	config.Enforcement.AccountDisable = AccountDisableConfig{Enabled: true, ViolationThreshold: 1}
	snapshot := integrationSnapshot("reset-user")
	snapshot.UserID = userID
	snapshot.UserEmailSnapshot = "reset@example.test"
	completion, err := repo.RecordBlocking(ctx, snapshot, config, integrationResult(EventCritical))
	require.NoError(t, err)
	require.Equal(t, userID, completion.DisabledUserID)

	_, err = db.Exec(`
		INSERT INTO prompt_audit_enforcement_states (user_id,disable_violation_count)
		VALUES ($1,4) ON CONFLICT (user_id)
		DO UPDATE SET disable_violation_count=EXCLUDED.disable_violation_count`, otherUserID)
	require.NoError(t, err)

	var beforeRevision, beforeWindowStart int64
	var beforeArmed bool
	require.NoError(t, db.QueryRow(`
		SELECT email_rule_revision,email_window_start_outcome_id,email_rule_armed
		FROM prompt_audit_enforcement_states WHERE user_id=$1`, userID).
		Scan(&beforeRevision, &beforeWindowStart, &beforeArmed))

	entClient := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	tx, err := entClient.Tx(ctx)
	require.NoError(t, err)
	txCtx := dbent.NewTxContext(ctx, tx)
	require.NoError(t, repo.ResetDisableCounter(txCtx, appservice.PromptAuditCounterResetInput{
		UserID: userID, Username: "reset-user", UserEmail: "reset@example.test",
	}))
	_, err = tx.Client().ExecContext(txCtx, `UPDATE users SET status='active',updated_at=NOW() WHERE id=$1`, userID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	var status string
	var disableCount int
	var resetOutcomeID, afterRevision, afterWindowStart int64
	var afterArmed bool
	require.NoError(t, db.QueryRow(`SELECT status FROM users WHERE id=$1`, userID).Scan(&status))
	require.NoError(t, db.QueryRow(`
		SELECT disable_violation_count,disable_reset_outcome_id,
			email_rule_revision,email_window_start_outcome_id,email_rule_armed
		FROM prompt_audit_enforcement_states WHERE user_id=$1`, userID).
		Scan(&disableCount, &resetOutcomeID, &afterRevision, &afterWindowStart, &afterArmed))
	require.Equal(t, "active", status)
	require.Zero(t, disableCount)
	require.Equal(t, completion.Outcome.ID, resetOutcomeID)
	require.Equal(t, beforeRevision, afterRevision)
	require.Equal(t, beforeWindowStart, afterWindowStart)
	require.Equal(t, beforeArmed, afterArmed)

	var otherDisableCount, resetActions, outcomeCount int
	require.NoError(t, db.QueryRow(`
		SELECT disable_violation_count FROM prompt_audit_enforcement_states WHERE user_id=$1`, otherUserID).
		Scan(&otherDisableCount))
	require.Equal(t, 4, otherDisableCount)
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_actions
		WHERE user_id=$1 AND action_type='counter_reset'`, userID).Scan(&resetActions))
	require.Equal(t, 1, resetActions)
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_outcomes WHERE user_id=$1`, userID).Scan(&outcomeCount))
	require.Equal(t, 1, outcomeCount)
}

func TestPromptAuditNotificationRecipientsRetryIndependently(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	var userID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('mail-retry@example.test','user','active') RETURNING id`).
		Scan(&userID))
	config := integrationConfig(1, false)
	config.Notifications.AdminEmail = "security@example.test"
	config.Enforcement.AccountDisable = AccountDisableConfig{Enabled: true, ViolationThreshold: 1}
	snapshot := integrationSnapshot("mail-retry")
	snapshot.UserID = userID
	snapshot.UserEmailSnapshot = "mail-retry@example.test"
	completion, err := repo.RecordBlocking(ctx, snapshot, config, integrationResult(EventCritical))
	require.NoError(t, err)

	var actionID int64
	require.NoError(t, db.QueryRow(`
		SELECT id FROM prompt_audit_enforcement_actions
		WHERE trigger_outcome_id=$1 AND action_type='account_disabled'`, completion.Outcome.ID).
		Scan(&actionID))
	now := time.Now().UTC()
	require.NoError(t, repo.finishNotificationRecipient(ctx, actionID, "admin", nil, now))
	require.NoError(t, repo.finishNotificationRecipient(
		ctx, actionID, "user", errors.New("simulated delivery failure"), now,
	))

	var adminStatus, userStatus, lastError string
	var adminAttempts, userAttempts int
	require.NoError(t, db.QueryRow(`
		SELECT admin_email_status,user_email_status,admin_email_attempts,user_email_attempts,last_error
		FROM prompt_audit_enforcement_actions WHERE id=$1`, actionID).
		Scan(&adminStatus, &userStatus, &adminAttempts, &userAttempts, &lastError))
	require.Equal(t, "sent", adminStatus)
	require.Equal(t, "failed", userStatus)
	require.Equal(t, 1, adminAttempts)
	require.Equal(t, 1, userAttempts)
	require.Equal(t, "user_email_delivery_failed", lastError)

	delivery, found, err := repo.claimNotificationDelivery(ctx, now.Add(2*time.Minute))
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, actionID, delivery.ActionID)
	require.Equal(t, "sent", delivery.AdminEmailStatus)
	require.Equal(t, "failed", delivery.UserEmailStatus)
	require.NoError(t, repo.finishNotificationRecipient(ctx, actionID, "user", nil, now.Add(2*time.Minute)))

	var completedAt sql.NullTime
	require.NoError(t, db.QueryRow(`
		SELECT admin_email_status,user_email_status,admin_email_attempts,user_email_attempts,
			last_error,completed_at
		FROM prompt_audit_enforcement_actions WHERE id=$1`, actionID).
		Scan(&adminStatus, &userStatus, &adminAttempts, &userAttempts, &lastError, &completedAt))
	require.Equal(t, "sent", adminStatus)
	require.Equal(t, "sent", userStatus)
	require.Equal(t, 1, adminAttempts, "a successful recipient must not be retried")
	require.Equal(t, 2, userAttempts)
	require.Empty(t, lastError)
	require.True(t, completedAt.Valid)

	var noEmailUserID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('','user','active') RETURNING id`).
		Scan(&noEmailUserID))
	noEmailSnapshot := integrationSnapshot("no-user-email")
	noEmailSnapshot.UserID = noEmailUserID
	noEmailSnapshot.UserEmailSnapshot = ""
	noEmailCompletion, err := repo.RecordBlocking(ctx, noEmailSnapshot, config, integrationResult(EventCritical))
	require.NoError(t, err)
	require.NoError(t, db.QueryRow(`
		SELECT user_email_status,last_error
		FROM prompt_audit_enforcement_actions
		WHERE trigger_outcome_id=$1 AND action_type='account_disabled'`, noEmailCompletion.Outcome.ID).
		Scan(&userStatus, &lastError))
	require.Equal(t, "not_required", userStatus)
	require.Equal(t, "user_email_missing", lastError)
}

func TestPromptAuditConcurrentOutcomesKeepAccurateCounterAndSingleDisableAction(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	var userID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('concurrent-enforcement@example.test','user','active') RETURNING id`).
		Scan(&userID))
	config := integrationConfig(1, false)
	config.Notifications.AdminEmail = "security@example.test"
	config.Enforcement.AccountDisable = AccountDisableConfig{Enabled: true, ViolationThreshold: 4}

	const requestCount = 8
	var wg sync.WaitGroup
	errs := make(chan error, requestCount)
	for index := 0; index < requestCount; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			snapshot := integrationSnapshot(fmt.Sprintf("concurrent-%02d", index))
			snapshot.UserID = userID
			snapshot.UserEmailSnapshot = "concurrent-enforcement@example.test"
			_, recordErr := repo.RecordBlocking(ctx, snapshot, config, integrationResult(EventCritical))
			errs <- recordErr
		}(index)
	}
	wg.Wait()
	close(errs)
	for recordErr := range errs {
		require.NoError(t, recordErr)
	}

	var status string
	var disableCount, outcomeCount, actionCount int
	require.NoError(t, db.QueryRow(`SELECT status FROM users WHERE id=$1`, userID).Scan(&status))
	require.NoError(t, db.QueryRow(`
		SELECT disable_violation_count FROM prompt_audit_enforcement_states WHERE user_id=$1`, userID).
		Scan(&disableCount))
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_outcomes WHERE user_id=$1`, userID).Scan(&outcomeCount))
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_actions
		WHERE user_id=$1 AND action_type='account_disabled'`, userID).Scan(&actionCount))
	require.Equal(t, "disabled", status)
	require.Equal(t, requestCount, disableCount)
	require.Equal(t, requestCount, outcomeCount)
	require.Equal(t, 1, actionCount)
}

func TestPromptAuditAdminNeverAccumulatesOrAutoDisables(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	var adminID int64
	require.NoError(t, db.QueryRow(`
		INSERT INTO users(email,role,status) VALUES ('prompt-admin@example.test','admin','active') RETURNING id`).
		Scan(&adminID))
	config := integrationConfig(1, false)
	config.Notifications.AdminEmail = "security@example.test"
	config.Enforcement.AccountDisable = AccountDisableConfig{Enabled: true, ViolationThreshold: 1}
	snapshot := integrationSnapshot("admin-safe")
	snapshot.UserID = adminID
	snapshot.UserEmailSnapshot = "prompt-admin@example.test"

	completion, err := repo.RecordBlocking(ctx, snapshot, config, integrationResult(EventCritical))

	require.NoError(t, err)
	require.Zero(t, completion.DisabledUserID)
	var status string
	var disableCount, disableActions int
	require.NoError(t, db.QueryRow(`SELECT status FROM users WHERE id=$1`, adminID).Scan(&status))
	require.NoError(t, db.QueryRow(`
		SELECT disable_violation_count FROM prompt_audit_enforcement_states WHERE user_id=$1`, adminID).
		Scan(&disableCount))
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM prompt_audit_enforcement_actions
		WHERE user_id=$1 AND action_type='account_disabled'`, adminID).Scan(&disableActions))
	require.Equal(t, "active", status)
	require.Zero(t, disableCount)
	require.Zero(t, disableActions)
}

func TestPromptAuditServiceConfirmationKeepsPostPreviewEventsAndConcurrentDeletesAreSafe(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	filter := EventFilter{Decision: string(EventCritical), StartAt: &start, EndAt: &end}

	for i := 0; i < 12; i++ {
		_, err := repo.RecordBlocking(ctx, integrationSnapshot(fmt.Sprintf("event-%02d", i)), integrationConfig(1, true), integrationResult(EventCritical))
		require.NoError(t, err)
	}
	service := &PromptService{
		config: &fakeConfigStore{}, repo: repo, payload: NewRedisPayloadStore(nil), clock: fixedClock{now: now},
	}
	preview, err := service.PreviewDelete(ctx, filter, 77)
	require.NoError(t, err)
	require.Equal(t, int64(12), preview.MatchedCount)

	newer, err := repo.RecordBlocking(ctx, integrationSnapshot("post-preview"), integrationConfig(1, true), integrationResult(EventCritical))
	require.NoError(t, err)
	result, err := service.DeleteByFilter(ctx, DeleteByFilterRequest{
		Filter: filter, SnapshotMaxID: preview.SnapshotMaxID, FilterHash: preview.FilterHash,
		ConfirmationToken: preview.ConfirmationToken, Confirm: true,
	}, 77)
	require.NoError(t, err)
	require.Equal(t, int64(12), result.DeletedEvents)
	_, err = repo.GetEvent(ctx, newer.ID)
	require.NoError(t, err, "events created after delete-preview must survive")

	resetPromptAuditIntegrationDB(t, db)
	for i := 0; i < 24; i++ {
		_, err := repo.RecordBlocking(ctx, integrationSnapshot(fmt.Sprintf("race-%02d", i)), integrationConfig(1, true), integrationResult(EventCritical))
		require.NoError(t, err)
	}
	preview, err = repo.PreviewDelete(ctx, filter)
	require.NoError(t, err)

	type deleteOutcome struct {
		result *DeleteResult
		err    error
	}
	outcomes := make(chan deleteOutcome, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			deleted, deleteErr := repo.DeleteEventsByFilter(ctx, filter, preview.SnapshotMaxID, 1)
			outcomes <- deleteOutcome{result: deleted, err: deleteErr}
		}()
	}
	wg.Wait()
	close(outcomes)
	var deletedTotal int64
	for outcome := range outcomes {
		require.NoError(t, outcome.err)
		require.NotNil(t, outcome.result)
		deletedTotal += outcome.result.DeletedEvents
	}
	require.Equal(t, int64(24), deletedTotal, "concurrent deleters must neither double-count nor strand matching events")
	remaining, err := repo.ListEvents(ctx, filter, 1, 100)
	require.NoError(t, err)
	require.Zero(t, remaining.Total)
}
