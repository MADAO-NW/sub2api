//go:build unit

package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration224ExtendsPromptAuditWithoutRewritingHistory(t *testing.T) {
	content, err := FS.ReadFile("224_prompt_audit_enforcement.sql")
	require.NoError(t, err)

	sql := strings.Join(strings.Fields(string(content)), " ")
	require.Contains(t, sql, "ALTER TABLE prompt_audit_events ADD COLUMN IF NOT EXISTS model_results JSONB NOT NULL DEFAULT '{}'::jsonb")
	require.Contains(t, sql, "ADD CONSTRAINT chk_prompt_audit_events_model_results_json")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS prompt_audit_outcomes")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS prompt_audit_enforcement_actions")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS prompt_audit_enforcement_states")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS prompt_audit_model_attempts")
	require.Contains(t, sql, "REFERENCES prompt_audit_jobs(id) ON DELETE CASCADE")
	require.Contains(t, sql, "UNIQUE (job_id, job_attempt, model_sequence, call_attempt)")
	require.Contains(t, sql, "response_body TEXT NOT NULL DEFAULT ''")
	require.Contains(t, sql, "response_sha256")
	require.Contains(t, sql, "response_truncated")
	require.Contains(t, sql, "response_purged_at")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_prompt_audit_enforcement_actions_mail_due")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_prompt_audit_model_attempts_response_cleanup")
	require.NotContains(t, sql, "ADD COLUMN IF NOT EXISTS full_prompt")
	require.NotContains(t, sql, "UPDATE prompt_audit_")
}
