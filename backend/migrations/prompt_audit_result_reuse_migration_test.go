//go:build unit

package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration229AddsPromptAuditResultReuseTrace(t *testing.T) {
	content, err := FS.ReadFile("229_prompt_audit_result_reuse.sql")
	require.NoError(t, err)

	sql := strings.Join(strings.Fields(string(content)), " ")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS reused_from_outcome_id BIGINT")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS evaluation_input_hash VARCHAR(64) NOT NULL DEFAULT ''")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS evaluation_contract_version VARCHAR(64) NOT NULL DEFAULT 'whole-prompt-v1'")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS role_contract_hash VARCHAR(64) NOT NULL DEFAULT ''")
	require.Contains(t, sql, "ADD CONSTRAINT fk_prompt_audit_outcomes_reused_from FOREIGN KEY (reused_from_outcome_id) REFERENCES prompt_audit_outcomes(id) ON DELETE SET NULL")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcomes_role_reuse_lookup")
	require.Contains(t, sql, "WHERE partial_failure = FALSE AND reused_from_outcome_id IS NULL")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_prompt_audit_outcomes_reused_from")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS prompt_audit_segment_results")
	require.Contains(t, sql, "CHECK (adapter = 'openai_compatible_qwen')")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_prompt_audit_segment_results_reuse")
	require.Contains(t, sql, "CREATE TABLE IF NOT EXISTS prompt_audit_outcome_segments")
	require.Contains(t, sql, "PRIMARY KEY (outcome_id, endpoint_id, segment_order)")
}
