package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

func (r *PostgreSQLRepository) FindReusableSegments(
	ctx context.Context,
	keys []SegmentReuseKey,
) (map[string]SegmentAuditResult, error) {
	result := make(map[string]SegmentAuditResult, len(keys))
	if len(keys) == 0 {
		return result, nil
	}
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("prompt audit database unavailable")
	}
	type lookupInput struct {
		LookupKey                 string `json:"lookup_key"`
		ContentHash               string `json:"content_hash"`
		PolicyRole                string `json:"policy_role"`
		TurnScope                 string `json:"turn_scope"`
		EndpointID                string `json:"endpoint_id"`
		Adapter                   string `json:"adapter"`
		ConfigVersion             int64  `json:"config_version"`
		AuditPromptHash           string `json:"audit_prompt_hash"`
		RolePromptHash            string `json:"role_prompt_hash"`
		EvaluationContractVersion string `json:"evaluation_contract_version"`
		PromptContractVersion     string `json:"prompt_contract_version"`
	}
	inputs := make([]lookupInput, 0, len(keys))
	keysByID := make(map[string]SegmentReuseKey, len(keys))
	for _, key := range keys {
		inputs = append(inputs, lookupInput{
			LookupKey: key.LookupKey, ContentHash: key.ContentHash, PolicyRole: key.PolicyRole,
			TurnScope: key.TurnScope, EndpointID: key.EndpointID, Adapter: key.Adapter,
			ConfigVersion: key.ConfigVersion, AuditPromptHash: key.AuditPromptHash,
			RolePromptHash: key.RolePromptHash, EvaluationContractVersion: key.EvaluationContractVersion,
			PromptContractVersion: key.PromptContractVersion,
		})
		keysByID[key.LookupKey] = key
	}
	raw, err := json.Marshal(inputs)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT k.lookup_key,s.id,s.source_role,s.model,s.decision,s.action,s.categories
		FROM jsonb_to_recordset($1::jsonb) AS k(
			lookup_key TEXT,content_hash VARCHAR(64),policy_role VARCHAR(16),turn_scope VARCHAR(16),
			endpoint_id TEXT,adapter VARCHAR(32),config_version BIGINT,audit_prompt_hash VARCHAR(64),
			role_prompt_hash VARCHAR(64),evaluation_contract_version VARCHAR(64),prompt_contract_version VARCHAR(64)
		)
		JOIN LATERAL (
			SELECT id,source_role,model,decision,action,categories
			FROM prompt_audit_segment_results s
			WHERE s.content_hash=k.content_hash AND s.policy_role=k.policy_role AND s.turn_scope=k.turn_scope
			  AND s.endpoint_id=k.endpoint_id AND s.adapter=k.adapter AND s.config_version=k.config_version
			  AND s.audit_prompt_hash=k.audit_prompt_hash AND s.role_prompt_hash=k.role_prompt_hash
			  AND s.evaluation_contract_version=k.evaluation_contract_version
			  AND s.prompt_contract_version=k.prompt_contract_version
			ORDER BY s.id DESC LIMIT 1
		) s ON TRUE`, raw)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var lookupKey, sourceRole, model string
		var id int64
		var decision EventDecision
		var action Action
		var categoriesJSON []byte
		if err := rows.Scan(&lookupKey, &id, &sourceRole, &model, &decision, &action, &categoriesJSON); err != nil {
			return nil, err
		}
		var categories []string
		if err := json.Unmarshal(categoriesJSON, &categories); err != nil {
			return nil, err
		}
		key, ok := keysByID[lookupKey]
		if !ok {
			return nil, errors.New("prompt audit segment lookup returned an unknown key")
		}
		result[lookupKey] = SegmentAuditResult{
			ID: id, ReuseKey: key, SourceRole: sourceRole, Model: model,
			Decision: decision, Action: action, Categories: categories,
		}
	}
	return result, rows.Err()
}

func persistSegmentEvaluation(
	ctx context.Context,
	tx *sql.Tx,
	outcomeID int64,
	modelResults ModelResults,
) error {
	if modelResults.Aggregation.ReusedFromOutcomeID != nil {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO prompt_audit_outcome_segments (
				outcome_id,endpoint_id,segment_order,source_role,turn_scope,source_segment_result_id
			)
			SELECT $1,endpoint_id,segment_order,source_role,turn_scope,source_segment_result_id
			FROM prompt_audit_outcome_segments WHERE outcome_id=$2
			ON CONFLICT (outcome_id,endpoint_id,segment_order) DO NOTHING`,
			outcomeID, *modelResults.Aggregation.ReusedFromOutcomeID)
		return err
	}
	insertedIDs, err := insertSegmentResults(ctx, tx, outcomeID, modelResults.NewSegmentResults)
	if err != nil {
		return err
	}
	return insertSegmentUses(ctx, tx, outcomeID, modelResults.SegmentUses, insertedIDs)
}

func insertSegmentResults(
	ctx context.Context,
	tx *sql.Tx,
	outcomeID int64,
	results []SegmentAuditResult,
) (map[string]int64, error) {
	insertedIDs := make(map[string]int64, len(results))
	if len(results) == 0 {
		return insertedIDs, nil
	}
	type insertInput struct {
		LookupKey                 string        `json:"lookup_key"`
		EndpointID                string        `json:"endpoint_id"`
		Adapter                   string        `json:"adapter"`
		Model                     string        `json:"model"`
		SourceRole                string        `json:"source_role"`
		PolicyRole                string        `json:"policy_role"`
		TurnScope                 string        `json:"turn_scope"`
		ContentHash               string        `json:"content_hash"`
		Decision                  EventDecision `json:"decision"`
		Action                    Action        `json:"action"`
		Categories                []string      `json:"categories"`
		ConfigVersion             int64         `json:"config_version"`
		AuditPromptHash           string        `json:"audit_prompt_hash"`
		RolePromptHash            string        `json:"role_prompt_hash"`
		EvaluationContractVersion string        `json:"evaluation_contract_version"`
		PromptContractVersion     string        `json:"prompt_contract_version"`
	}
	inputs := make([]insertInput, 0, len(results))
	for _, result := range results {
		key := result.ReuseKey
		inputs = append(inputs, insertInput{
			LookupKey: key.LookupKey, EndpointID: key.EndpointID, Adapter: key.Adapter, Model: result.Model,
			SourceRole: result.SourceRole, PolicyRole: key.PolicyRole, TurnScope: key.TurnScope,
			ContentHash: key.ContentHash, Decision: result.Decision, Action: result.Action,
			Categories: append([]string(nil), result.Categories...), ConfigVersion: key.ConfigVersion,
			AuditPromptHash: key.AuditPromptHash, RolePromptHash: key.RolePromptHash,
			EvaluationContractVersion: key.EvaluationContractVersion,
			PromptContractVersion:     key.PromptContractVersion,
		})
	}
	raw, err := json.Marshal(inputs)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
		WITH input AS (
			SELECT * FROM jsonb_to_recordset($2::jsonb) AS i(
				lookup_key TEXT,endpoint_id TEXT,adapter VARCHAR(32),model TEXT,source_role VARCHAR(16),
				policy_role VARCHAR(16),turn_scope VARCHAR(16),content_hash VARCHAR(64),decision VARCHAR(32),
				action VARCHAR(32),categories JSONB,config_version BIGINT,audit_prompt_hash VARCHAR(64),
				role_prompt_hash VARCHAR(64),evaluation_contract_version VARCHAR(64),prompt_contract_version VARCHAR(64)
			)
		), inserted AS (
			INSERT INTO prompt_audit_segment_results (
				source_outcome_id,endpoint_id,adapter,model,source_role,policy_role,turn_scope,content_hash,
				decision,action,categories,config_version,audit_prompt_hash,role_prompt_hash,
				evaluation_contract_version,prompt_contract_version
			)
			SELECT $1,endpoint_id,adapter,model,source_role,policy_role,turn_scope,content_hash,
				decision,action,categories,config_version,audit_prompt_hash,role_prompt_hash,
				evaluation_contract_version,prompt_contract_version
			FROM input
			RETURNING id,endpoint_id,policy_role,turn_scope,content_hash,config_version,audit_prompt_hash,
				role_prompt_hash,evaluation_contract_version,prompt_contract_version
		)
		SELECT i.lookup_key,n.id FROM input i JOIN inserted n
		  ON n.endpoint_id=i.endpoint_id AND n.policy_role=i.policy_role AND n.turn_scope=i.turn_scope
		 AND n.content_hash=i.content_hash AND n.config_version=i.config_version
		 AND n.audit_prompt_hash=i.audit_prompt_hash AND n.role_prompt_hash=i.role_prompt_hash
		 AND n.evaluation_contract_version=i.evaluation_contract_version
		 AND n.prompt_contract_version=i.prompt_contract_version`, outcomeID, raw)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var lookupKey string
		var id int64
		if err := rows.Scan(&lookupKey, &id); err != nil {
			return nil, err
		}
		insertedIDs[lookupKey] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(insertedIDs) != len(results) {
		return nil, errors.New("prompt audit segment result mapping is incomplete")
	}
	return insertedIDs, nil
}

func insertSegmentUses(
	ctx context.Context,
	tx *sql.Tx,
	outcomeID int64,
	uses []SegmentResultUse,
	insertedIDs map[string]int64,
) error {
	if len(uses) == 0 {
		return nil
	}
	type useInput struct {
		EndpointID            string `json:"endpoint_id"`
		SegmentOrder          int    `json:"segment_order"`
		SourceRole            string `json:"source_role"`
		TurnScope             string `json:"turn_scope"`
		SourceSegmentResultID int64  `json:"source_segment_result_id"`
	}
	inputs := make([]useInput, 0, len(uses))
	for _, use := range uses {
		resultID := use.SourceSegmentResultID
		if resultID == 0 {
			resultID = insertedIDs[use.LookupKey]
		}
		if resultID == 0 {
			return errors.New("prompt audit segment use has no source result")
		}
		inputs = append(inputs, useInput{
			EndpointID: use.EndpointID, SegmentOrder: use.SegmentOrder, SourceRole: use.SourceRole,
			TurnScope: use.TurnScope, SourceSegmentResultID: resultID,
		})
	}
	raw, err := json.Marshal(inputs)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO prompt_audit_outcome_segments (
			outcome_id,endpoint_id,segment_order,source_role,turn_scope,source_segment_result_id
		)
		SELECT $1,i.endpoint_id,i.segment_order,i.source_role,i.turn_scope,i.source_segment_result_id
		FROM jsonb_to_recordset($2::jsonb) AS i(
			endpoint_id TEXT,segment_order INT,source_role VARCHAR(16),turn_scope VARCHAR(16),source_segment_result_id BIGINT
		)
		JOIN prompt_audit_segment_results s
		  ON s.id=i.source_segment_result_id AND s.endpoint_id=i.endpoint_id
		ON CONFLICT (outcome_id,endpoint_id,segment_order) DO NOTHING`, outcomeID, raw)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != int64(len(inputs)) {
		return errors.New("prompt audit segment use endpoint does not match source result")
	}
	return nil
}

func (r *PostgreSQLRepository) loadEventSegments(ctx context.Context, eventID int64) ([]PromptAuditSegmentDetail, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT u.endpoint_id,u.segment_order,u.source_role,s.policy_role,u.turn_scope,
			u.source_segment_result_id,
			CASE WHEN s.source_outcome_id=o.id THEN NULL ELSE u.source_segment_result_id END,
			s.decision,s.action,s.categories
		FROM prompt_audit_outcomes o
		JOIN prompt_audit_outcome_segments u ON u.outcome_id=o.id
		JOIN prompt_audit_segment_results s ON s.id=u.source_segment_result_id
		WHERE o.event_id=$1
		ORDER BY u.endpoint_id,u.segment_order`, eventID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	details := make([]PromptAuditSegmentDetail, 0)
	for rows.Next() {
		var detail PromptAuditSegmentDetail
		var reused sql.NullInt64
		var categoriesJSON []byte
		if err := rows.Scan(
			&detail.EndpointID, &detail.SegmentOrder, &detail.SourceRole, &detail.PolicyRole,
			&detail.TurnScope, &detail.SourceSegmentResultID, &reused, &detail.Decision,
			&detail.Action, &categoriesJSON,
		); err != nil {
			return nil, err
		}
		if reused.Valid {
			detail.ReusedFromSegmentResultID = &reused.Int64
		}
		if err := json.Unmarshal(categoriesJSON, &detail.Categories); err != nil {
			return nil, err
		}
		details = append(details, detail)
	}
	return details, rows.Err()
}
