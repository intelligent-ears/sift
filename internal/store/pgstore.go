package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/target"
)

// PGStore implements the Store interface using pgx/v5 pool.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore connects to PostgreSQL using the given connection string and verifies connection via Ping.
func NewPGStore(connString string) (*PGStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	return &PGStore{pool: pool}, nil
}

// Close closes the underlying pgxpool connection.
func (s *PGStore) Close() {
	s.pool.Close()
}

// SaveTarget inserts or updates a target in PostgreSQL.
func (s *PGStore) SaveTarget(ctx context.Context, t target.Target) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}

	query := `
		INSERT INTO targets (id, type, value, org, tags)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE
		SET type = EXCLUDED.type,
			value = EXCLUDED.value,
			org = EXCLUDED.org,
			tags = EXCLUDED.tags
	`
	_, err := s.pool.Exec(ctx, query, t.ID, string(t.Type), t.Value, t.Org, t.Tags)
	if err != nil {
		return fmt.Errorf("failed to save target: %w", err)
	}
	return nil
}

// GetTargets retrieves all targets from the database.
func (s *PGStore) GetTargets(ctx context.Context) ([]target.Target, error) {
	query := `SELECT id, type, value, org, tags FROM targets`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query targets: %w", err)
	}
	defer rows.Close()

	var targets []target.Target
	for rows.Next() {
		var t target.Target
		var typeStr string
		var tags []string

		err := rows.Scan(&t.ID, &typeStr, &t.Value, &t.Org, &tags)
		if err != nil {
			return nil, fmt.Errorf("failed to scan target row: %w", err)
		}
		t.Type = target.TargetType(typeStr)
		t.Tags = tags
		targets = append(targets, t)
	}
	return targets, nil
}

// SaveFinding inserts or updates a finding in PostgreSQL. It saves the finding's target first.
func (s *PGStore) SaveFinding(ctx context.Context, f finding.Finding) error {
	if f.Target.ID == "" {
		f.Target.ID = uuid.New().String()
	}

	// Ensure the finding target is persisted first to maintain foreign key integrity
	err := s.SaveTarget(ctx, f.Target)
	if err != nil {
		return fmt.Errorf("failed to save target for finding: %w", err)
	}

	var scanID *string
	if val := ctx.Value(ScanIDContextKey); val != nil {
		if sVal, ok := val.(string); ok && sVal != "" {
			scanID = &sVal
		}
	}

	if scanID == nil && f.Evidence != nil {
		if sVal, ok := f.Evidence["scan_id"].(string); ok && sVal != "" {
			scanID = &sVal
		}
	}

	evidenceJSON, err := json.Marshal(f.Evidence)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	if f.ID == "" {
		f.ID = uuid.New().String()
	}

	query := `
		INSERT INTO findings (id, module_name, target_id, severity, title, description, evidence, false_pos_prob, created_at, scan_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE
		SET module_name = EXCLUDED.module_name,
			target_id = EXCLUDED.target_id,
			severity = EXCLUDED.severity,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			evidence = EXCLUDED.evidence,
			false_pos_prob = EXCLUDED.false_pos_prob,
			created_at = EXCLUDED.created_at,
			scan_id = COALESCE(EXCLUDED.scan_id, findings.scan_id)
	`

	createdAt := f.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	_, err = s.pool.Exec(ctx, query,
		f.ID,
		f.ModuleName,
		f.Target.ID,
		string(f.Severity),
		f.Title,
		f.Description,
		evidenceJSON,
		f.FalsePos,
		createdAt,
		scanID,
	)
	if err != nil {
		return fmt.Errorf("failed to save finding: %w", err)
	}

	return nil
}

// GetFindings queries findings using the provided FindingFilter.
func (s *PGStore) GetFindings(ctx context.Context, filter FindingFilter) ([]finding.Finding, error) {
	query := `
		SELECT f.id, f.module_name, f.severity, f.title, f.description, f.evidence, f.false_pos_prob, f.created_at,
		       t.id, t.type, t.value, t.org, t.tags
		FROM findings f
		JOIN targets t ON f.target_id = t.id
		WHERE 1=1
	`
	var args []any
	argPlaceholderNum := 1

	if filter.TargetID != "" {
		query += fmt.Sprintf(" AND f.target_id = $%d", argPlaceholderNum)
		args = append(args, filter.TargetID)
		argPlaceholderNum++
	}
	if filter.Severity != "" {
		query += fmt.Sprintf(" AND f.severity = $%d", argPlaceholderNum)
		args = append(args, string(filter.Severity))
		argPlaceholderNum++
	}
	if filter.ScanID != "" {
		query += fmt.Sprintf(" AND f.scan_id = $%d", argPlaceholderNum)
		args = append(args, filter.ScanID)
		argPlaceholderNum++
	}
	if filter.ModuleName != "" {
		query += fmt.Sprintf(" AND f.module_name = $%d", argPlaceholderNum)
		args = append(args, filter.ModuleName)
		argPlaceholderNum++
	}

	query += " ORDER BY f.created_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []finding.Finding
	for rows.Next() {
		var f finding.Finding
		var sevStr string
		var evidenceBytes []byte
		var t target.Target
		var typeStr string
		var tags []string

		err := rows.Scan(
			&f.ID,
			&f.ModuleName,
			&sevStr,
			&f.Title,
			&f.Description,
			&evidenceBytes,
			&f.FalsePos,
			&f.CreatedAt,
			&t.ID,
			&typeStr,
			&t.Value,
			&t.Org,
			&tags,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}

		f.Severity = finding.Severity(sevStr)
		t.Type = target.TargetType(typeStr)
		t.Tags = tags
		f.Target = t

		if len(evidenceBytes) > 0 {
			var evidence map[string]any
			if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
				return nil, fmt.Errorf("failed to unmarshal finding evidence: %w", err)
			}
			f.Evidence = evidence
		}

		findings = append(findings, f)
	}

	return findings, nil
}

// CreateScan generates a new scan record with status RUNNING.
func (s *PGStore) CreateScan(ctx context.Context) (string, error) {
	var id string
	query := `INSERT INTO scans (started_at, status, config) VALUES ($1, $2, $3) RETURNING id`
	err := s.pool.QueryRow(ctx, query, time.Now(), "RUNNING", []byte("{}")).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to create scan: %w", err)
	}
	return id, nil
}

// UpdateScanStatus modifies a scan status and updates ended_at if the scan has finished.
func (s *PGStore) UpdateScanStatus(ctx context.Context, scanID, status string) error {
	var query string
	var err error

	if status == "COMPLETED" || status == "FAILED" || status == "FINISHED" {
		query = `UPDATE scans SET status = $1, ended_at = $2 WHERE id = $3`
		_, err = s.pool.Exec(ctx, query, status, time.Now(), scanID)
	} else {
		query = `UPDATE scans SET status = $1 WHERE id = $2`
		_, err = s.pool.Exec(ctx, query, status, scanID)
	}

	if err != nil {
		return fmt.Errorf("failed to update scan status to %s: %w", status, err)
	}
	return nil
}

// Ensure PGStore implements Store interface.
var _ Store = (*PGStore)(nil)
