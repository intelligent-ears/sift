package store

import (
	"context"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/target"
)

// Store defines the database persistence contract for scans, targets, and findings.
type Store interface {
	SaveFinding(ctx context.Context, f finding.Finding) error
	GetFindings(ctx context.Context, filter FindingFilter) ([]finding.Finding, error)
	SaveTarget(ctx context.Context, t target.Target) error
	GetTargets(ctx context.Context) ([]target.Target, error)
	CreateScan(ctx context.Context) (string, error)
	UpdateScanStatus(ctx context.Context, scanID, status string) error
}

// FindingFilter provides criteria to filter findings from the store.
type FindingFilter struct {
	TargetID   string
	Severity   finding.Severity
	ScanID     string
	ModuleName string
}

type contextKey string

const ScanIDContextKey contextKey = "scan_id"

// WithScanID attaches a scan ID to the context.
func WithScanID(ctx context.Context, scanID string) context.Context {
	return context.WithValue(ctx, ScanIDContextKey, scanID)
}
