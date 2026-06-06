package module

import (
	"context"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/target"
)

// TaskType represents the subject or type of scanning task.
type TaskType string

// Task represents a scanning job passed to modules.
type Task struct {
	ID       string         `json:"id"`
	Type     TaskType       `json:"type"`
	Target   target.Target  `json:"target"`
	Payload  map[string]any `json:"payload"`
	ParentID string         `json:"parent_id"`
}

// Finding is type-aliased to finding.Finding for design compatibility.
type Finding = finding.Finding

// Severity is type-aliased to finding.Severity for design compatibility.
type Severity = finding.Severity

// Severity constants re-exposed for module package consumers.
const (
	SeverityCritical = finding.SeverityCritical
	SeverityHigh     = finding.SeverityHigh
	SeverityMedium   = finding.SeverityMedium
	SeverityLow      = finding.SeverityLow
	SeverityInfo     = finding.SeverityInfo
)

// Module is the core interface that every scanner module must implement.
type Module interface {
	Name() string
	Consumes() []TaskType // NATS subjects this module subscribes to
	Produces() []TaskType // task types this module can emit downstream
	Run(ctx context.Context, task Task) ([]Finding, []Task, error)
}
