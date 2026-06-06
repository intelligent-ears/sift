package finding

import (
	"time"

	"github.com/sift-scanner/sift/pkg/target"
)

// Severity represents the severity classification of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents the structured security finding schema as described in DESIGN.md.
type Finding struct {
	ID          string         `json:"id"`
	ModuleName  string         `json:"module_name"`
	Target      target.Target  `json:"target"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	FalsePos    float32        `json:"false_pos"` // ML-assigned FP probability [0,1]
	CreatedAt   time.Time      `json:"created_at"`
}
