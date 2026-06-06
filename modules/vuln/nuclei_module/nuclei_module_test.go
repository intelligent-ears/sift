package nuclei_module

import (
	"context"
	"testing"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func TestNucleiModule_Run(t *testing.T) {
	tests := []struct {
		name              string
		templates         []string
		nucleiStdout      string
		expectedFindings  int
		expectedOutcomes  int
		expectedHitStatus map[string]bool
	}{
		{
			name:      "Vulnerability found",
			templates: []string{"wp-xss.yaml", "generic-cve.yaml"},
			nucleiStdout: `{"template-id":"wp-xss","matcher-name":"default","matched-at":"http://example.com/","info":{"name":"WordPress XSS","severity":"high","description":"XSS vulnerability"},"curl-command":"curl -i ...","ip":"192.0.2.1"}
`,
			expectedFindings: 1,
			expectedOutcomes: 2,
			expectedHitStatus: map[string]bool{
				"wp-xss":           true,
				"generic-cve": false,
			},
		},
		{
			name:              "No templates to run",
			templates:         []string{},
			nucleiStdout:      "",
			expectedFindings:  0,
			expectedOutcomes:  0,
			expectedHitStatus: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &NucleiModule{
				runCmd: func(ctx context.Context, name string, arg ...string) ([]byte, error) {
					return []byte(tt.nucleiStdout), nil
				},
			}

			task := module.Task{
				ID:     "task-1",
				Type:   "nuclei_execution",
				Target: target.Target{ID: "tgt-1", Type: target.TargetTypeURL, Value: "http://example.com"},
				Payload: map[string]any{
					"url":       "http://example.com",
					"templates": tt.templates,
				},
			}

			findings, nextTasks, err := mod.Run(context.Background(), task)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(findings) != tt.expectedFindings {
				t.Errorf("expected %d findings, got %d", tt.expectedFindings, len(findings))
			}

			if len(nextTasks) != tt.expectedOutcomes {
				t.Errorf("expected %d outcomes tasks, got %d", tt.expectedOutcomes, len(nextTasks))
			}

			if len(findings) > 0 {
				f := findings[0]
				if f.Severity != finding.SeverityHigh {
					t.Errorf("expected mapped severity HIGH, got %v", f.Severity)
				}
				if f.Title != "WordPress XSS" {
					t.Errorf("expected title 'WordPress XSS', got %q", f.Title)
				}
			}

			outcomesMap := make(map[string]bool)
			for _, nt := range nextTasks {
				if nt.Type != "sift.outcomes" {
					t.Errorf("expected task type 'sift.outcomes', got %q", nt.Type)
				}
				templateID := nt.Payload["template_id"].(string)
				hit := nt.Payload["hit"].(bool)
				outcomesMap[templateID] = hit
			}

			for tid, expectedHit := range tt.expectedHitStatus {
				if gotHit, ok := outcomesMap[tid]; !ok || gotHit != expectedHit {
					t.Errorf("expected outcome for %q to have hit=%t, got hit=%t (present=%t)", tid, expectedHit, gotHit, ok)
				}
			}
		})
	}
}
