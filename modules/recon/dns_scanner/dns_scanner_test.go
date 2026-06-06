package dns_scanner

import (
	"context"
	"net"
	"testing"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func TestDNSScanner_Run(t *testing.T) {
	tests := []struct {
		name          string
		targetValue   string
		lookupNSErr   error
		nsList        []*net.NS
		digOutput     string
		expectedFinds int
	}{
		{
			name:        "Zone transfer succeeds",
			targetValue: "example.com",
			nsList: []*net.NS{
				{Host: "ns1.example.com."},
			},
			digOutput: `
; <<>> DiG 9.18.1 <<>> axfr @ns1.example.com example.com
example.com.		86400	IN	SOA	ns1.example.com. hostmaster.example.com. (
					2026060601 ; serial
					3600       ; refresh
					1800       ; retry
					604800     ; expire
					86400      ; minimum
					)
example.com.		86400	IN	NS	ns1.example.com.
example.com.		86400	IN	A	192.0.2.1
example.com.		86400	IN	SOA	ns1.example.com. hostmaster.example.com. (
					2026060601 ; serial
					)
`,
			expectedFinds: 1,
		},
		{
			name:        "Zone transfer refused/failed",
			targetValue: "example.com",
			nsList: []*net.NS{
				{Host: "ns1.example.com."},
			},
			digOutput: `
; <<>> DiG 9.18.1 <<>> axfr @ns1.example.com example.com
; Transfer failed.
`,
			expectedFinds: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &DNSScanner{
				runCmd: func(ctx context.Context, name string, arg ...string) ([]byte, error) {
					return []byte(tt.digOutput), nil
				},
				lookupNS: func(ctx context.Context, host string) ([]*net.NS, error) {
					if tt.lookupNSErr != nil {
						return nil, tt.lookupNSErr
					}
					return tt.nsList, nil
				},
			}

			task := module.Task{
				ID:     "task-1",
				Type:   "domain",
				Target: target.Target{ID: "tgt-1", Type: target.TargetTypeDomain, Value: tt.targetValue},
			}

			findings, nextTasks, err := mod.Run(context.Background(), task)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(nextTasks) != 0 {
				t.Errorf("expected 0 next tasks, got %d", len(nextTasks))
			}

			if len(findings) != tt.expectedFinds {
				t.Errorf("expected %d findings, got %d", tt.expectedFinds, len(findings))
			}

			if len(findings) > 0 {
				f := findings[0]
				if f.Severity != finding.SeverityMedium {
					t.Errorf("expected Severity to be MEDIUM, got %v", f.Severity)
				}
				if f.Title != "DNS Zone Transfer Allowed" {
					t.Errorf("expected Title to be 'DNS Zone Transfer Allowed', got %q", f.Title)
				}
			}
		})
	}
}
