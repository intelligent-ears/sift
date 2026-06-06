package ip_lookup

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func TestIPLookup_Run(t *testing.T) {
	tests := []struct {
		name          string
		targetValue   string
		lookupIPErr   error
		ipList        []net.IPAddr
		expectedTasks int
	}{
		{
			name:        "Success with IPv4 and IPv6",
			targetValue: "example.com",
			ipList: []net.IPAddr{
				{IP: net.ParseIP("192.0.2.1")},
				{IP: net.ParseIP("2001:db8::1")},
				{IP: net.ParseIP("192.0.2.1")}, // duplicate check
			},
			expectedTasks: 2,
		},
		{
			name:          "Lookup error",
			targetValue:   "nonexistent.example.com",
			lookupIPErr:   errors.New("no such host"),
			expectedTasks: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &IPLookup{
				lookupIP: func(ctx context.Context, host string) ([]net.IPAddr, error) {
					if tt.lookupIPErr != nil {
						return nil, tt.lookupIPErr
					}
					return tt.ipList, nil
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
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}

			if len(nextTasks) != tt.expectedTasks {
				t.Errorf("expected %d next tasks, got %d", tt.expectedTasks, len(nextTasks))
			}

			for _, nt := range nextTasks {
				if nt.Type != "ip" {
					t.Errorf("expected task type 'ip', got %q", nt.Type)
				}
				if nt.Target.Type != target.TargetTypeIP {
					t.Errorf("expected target type IP, got %v", nt.Target.Type)
				}
			}
		})
	}
}
