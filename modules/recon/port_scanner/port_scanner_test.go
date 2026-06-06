package port_scanner

import (
	"context"
	"testing"

	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func TestPortScanner_Run(t *testing.T) {
	tests := []struct {
		name               string
		targetValue        string
		naabuOutput        string
		fingerprintxOutput string
		expectedOpenPorts  int
		expectedServices   int
	}{
		{
			name:        "Success finding ports and services",
			targetValue: "192.0.2.1",
			naabuOutput: "192.0.2.1:22\n192.0.2.1:80\n",
			fingerprintxOutput: `{"ip":"192.0.2.1","port":22,"service":"ssh","transport":"tcp","tls":false,"banner":"SSH-2.0-OpenSSH_8.9p1"}
{"ip":"192.0.2.1","port":80,"service":"http","transport":"tcp","tls":false,"banner":"Apache/2.4.52"}`,
			expectedOpenPorts: 2,
			expectedServices:  2,
		},
		{
			name:               "Success but fingerprintx fails",
			targetValue:        "192.0.2.1",
			naabuOutput:        "192.0.2.1:443\n",
			fingerprintxOutput: "",
			expectedOpenPorts:  1,
			expectedServices:   0,
		},
		{
			name:               "No open ports",
			targetValue:        "192.0.2.1",
			naabuOutput:        "",
			fingerprintxOutput: "",
			expectedOpenPorts:  0,
			expectedServices:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &PortScanner{
				runCmd: func(ctx context.Context, stdin string, name string, arg ...string) ([]byte, error) {
					if name == "naabu" {
						return []byte(tt.naabuOutput), nil
					}
					if name == "fingerprintx" {
						return []byte(tt.fingerprintxOutput), nil
					}
					return nil, nil
				},
			}

			task := module.Task{
				ID:     "task-1",
				Type:   "ip",
				Target: target.Target{ID: "tgt-1", Type: target.TargetTypeIP, Value: tt.targetValue},
			}

			findings, nextTasks, err := mod.Run(context.Background(), task)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}

			openPortCount := 0
			serviceCount := 0
			for _, nt := range nextTasks {
				if nt.Type == "open_port" {
					openPortCount++
				} else if nt.Type == "service" {
					serviceCount++
				}
			}

			if openPortCount != tt.expectedOpenPorts {
				t.Errorf("expected %d open_port tasks, got %d", tt.expectedOpenPorts, openPortCount)
			}
			if serviceCount != tt.expectedServices {
				t.Errorf("expected %d service tasks, got %d", tt.expectedServices, serviceCount)
			}
		})
	}
}
