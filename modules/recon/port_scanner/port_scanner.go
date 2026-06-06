package port_scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/config"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func init() {
	registry.Register(&PortScanner{})
}

// PortScanner wraps naabu and fingerprintx to discover open ports and fingerprint services.
type PortScanner struct {
	runCmd func(ctx context.Context, stdin string, name string, arg ...string) ([]byte, error)
}

func (p *PortScanner) getRunCmd() func(context.Context, string, string, ...string) ([]byte, error) {
	if p.runCmd != nil {
		return p.runCmd
	}
	return func(ctx context.Context, stdin string, name string, arg ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, arg...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		return cmd.Output()
	}
}

// Name returns the module name.
func (p *PortScanner) Name() string {
	return "port_scanner"
}

// Consumes returns the task types this module handles.
func (p *PortScanner) Consumes() []module.TaskType {
	return []module.TaskType{"ip"}
}

// Produces returns the task types this module produces.
func (p *PortScanner) Produces() []module.TaskType {
	return []module.TaskType{"open_port", "service"}
}

type fingerprintxOutput struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Service   string `json:"service"`
	Transport string `json:"transport"`
	TLS       bool   `json:"tls"`
	Banner    string `json:"banner"`
}

// Run executes naabu and fingerprintx.
func (p *PortScanner) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	ip := strings.TrimSpace(task.Target.Value)
	if ip == "" {
		return nil, nil, fmt.Errorf("empty ip target")
	}

	cfg := config.Get()
	ports := cfg.PortScannerPorts
	if ports == "" {
		ports = "21,22,25,80,443,3306,5432,6379,8080,8443"
	}
	rate := strconv.Itoa(cfg.ScanningPacketsPerSecond)
	if rate == "0" {
		rate = "5"
	}

	runCmd := p.getRunCmd()

	// 1. Run naabu
	naabuOut, err := runCmd(ctx, "", "naabu", "-host", ip, "-p", ports, "-rate", rate, "-silent")
	if err != nil {
		// Suppress and return empty, as binary execution failure might mean naabu is not installed or network issue
		return nil, nil, nil
	}

	var openPorts []int
	var fpInputLines []string

	lines := strings.Split(string(naabuOut), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			portStr := parts[len(parts)-1]
			if pVal, err := strconv.Atoi(portStr); err == nil {
				openPorts = append(openPorts, pVal)
				fpInputLines = append(fpInputLines, line)
			}
		}
	}

	if len(openPorts) == 0 {
		return nil, nil, nil
	}

	var nextTasks []module.Task

	// Emit open_port tasks
	for _, port := range openPorts {
		nextTasks = append(nextTasks, module.Task{
			ID:   fmt.Sprintf("open_port-%s-%d", ip, port),
			Type: "open_port",
			Target: target.Target{
				ID:    task.Target.ID,
				Type:  target.TargetTypeIP,
				Value: fmt.Sprintf("%s:%d", ip, port),
				Org:   task.Target.Org,
				Tags:  task.Target.Tags,
			},
			Payload: map[string]any{
				"ip":   ip,
				"port": port,
			},
			ParentID: task.ID,
		})
	}

	// 2. Run fingerprintx to identify services
	fpInput := strings.Join(fpInputLines, "\n")
	fpOut, err := runCmd(ctx, fpInput, "fingerprintx", "--json")
	if err == nil {
		fpLines := strings.Split(string(fpOut), "\n")
		for _, fpLine := range fpLines {
			fpLine = strings.TrimSpace(fpLine)
			if fpLine == "" {
				continue
			}

			var fp fingerprintxOutput
			if err := json.Unmarshal([]byte(fpLine), &fp); err == nil {
				nextTasks = append(nextTasks, module.Task{
					ID:   fmt.Sprintf("service-%s-%d", fp.IP, fp.Port),
					Type: "service",
					Target: target.Target{
						ID:    task.Target.ID,
						Type:  target.TargetTypeIP,
						Value: fmt.Sprintf("%s:%d", fp.IP, fp.Port),
						Org:   task.Target.Org,
						Tags:  task.Target.Tags,
					},
					Payload: map[string]any{
						"ip":        fp.IP,
						"port":      fp.Port,
						"service":   fp.Service,
						"transport": fp.Transport,
						"tls":       fp.TLS,
						"banner":    fp.Banner,
					},
					ParentID: task.ID,
				})
			}
		}
	}

	return nil, nextTasks, nil
}

// Ensure interface compliance.
var _ module.Module = (*PortScanner)(nil)
