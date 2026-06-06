package subdomain_enumeration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/config"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func init() {
	registry.Register(&SubdomainEnumeration{})
}

// SubdomainEnumeration performs subdomain discovery using subfinder and crt.sh.
type SubdomainEnumeration struct {
	runCmd     func(ctx context.Context, name string, arg ...string) ([]byte, error)
	httpClient *http.Client
}

func (s *SubdomainEnumeration) getRunCmd() func(context.Context, string, ...string) ([]byte, error) {
	if s.runCmd != nil {
		return s.runCmd
	}
	return func(ctx context.Context, name string, arg ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, arg...)
		return cmd.Output()
	}
}

func (s *SubdomainEnumeration) getHTTPClient() *http.Client {
	if s.httpClient != nil {
		return s.httpClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Name returns the module name.
func (s *SubdomainEnumeration) Name() string {
	return "subdomain_enumeration"
}

// Consumes returns the task types this module handles.
func (s *SubdomainEnumeration) Consumes() []module.TaskType {
	return []module.TaskType{"domain"}
}

// Produces returns the task types this module produces.
func (s *SubdomainEnumeration) Produces() []module.TaskType {
	return []module.TaskType{"subdomain", "url"}
}

// Run executes the subdomain enumeration module.
func (s *SubdomainEnumeration) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	domain := strings.TrimSpace(task.Target.Value)
	if domain == "" {
		return nil, nil, fmt.Errorf("empty domain target")
	}

	subfinderTimeout := config.Get().SubfinderTimeout
	if subfinderTimeout == 0 {
		subfinderTimeout = 60 * time.Second
	}

	results := make(map[string]bool)

	// 1. Run Subfinder
	subfinderCtx, cancel := context.WithTimeout(ctx, subfinderTimeout)
	defer cancel()

	runCmd := s.getRunCmd()
	output, err := runCmd(subfinderCtx, "subfinder", "-d", domain, "-silent")
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				results[line] = true
			}
		}
	}

	// 2. Query crt.sh API
	crtshURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", crtshURL, nil)
	if err == nil {
		resp, err := s.getHTTPClient().Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var crtResults []struct {
					CommonName string `json:"common_name"`
					NameValue  string `json:"name_value"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&crtResults); err == nil {
					for _, item := range crtResults {
						// Split names in case they are newline-delimited
						names := strings.Split(item.NameValue, "\n")
						for _, name := range names {
							name = strings.TrimSpace(name)
							name = strings.TrimPrefix(name, "*.")
							if name != "" && strings.HasSuffix(name, domain) {
								results[name] = true
							}
						}
						cName := strings.TrimPrefix(strings.TrimSpace(item.CommonName), "*.")
						if cName != "" && strings.HasSuffix(cName, domain) {
							results[cName] = true
						}
					}
				}
			}
		}
	}

	var nextTasks []module.Task
	for sub := range results {
		// Create subdomain task
		nextTasks = append(nextTasks, module.Task{
			ID:   fmt.Sprintf("sub-%s", sub),
			Type: "subdomain",
			Target: target.Target{
				ID:    task.Target.ID,
				Type:  target.TargetTypeDomain,
				Value: sub,
				Org:   task.Target.Org,
				Tags:  task.Target.Tags,
			},
			Payload:  map[string]any{"subdomain": sub},
			ParentID: task.ID,
		})

		// Create HTTP URL task
		nextTasks = append(nextTasks, module.Task{
			ID:   fmt.Sprintf("url-http-%s", sub),
			Type: "url",
			Target: target.Target{
				ID:    task.Target.ID,
				Type:  target.TargetTypeURL,
				Value: fmt.Sprintf("http://%s", sub),
				Org:   task.Target.Org,
				Tags:  task.Target.Tags,
			},
			Payload:  map[string]any{"url": fmt.Sprintf("http://%s", sub)},
			ParentID: task.ID,
		})

		// Create HTTPS URL task
		nextTasks = append(nextTasks, module.Task{
			ID:   fmt.Sprintf("url-https-%s", sub),
			Type: "url",
			Target: target.Target{
				ID:    task.Target.ID,
				Type:  target.TargetTypeURL,
				Value: fmt.Sprintf("https://%s", sub),
				Org:   task.Target.Org,
				Tags:  task.Target.Tags,
			},
			Payload:  map[string]any{"url": fmt.Sprintf("https://%s", sub)},
			ParentID: task.ID,
		})
	}

	return nil, nextTasks, nil
}

// Ensure interface compliance.
var _ module.Module = (*SubdomainEnumeration)(nil)
