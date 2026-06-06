package nuclei_module

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
	"github.com/spf13/viper"
)

func init() {
	registry.Register(&NucleiModule{})
}

// NucleiModule executes Nuclei templates against the target URL.
type NucleiModule struct {
	runCmd func(ctx context.Context, name string, arg ...string) ([]byte, error)
}

func (n *NucleiModule) getRunCmd() func(context.Context, string, ...string) ([]byte, error) {
	if n.runCmd != nil {
		return n.runCmd
	}
	return func(ctx context.Context, name string, arg ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, arg...)
		return cmd.Output()
	}
}

// Name returns the module name.
func (n *NucleiModule) Name() string {
	return "nuclei_module"
}

// Consumes returns the task types this module handles.
func (n *NucleiModule) Consumes() []module.TaskType {
	return []module.TaskType{"nuclei_execution"}
}

// Produces returns the task types this module produces.
func (n *NucleiModule) Produces() []module.TaskType {
	return []module.TaskType{"finding", "sift.outcomes"}
}

type nucleiResult struct {
	TemplateID  string `json:"template-id"`
	MatcherName string `json:"matcher-name"`
	MatchedAt   string `json:"matched-at"`
	Info        struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	CurlCommand string   `json:"curl-command"`
	Extracted   []string `json:"extracted-results"`
	IP          string   `json:"ip"`
}

// Run executes the Nuclei vulnerability checks.
func (n *NucleiModule) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	urlStr, ok := task.Payload["url"].(string)
	if !ok || urlStr == "" {
		return nil, nil, fmt.Errorf("missing or empty url in payload")
	}

	templatesVal, ok := task.Payload["templates"]
	if !ok {
		return nil, nil, nil // no templates to run
	}

	var templates []string
	switch v := templatesVal.(type) {
	case []string:
		templates = v
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok {
				templates = append(templates, str)
			}
		}
	}

	if len(templates) == 0 {
		return nil, nil, nil
	}

	// Load configs
	viper.SetDefault("nuclei.timeout", "300s")
	viper.SetDefault("nuclei.rate_limit", 10)
	_ = viper.BindEnv("nuclei.timeout", "NUCLEI_TIMEOUT")
	_ = viper.BindEnv("nuclei.rate_limit", "NUCLEI_RATE_LIMIT")
	_ = viper.BindEnv("nuclei.interactsh_server", "NUCLEI_INTERACTSH_SERVER")

	timeout := viper.GetDuration("nuclei.timeout")
	rateLimit := viper.GetInt("nuclei.rate_limit")
	interactsh := viper.GetString("nuclei.interactsh_server")

	// Prepare nuclei command arguments
	args := []string{"-u", urlStr, "-json", "-silent"}
	for _, t := range templates {
		args = append(args, "-t", t)
	}
	if rateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(rateLimit))
	}
	if interactsh != "" {
		args = append(args, "-interactsh-server", interactsh)
	}

	// Run command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runCmd := n.getRunCmd()
	output, err := runCmd(cmdCtx, "nuclei", args...)
	if err != nil {
		// Log error, but proceed to process any stdout if returned (e.g. exit code 1 on findings found)
	}

	var findings []module.Finding
	hitTemplates := make(map[string]bool)

	// Process output line by line
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var res nucleiResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue // skip corrupt lines
		}

		hitTemplates[res.TemplateID] = true

		severityVal := mapSeverity(res.Info.Severity)

		evidence := map[string]any{
			"template_id":  res.TemplateID,
			"matcher_name": res.MatcherName,
			"matched_at":   res.MatchedAt,
			"ip":           res.IP,
		}
		if res.CurlCommand != "" {
			evidence["curl_command"] = res.CurlCommand
		}
		if len(res.Extracted) > 0 {
			evidence["extracted_results"] = res.Extracted
		}

		findings = append(findings, module.Finding{
			ID:          fmt.Sprintf("nuclei-%s-%s", res.TemplateID, task.ID),
			ModuleName:  n.Name(),
			Target:      task.Target,
			Severity:    severityVal,
			Title:       res.Info.Name,
			Description: res.Info.Description,
			Evidence:    evidence,
			FalsePos:    0.0, // Updated later by ML triage middleware
			CreatedAt:   time.Now(),
		})
	}

	// Generate outcomes tasks for feedback loop
	var downstreamTasks []module.Task
	for _, t := range templates {
		hit := hitTemplates[t]
		downstreamTasks = append(downstreamTasks, module.Task{
			ID:   fmt.Sprintf("outcome-%s-%s", task.ID, t),
			Type: "sift.outcomes",
			Target: target.Target{
				ID:    task.Target.ID,
				Type:  task.Target.Type,
				Value: task.Target.Value,
				Org:   task.Target.Org,
				Tags:  task.Target.Tags,
			},
			Payload: map[string]any{
				"template_id": t,
				"target_type": string(task.Target.Type),
				"hit":         hit,
			},
			ParentID: task.ID,
		})
	}

	return findings, downstreamTasks, nil
}

func mapSeverity(sev string) finding.Severity {
	switch strings.ToLower(sev) {
	case "info":
		return finding.SeverityInfo
	case "low":
		return finding.SeverityLow
	case "medium":
		return finding.SeverityMedium
	case "high":
		return finding.SeverityHigh
	case "critical":
		return finding.SeverityCritical
	default:
		return finding.SeverityInfo
	}
}

// Ensure interface compliance.
var _ module.Module = (*NucleiModule)(nil)
