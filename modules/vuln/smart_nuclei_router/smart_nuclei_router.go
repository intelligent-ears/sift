package smart_nuclei_router

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router/filter"
	"github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router/index"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
	"github.com/spf13/viper"
)

func init() {
	registry.Register(&SmartNucleiRouter{})
}

// SmartNucleiRouter implements the intelligent two-stage template routing module.
type SmartNucleiRouter struct {
	index    *index.TemplateIndex
	mlClient MLClient
}

// Name returns the module name.
func (s *SmartNucleiRouter) Name() string {
	return "smart_nuclei_router"
}

// Consumes returns the task types this module handles.
func (s *SmartNucleiRouter) Consumes() []module.TaskType {
	return []module.TaskType{"nuclei_job"}
}

// Produces returns the task types this module produces.
func (s *SmartNucleiRouter) Produces() []module.TaskType {
	return []module.TaskType{"nuclei_execution"}
}

func (s *SmartNucleiRouter) getIndex() (*index.TemplateIndex, error) {
	if s.index != nil {
		return s.index, nil
	}

	viper.SetDefault("nuclei.templates_path", "~/.nuclei-templates")
	_ = viper.BindEnv("nuclei.templates_path", "NUCLEI_TEMPLATES_PATH")
	templatesPath := viper.GetString("nuclei.templates_path")

	if strings.HasPrefix(templatesPath, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			templatesPath = filepath.Join(home, templatesPath[1:])
		}
	}

	idx, err := index.NewTemplateIndex(templatesPath)
	if err != nil {
		return nil, err
	}
	s.index = idx
	return s.index, nil
}

func (s *SmartNucleiRouter) getMLClient() MLClient {
	if s.mlClient != nil {
		return s.mlClient
	}
	return &NoOpMLClient{}
}

// Run executes the template filtering and ML re-ranking logic.
func (s *SmartNucleiRouter) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	var payload filter.NucleiJobPayload
	payload.URL = task.Target.Value

	if urlVal, ok := task.Payload["url"].(string); ok {
		payload.URL = urlVal
	}

	// Parse CMSContext
	if cmsCtxMap, ok := task.Payload["cms_context"].(map[string]any); ok {
		var cmsCtx filter.CMSContext
		if cmsVal, ok := cmsCtxMap["cms"].(string); ok {
			cmsCtx.CMS = cmsVal
		}
		if verVal, ok := cmsCtxMap["version"].(string); ok {
			cmsCtx.Version = verVal
		}
		if confVal, ok := cmsCtxMap["confidence"].(float64); ok {
			cmsCtx.Confidence = float32(confVal)
		}
		payload.CMSContext = &cmsCtx
	}

	// Parse Services
	if svcsList, ok := task.Payload["services"].([]any); ok {
		for _, svcItem := range svcsList {
			if svcMap, ok := svcItem.(map[string]any); ok {
				var svc filter.ServiceFingerprint
				if pVal, ok := svcMap["port"].(float64); ok {
					svc.Port = int(pVal)
				}
				if sVal, ok := svcMap["service"].(string); ok {
					svc.Service = sVal
				}
				payload.Services = append(payload.Services, svc)
			}
		}
	}

	// Parse OpenPorts
	if portsList, ok := task.Payload["open_ports"].([]any); ok {
		for _, pItem := range portsList {
			if pVal, ok := pItem.(float64); ok {
				payload.OpenPorts = append(payload.OpenPorts, int(pVal))
			}
		}
	}

	// Parse Headers
	if headersMap, ok := task.Payload["headers"].(map[string]any); ok {
		payload.Headers = make(map[string]string)
		for k, v := range headersMap {
			if vStr, ok := v.(string); ok {
				payload.Headers[k] = vStr
			}
		}
	}

	idx, err := s.getIndex()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load template index: %w", err)
	}

	candidateIDs := filter.FilterCandidates(idx, payload)

	mlClient := s.getMLClient()
	rankedResp, err := mlClient.RankTemplates(ctx, &RankRequest{
		TemplateIDs:   candidateIDs,
		TargetContext: task.Payload,
	})
	if err != nil {
		rankedResp = &RankResponse{TemplateIDs: candidateIDs}
	}

	viper.SetDefault("nuclei.max_templates", 50)
	_ = viper.BindEnv("nuclei.max_templates", "NUCLEI_MAX_TEMPLATES")
	maxTemplates := viper.GetInt("nuclei.max_templates")
	if maxTemplates <= 0 {
		maxTemplates = 50
	}

	finalTemplates := rankedResp.TemplateIDs
	if len(finalTemplates) > maxTemplates {
		finalTemplates = finalTemplates[:maxTemplates]
	}

	execTask := module.Task{
		ID:   fmt.Sprintf("nuclei-exec-%s", task.ID),
		Type: "nuclei_execution",
		Target: target.Target{
			ID:    task.Target.ID,
			Type:  task.Target.Type,
			Value: task.Target.Value,
			Org:   task.Target.Org,
			Tags:  task.Target.Tags,
		},
		Payload: map[string]any{
			"url":       payload.URL,
			"templates": finalTemplates,
		},
		ParentID: task.ID,
	}

	return nil, []module.Task{execTask}, nil
}

// Ensure interface compliance.
var _ module.Module = (*SmartNucleiRouter)(nil)
