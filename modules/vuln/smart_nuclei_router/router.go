package smart_nuclei_router

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router/filter"
	"github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router/index"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
	"github.com/spf13/viper"

	pb "github.com/sift-scanner/sift/proto/triage"
)

func init() {
	registry.Register(&SmartNucleiRouter{})
}

// SmartNucleiRouter implements the intelligent two-stage template routing module.
type SmartNucleiRouter struct {
	index     *index.TemplateIndex
	indexOnce sync.Once
	logger    *zap.Logger
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

func (s *SmartNucleiRouter) getLogger() *zap.Logger {
	if s.logger != nil {
		return s.logger
	}
	logger, err := zap.NewProduction()
	if err != nil {
		return zap.NewNop()
	}
	s.logger = logger
	return s.logger
}

func (s *SmartNucleiRouter) getIndex() (*index.TemplateIndex, error) {
	var loadErr error
	s.indexOnce.Do(func() {
		viper.SetDefault("nuclei.templates_path", "~/.nuclei-templates")
		_ = viper.BindEnv("nuclei.templates_path", "NUCLEI_TEMPLATES_PATH")
		templatesPath := viper.GetString("nuclei.templates_path")

		if strings.HasPrefix(templatesPath, "~") {
			home, err := os.UserHomeDir()
			if err == nil {
				templatesPath = filepath.Join(home, templatesPath[1:])
			}
		}

		idx, err := index.LoadIndex(templatesPath)
		if err != nil {
			loadErr = err
			return
		}
		s.index = idx
	})

	if s.index == nil {
		if loadErr != nil {
			return nil, loadErr
		}
		return nil, fmt.Errorf("failed to load template index")
	}

	return s.index, nil
}

// Run executes the template filtering and ML re-ranking logic.
func (s *SmartNucleiRouter) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	payloadBytes, err := json.Marshal(task.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal task payload: %w", err)
	}

	var payload filter.NucleiJobPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal task payload: %w", err)
	}

	if payload.URL == "" {
		payload.URL = task.Target.Value
	}

	idx, err := s.getIndex()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load template index: %w", err)
	}

	// Stage 1: Filter templates deterministically
	candidateIDs := filter.FilterCandidates(idx, payload)

	// Stage 2: Call ML re-ranker via gRPC
	viper.SetDefault("ml.endpoint", "")
	_ = viper.BindEnv("ml.endpoint", "SIFT_ML_ENDPOINT")
	mlEndpoint := viper.GetString("ml.endpoint")

	var rankedIDs []string
	var mlCalled bool

	if mlEndpoint != "" {
		rankedIDs, err = s.callMLRanker(ctx, mlEndpoint, candidateIDs, payload)
		if err != nil {
			s.getLogger().Warn("ML templates re-ranker failed, falling back silently to stage 1 results",
				zap.String("endpoint", mlEndpoint),
				zap.Error(err),
			)
		} else {
			mlCalled = true
		}
	}

	if !mlCalled {
		rankedIDs = candidateIDs
	}

	// Limit templates to top N config
	viper.SetDefault("nuclei.max_templates", 50)
	_ = viper.BindEnv("nuclei.max_templates", "NUCLEI_MAX_TEMPLATES")
	maxTemplates := viper.GetInt("nuclei.max_templates")
	if maxTemplates <= 0 {
		maxTemplates = 50
	}

	if len(rankedIDs) > maxTemplates {
		rankedIDs = rankedIDs[:maxTemplates]
	}

	execTask := module.Task{
		ID:   uuid.New().String(),
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
			"templates": rankedIDs,
		},
		ParentID: task.ID,
	}

	return nil, []module.Task{execTask}, nil
}

func (s *SmartNucleiRouter) callMLRanker(ctx context.Context, endpoint string, candidateIDs []string, payload filter.NucleiJobPayload) ([]string, error) {
	conn, err := grpc.DialContext(ctx, endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to dial ML service: %w", err)
	}
	defer conn.Close()

	client := pb.NewTriageServiceClient(conn)

	var technologies []string
	for _, svc := range payload.Services {
		if svc.Service != "" {
			technologies = append(technologies, strings.ToLower(svc.Service))
		}
	}
	if payload.CMSContext != nil && payload.CMSContext.CMS != "" {
		technologies = append(technologies, strings.ToLower(payload.CMSContext.CMS))
	}

	var openPorts []int32
	for _, p := range payload.OpenPorts {
		openPorts = append(openPorts, int32(p))
	}

	var cmsType, cmsVersion string
	if payload.CMSContext != nil {
		cmsType = payload.CMSContext.CMS
		cmsVersion = payload.CMSContext.Version
	}

	req := &pb.RankRequest{
		TemplateIds: candidateIDs,
		TargetContext: &pb.TargetContext{
			Technologies: technologies,
			OpenPorts:    openPorts,
			CmsType:      cmsType,
			CmsVersion:   cmsVersion,
		},
	}

	resp, err := client.RankTemplates(ctx, req)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, t := range resp.Templates {
		if t.TemplateId != "" {
			result = append(result, t.TemplateId)
		}
	}

	if len(result) == 0 {
		return candidateIDs, nil
	}

	return result, nil
}

// Ensure interface compliance.
var _ module.Module = (*SmartNucleiRouter)(nil)
