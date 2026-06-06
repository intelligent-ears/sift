package smart_nuclei_router

import "context"

// RankRequest represents the parameters sent to the ML middleware for template ranking.
type RankRequest struct {
	TemplateIDs   []string
	TargetContext map[string]any
}

// RankResponse contains the scored template IDs returned by the ML middleware.
type RankResponse struct {
	TemplateIDs []string
	Scores      []float32
}

// MLClient defines the contract with the ML microservice for re-ranking.
type MLClient interface {
	RankTemplates(ctx context.Context, req *RankRequest) (*RankResponse, error)
}

// NoOpMLClient is a fallback client used when the gRPC server is unreachable.
type NoOpMLClient struct{}

// RankTemplates returns the templates in their original unfiltered order.
func (n *NoOpMLClient) RankTemplates(ctx context.Context, req *RankRequest) (*RankResponse, error) {
	return &RankResponse{
		TemplateIDs: req.TemplateIDs,
	}, nil
}

// Ensure NoOpMLClient implements MLClient.
var _ MLClient = (*NoOpMLClient)(nil)
