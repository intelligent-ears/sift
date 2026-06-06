package triage

import (
	"context"

	"google.golang.org/grpc"
)

type TriageServiceClient interface {
	RankTemplates(ctx context.Context, in *RankRequest, opts ...grpc.CallOption) (*RankResponse, error)
	ScoreFinding(ctx context.Context, in *ScoreRequest, opts ...grpc.CallOption) (*ScoreResponse, error)
	RecordOutcome(ctx context.Context, in *OutcomeRequest, opts ...grpc.CallOption) (*OutcomeResponse, error)
}

type triageServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTriageServiceClient(cc grpc.ClientConnInterface) TriageServiceClient {
	return &triageServiceClient{cc}
}

func (c *triageServiceClient) RankTemplates(ctx context.Context, in *RankRequest, opts ...grpc.CallOption) (*RankResponse, error) {
	out := new(RankResponse)
	err := c.cc.Invoke(ctx, "/triage.TriageService/RankTemplates", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *triageServiceClient) ScoreFinding(ctx context.Context, in *ScoreRequest, opts ...grpc.CallOption) (*ScoreResponse, error) {
	out := new(ScoreResponse)
	err := c.cc.Invoke(ctx, "/triage.TriageService/ScoreFinding", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *triageServiceClient) RecordOutcome(ctx context.Context, in *OutcomeRequest, opts ...grpc.CallOption) (*OutcomeResponse, error) {
	out := new(OutcomeResponse)
	err := c.cc.Invoke(ctx, "/triage.TriageService/RecordOutcome", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}
