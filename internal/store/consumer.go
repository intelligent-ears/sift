package store

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/sift-scanner/sift/pkg/finding"
	siftnats "github.com/sift-scanner/sift/pkg/nats"
)

// Consumer listens to findings published on NATS and persists them.
type Consumer struct {
	natsClient siftnats.ClientInterface
	store      Store
	logger     *zap.Logger
}

// NewConsumer creates a new findings NATS consumer.
func NewConsumer(natsClient siftnats.ClientInterface, store Store, logger *zap.Logger) *Consumer {
	return &Consumer{
		natsClient: natsClient,
		store:      store,
		logger:     logger,
	}
}

// Start subscribes to sift.findings and blocks until the context is canceled.
func (c *Consumer) Start(ctx context.Context) error {
	c.logger.Info("Starting findings store consumer, subscribing to", zap.String("subject", siftnats.SubjectFindings))

	err := c.natsClient.SubscribeFinding(ctx, siftnats.SubjectFindings, func(f finding.Finding) error {
		c.logger.Info("Persisting finding to database", zap.String("finding_id", f.ID), zap.String("title", f.Title))

		// Propagate scan ID to the context if present in the finding's evidence
		saveCtx := ctx
		if f.Evidence != nil {
			if scanID, ok := f.Evidence["scan_id"].(string); ok && scanID != "" {
				saveCtx = WithScanID(ctx, scanID)
			}
		}

		err := c.store.SaveFinding(saveCtx, f)
		if err != nil {
			c.logger.Error("Failed to persist finding", zap.String("finding_id", f.ID), zap.Error(err))
			return fmt.Errorf("failed to save finding: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe findings consumer: %w", err)
	}

	// Block until context is canceled
	<-ctx.Done()
	c.logger.Info("Findings store consumer shutting down")
	return nil
}
