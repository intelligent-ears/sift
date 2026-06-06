package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
)

// ClientInterface defines the NATS client contract required by Sift components.
type ClientInterface interface {
	Publish(ctx context.Context, subject string, task module.Task) error
	PublishFinding(ctx context.Context, subject string, f finding.Finding) error
	Subscribe(ctx context.Context, subject string, handler func(module.Task) error) error
	SubscribeFinding(ctx context.Context, subject string, handler func(finding.Finding) error) error
}

// Client is a wrapper around the NATS JetStream client with structured logging and automatic JSON conversion.
type Client struct {
	nc     *nats.Conn
	js     nats.JetStreamContext
	logger *zap.Logger
}

// Connect initializes the NATS connection and asserts the "SIFT" JetStream stream.
func Connect(url string) (*Client, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		logger = zap.NewNop()
	}
	return ConnectWithLogger(url, logger)
}

// ConnectWithLogger initializes NATS using a specific logger.
func ConnectWithLogger(url string, logger *zap.Logger) (*Client, error) {
	nc, err := nats.Connect(url, nats.Name("sift-core"))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS at %s: %w", url, err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to get JetStream context: %w", err)
	}

	// Ensure the stream exists for "sift.>" subject wildcard
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "SIFT",
		Subjects: []string{"sift.>"},
	})
	if err != nil {
		// Verify if the stream already exists
		if _, infoErr := js.StreamInfo("SIFT"); infoErr != nil {
			nc.Close()
			return nil, fmt.Errorf("failed to assert SIFT stream: %w", err)
		}
	}

	return &Client{
		nc:     nc,
		js:     js,
		logger: logger,
	}, nil
}

// Close closes the NATS connection.
func (c *Client) Close() {
	if c.nc != nil {
		c.nc.Close()
	}
}

// Publish serializes and publishes a module.Task to NATS JetStream.
func (c *Client) Publish(ctx context.Context, subject string, task module.Task) error {
	data, err := json.Marshal(task)
	if err != nil {
		return fmt.Errorf("failed to marshal task: %w", err)
	}

	c.logger.Info("Publishing task",
		zap.String("subject", subject),
		zap.String("task_id", task.ID),
		zap.String("task_type", string(task.Type)),
	)

	_, err = c.js.Publish(subject, data, nats.Context(ctx))
	if err != nil {
		c.logger.Error("Failed to publish task",
			zap.String("subject", subject),
			zap.String("task_id", task.ID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to publish to JetStream: %w", err)
	}

	return nil
}

// PublishFinding serializes and publishes a finding.Finding to NATS JetStream.
func (c *Client) PublishFinding(ctx context.Context, subject string, f finding.Finding) error {
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}

	c.logger.Info("Publishing finding",
		zap.String("subject", subject),
		zap.String("finding_id", f.ID),
		zap.String("module_name", f.ModuleName),
	)

	_, err = c.js.Publish(subject, data, nats.Context(ctx))
	if err != nil {
		c.logger.Error("Failed to publish finding",
			zap.String("subject", subject),
			zap.String("finding_id", f.ID),
			zap.Error(err),
		)
		return fmt.Errorf("failed to publish finding to JetStream: %w", err)
	}

	return nil
}

// Subscribe registers a durable push consumer subscription with explicit manual Acks.
func (c *Client) Subscribe(ctx context.Context, subject string, handler func(module.Task) error) error {
	cleanSubject := strings.ReplaceAll(subject, ".", "_")
	cleanSubject = strings.ReplaceAll(cleanSubject, "*", "wildcard")
	durableName := fmt.Sprintf("sift_durable_%s", cleanSubject)

	c.logger.Info("Subscribing to subject with durable push consumer",
		zap.String("subject", subject),
		zap.String("durable", durableName),
	)

	_, err := c.js.Subscribe(subject, func(msg *nats.Msg) {
		var task module.Task
		if err := json.Unmarshal(msg.Data, &task); err != nil {
			c.logger.Error("Failed to unmarshal task message, discarding",
				zap.String("subject", subject),
				zap.Error(err),
			)
			// Terminate corrupt JSON to prevent infinite redelivery
			_ = msg.Term()
			return
		}

		c.logger.Info("Received task",
			zap.String("subject", subject),
			zap.String("task_id", task.ID),
			zap.String("task_type", string(task.Type)),
		)

		err := handler(task)
		if err != nil {
			c.logger.Error("Handler failed, nacking message",
				zap.String("subject", subject),
				zap.String("task_id", task.ID),
				zap.Error(err),
			)
			_ = msg.Nack()
		} else {
			c.logger.Info("Handler completed successfully, acking message",
				zap.String("subject", subject),
				zap.String("task_id", task.ID),
			)
			_ = msg.Ack()
		}
	}, nats.Durable(durableName), nats.ManualAck())

	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", subject, err)
	}

	return nil
}

// SubscribeFinding registers a durable push consumer subscription for findings with explicit manual Acks.
func (c *Client) SubscribeFinding(ctx context.Context, subject string, handler func(finding.Finding) error) error {
	cleanSubject := strings.ReplaceAll(subject, ".", "_")
	cleanSubject = strings.ReplaceAll(cleanSubject, "*", "wildcard")
	durableName := fmt.Sprintf("sift_durable_%s", cleanSubject)

	c.logger.Info("Subscribing to findings subject with durable push consumer",
		zap.String("subject", subject),
		zap.String("durable", durableName),
	)

	_, err := c.js.Subscribe(subject, func(msg *nats.Msg) {
		var f finding.Finding
		if err := json.Unmarshal(msg.Data, &f); err != nil {
			c.logger.Error("Failed to unmarshal finding message, discarding",
				zap.String("subject", subject),
				zap.Error(err),
			)
			_ = msg.Term()
			return
		}

		c.logger.Info("Received finding",
			zap.String("subject", subject),
			zap.String("finding_id", f.ID),
			zap.String("module_name", f.ModuleName),
		)

		err := handler(f)
		if err != nil {
			c.logger.Error("Handler failed for finding, nacking message",
				zap.String("subject", subject),
				zap.String("finding_id", f.ID),
				zap.Error(err),
			)
			_ = msg.Nack()
		} else {
			c.logger.Info("Handler completed successfully for finding, acking message",
				zap.String("subject", subject),
				zap.String("finding_id", f.ID),
			)
			_ = msg.Ack()
		}
	}, nats.Durable(durableName), nats.ManualAck())

	if err != nil {
		return fmt.Errorf("failed to subscribe to findings %s: %w", subject, err)
	}

	return nil
}

// Ensure Client implements ClientInterface.
var _ ClientInterface = (*Client)(nil)
