package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/config"
	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
	siftnats "github.com/sift-scanner/sift/pkg/nats"
)

// Orchestrator routes tasks to modules via NATS JetStream.
type Orchestrator struct {
	client siftnats.ClientInterface
	logger *zap.Logger
}

// New creates a new task Orchestrator.
func New(client siftnats.ClientInterface, logger *zap.Logger) *Orchestrator {
	return &Orchestrator{
		client: client,
		logger: logger,
	}
}

// Start loads modules, subscribes to NATS task subjects, and blocks until ctx is canceled.
func (o *Orchestrator) Start(ctx context.Context) error {
	modules := registry.All()
	o.logger.Info("Starting orchestrator, loading modules", zap.Int("modules_loaded", len(modules)))

	for _, mod := range modules {
		mod := mod // capture range variable for closures
		for _, consumes := range mod.Consumes() {
			subSubject := o.resolveSubscriptionSubject(string(consumes))

			o.logger.Info("Subscribing module to subject",
				zap.String("module", mod.Name()),
				zap.String("consumes", string(consumes)),
				zap.String("nats_subject", subSubject),
			)

			err := o.client.Subscribe(ctx, subSubject, func(task module.Task) error {
				// Check for context cancellation before processing
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				// Skip if module is disabled
				if !config.IsModuleEnabled(mod.Name()) {
					o.logger.Debug("Skipping disabled module task execution",
						zap.String("module", mod.Name()),
						zap.String("task_id", task.ID),
					)
					return nil
				}

				o.logger.Info("Orchestrating task for module",
					zap.String("module", mod.Name()),
					zap.String("task_id", task.ID),
				)

				findings, nextTasks, err := mod.Run(ctx, task)
				if err != nil {
					o.logger.Error("Module execution failed",
						zap.String("module", mod.Name()),
						zap.String("task_id", task.ID),
						zap.Error(err),
					)
					return err // triggers Nack in subscriber wrapper
				}

				// Publish returned findings to sift.findings
				for _, find := range findings {
					if find.ModuleName == "" {
						find.ModuleName = mod.Name()
					}
					err = o.client.PublishFinding(ctx, siftnats.SubjectFindings, find)
					if err != nil {
						o.logger.Error("Failed to publish finding",
							zap.String("module", mod.Name()),
							zap.String("finding_title", find.Title),
							zap.Error(err),
						)
						return fmt.Errorf("failed to publish finding: %w", err)
					}
				}

				// Publish downstream tasks
				for _, nextTask := range nextTasks {
					targetSubject := o.resolvePublishSubject(nextTask)
					err = o.client.Publish(ctx, targetSubject, nextTask)
					if err != nil {
						o.logger.Error("Failed to publish downstream task",
							zap.String("module", mod.Name()),
							zap.String("next_task_id", nextTask.ID),
							zap.String("subject", targetSubject),
							zap.Error(err),
						)
						return fmt.Errorf("failed to publish downstream task: %w", err)
					}
				}

				return nil
			})
			if err != nil {
				return fmt.Errorf("failed to subscribe module %s to subject %s: %w", mod.Name(), subSubject, err)
			}
		}
	}

	// Wait until context is canceled
	<-ctx.Done()
	o.logger.Info("Orchestrator shutting down")
	return nil
}

// resolveSubscriptionSubject maps a module's Consumes() item to the full NATS subject.
// Handles bracket specifications: "open_port[22]" -> "sift.tasks.open_port.22".
func (o *Orchestrator) resolveSubscriptionSubject(consume string) string {
	if strings.Contains(consume, "[") && strings.Contains(consume, "]") {
		idxStart := strings.Index(consume, "[")
		idxEnd := strings.Index(consume, "]")
		base := consume[:idxStart]
		param := consume[idxStart+1 : idxEnd]
		return fmt.Sprintf("sift.tasks.%s.%s", base, param)
	}

	if len(consume) > 11 && consume[:11] == "sift.tasks." {
		return consume
	}

	return fmt.Sprintf("sift.tasks.%s", consume)
}

// resolvePublishSubject maps a Task to the dynamic NATS subject it should be published to.
func (o *Orchestrator) resolvePublishSubject(task module.Task) string {
	taskTypeStr := string(task.Type)

	if strings.HasPrefix(taskTypeStr, "sift.") {
		return taskTypeStr
	}

	if taskTypeStr == "open_port" {
		if port, ok := task.Payload["port"]; ok {
			return fmt.Sprintf("sift.tasks.open_port.%v", port)
		}
	}

	if taskTypeStr == "cms_context" {
		if cms, ok := task.Payload["cms"]; ok {
			return fmt.Sprintf("sift.tasks.cms_context.%v", cms)
		}
	}

	return fmt.Sprintf("sift.tasks.%s", taskTypeStr)
}
