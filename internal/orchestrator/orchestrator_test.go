package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
	siftnats "github.com/sift-scanner/sift/pkg/nats"
	"github.com/sift-scanner/sift/pkg/target"
)

// mockNATSClient is a thread-safe mock implementation of ClientInterface.
type mockNATSClient struct {
	mu        sync.Mutex
	published []mockPublishCall
	findings  []mockFindingCall
	subs      map[string]func(module.Task) error
}

type mockPublishCall struct {
	subject string
	task    module.Task
}

type mockFindingCall struct {
	subject string
	finding finding.Finding
}

func newMockNATSClient() *mockNATSClient {
	return &mockNATSClient{
		subs: make(map[string]func(module.Task) error),
	}
}

func (m *mockNATSClient) Publish(ctx context.Context, subject string, task module.Task) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = append(m.published, mockPublishCall{subject: subject, task: task})
	return nil
}

func (m *mockNATSClient) PublishFinding(ctx context.Context, subject string, f finding.Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = append(m.findings, mockFindingCall{subject: subject, finding: f})
	return nil
}

func (m *mockNATSClient) Subscribe(ctx context.Context, subject string, handler func(module.Task) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs[subject] = handler
	return nil
}

func (m *mockNATSClient) SubscribeFinding(ctx context.Context, subject string, handler func(finding.Finding) error) error {
	return nil
}

var _ siftnats.ClientInterface = (*mockNATSClient)(nil)

// mockModule implements module.Module for testing.
type mockModule struct {
	name     string
	consumes []module.TaskType
	produces []module.TaskType
	runFunc  func(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error)
}

func (mm *mockModule) Name() string { return mm.name }
func (mm *mockModule) Consumes() []module.TaskType { return mm.consumes }
func (mm *mockModule) Produces() []module.TaskType { return mm.produces }
func (mm *mockModule) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	if mm.runFunc != nil {
		return mm.runFunc(ctx, task)
	}
	return nil, nil, nil
}

func TestOrchestrator_Flow(t *testing.T) {
	logger := zap.NewNop()
	mockClient := newMockNATSClient()

	// Register a mock module
	m := &mockModule{
		name:     "test_module",
		consumes: []module.TaskType{"domain", "open_port[22]"},
		produces: []module.TaskType{"subdomain", "finding"},
		runFunc: func(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
			if task.ID == "err-task" {
				return nil, nil, errors.New("forced module error")
			}
			f := module.Finding{
				ID:    "find-1",
				Title: "Test Finding",
			}
			t2 := module.Task{
				ID:   "task-downstream",
				Type: "subdomain",
			}
			return []module.Finding{f}, []module.Task{t2}, nil
		},
	}
	registry.Register(m)

	orchestrator := New(mockClient, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start orchestrator in the background
	errChan := make(chan error, 1)
	go func() {
		errChan <- orchestrator.Start(ctx)
	}()

	// Give a tiny amount of time for subscription registry
	time.Sleep(50 * time.Millisecond)

	mockClient.mu.Lock()
	subDomainHandler, hasDomain := mockClient.subs["sift.tasks.domain"]
	mockClient.mu.Unlock()

	if !hasDomain {
		t.Fatal("expected subscription for sift.tasks.domain")
	}

	// Test successful run
	taskInput := module.Task{
		ID:     "task-1",
		Type:   "domain",
		Target: target.Target{ID: "target-1", Value: "example.com"},
	}

	err := subDomainHandler(taskInput)
	if err != nil {
		t.Errorf("expected handler to succeed, got: %v", err)
	}

	mockClient.mu.Lock()
	if len(mockClient.findings) != 1 {
		t.Errorf("expected 1 finding to be published, got %d", len(mockClient.findings))
	} else {
		f := mockClient.findings[0]
		if f.subject != "sift.findings" {
			t.Errorf("expected findings to be published to sift.findings, got %q", f.subject)
		}
		if f.finding.Title != "Test Finding" {
			t.Errorf("expected finding title to be 'Test Finding', got %q", f.finding.Title)
		}
		if f.finding.ModuleName != m.name {
			t.Errorf("expected finding ModuleName to be auto-populated to %q, got %q", m.name, f.finding.ModuleName)
		}
	}

	if len(mockClient.published) != 1 {
		t.Errorf("expected 1 downstream task to be published, got %d", len(mockClient.published))
	} else {
		p := mockClient.published[0]
		if p.subject != "sift.tasks.subdomain" {
			t.Errorf("expected downstream task to be published to sift.tasks.subdomain, got %q", p.subject)
		}
		if p.task.ID != "task-downstream" {
			t.Errorf("expected downstream task ID to be 'task-downstream', got %q", p.task.ID)
		}
	}
	mockClient.mu.Unlock()

	// Test error run
	errTaskInput := module.Task{
		ID:     "err-task",
		Type:   "domain",
		Target: target.Target{ID: "target-1", Value: "example.com"},
	}
	err = subDomainHandler(errTaskInput)
	if err == nil {
		t.Error("expected handler to return error for forced module failure")
	}

	// Cancel context to stop orchestrator
	cancel()
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("orchestrator returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("orchestrator did not stop on context cancellation")
	}
}
