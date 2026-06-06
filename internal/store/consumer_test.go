package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

// mockStore is a mock implementation of Store for testing.
type mockStore struct {
	savedFindings []finding.Finding
	saveError     error
}

func (m *mockStore) SaveFinding(ctx context.Context, f finding.Finding) error {
	if m.saveError != nil {
		return m.saveError
	}
	m.savedFindings = append(m.savedFindings, f)
	return nil
}

func (m *mockStore) GetFindings(ctx context.Context, filter FindingFilter) ([]finding.Finding, error) {
	return nil, nil
}

func (m *mockStore) SaveTarget(ctx context.Context, t target.Target) error {
	return nil
}

func (m *mockStore) GetTargets(ctx context.Context) ([]target.Target, error) {
	return nil, nil
}

func (m *mockStore) CreateScan(ctx context.Context) (string, error) {
	return "", nil
}

func (m *mockStore) UpdateScanStatus(ctx context.Context, scanID, status string) error {
	return nil
}

// mockConsumerNATSClient is a mock NATS client for consumer tests.
type mockConsumerNATSClient struct {
	handler func(finding.Finding) error
}

func (m *mockConsumerNATSClient) Publish(ctx context.Context, subject string, task module.Task) error {
	return nil
}

func (m *mockConsumerNATSClient) PublishFinding(ctx context.Context, subject string, f finding.Finding) error {
	return nil
}

func (m *mockConsumerNATSClient) Subscribe(ctx context.Context, subject string, handler func(module.Task) error) error {
	return nil
}

func (m *mockConsumerNATSClient) SubscribeFinding(ctx context.Context, subject string, handler func(finding.Finding) error) error {
	m.handler = handler
	return nil
}

func TestConsumer(t *testing.T) {
	logger := zap.NewNop()
	mockSt := &mockStore{}
	mockNATS := &mockConsumerNATSClient{}

	consumer := NewConsumer(mockNATS, mockSt, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start consumer in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- consumer.Start(ctx)
	}()

	// Give a moment for the subscription to register
	time.Sleep(50 * time.Millisecond)

	if mockNATS.handler == nil {
		t.Fatal("Expected SubscribeFinding to register a handler, got nil")
	}

	// Send a test finding
	testFinding := finding.Finding{
		ID:         "test-finding-id",
		Title:      "Test Vulnerability",
		ModuleName: "test-module",
		Target: target.Target{
			ID:    "target-id",
			Type:  target.TargetTypeDomain,
			Value: "example.com",
		},
		Evidence: map[string]any{"scan_id": "test-scan-id"},
	}

	err := mockNATS.handler(testFinding)
	if err != nil {
		t.Fatalf("Handler returned unexpected error: %v", err)
	}

	if len(mockSt.savedFindings) != 1 {
		t.Fatalf("Expected 1 saved finding, got %d", len(mockSt.savedFindings))
	}

	if mockSt.savedFindings[0].ID != testFinding.ID {
		t.Errorf("Expected saved finding ID %s, got %s", testFinding.ID, mockSt.savedFindings[0].ID)
	}

	// Test store error propagation
	mockSt.saveError = errors.New("db error")
	err = mockNATS.handler(testFinding)
	if err == nil {
		t.Error("Expected handler to fail when DB save fails, but it succeeded")
	}

	// Cancel context to stop consumer
	cancel()

	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Consumer stopped with error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("Consumer did not stop after context cancel")
	}
}
