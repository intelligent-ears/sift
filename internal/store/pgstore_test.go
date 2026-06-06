package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/target"
)

func TestPGStore(t *testing.T) {
	connStr := os.Getenv("TEST_DATABASE_URL")
	if connStr == "" {
		t.Skip("Skipping postgres store tests: TEST_DATABASE_URL not set")
	}

	ctx := context.Background()
	store, err := NewPGStore(connStr)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer store.Close()

	// Clear tables for a clean test run
	_, _ = store.pool.Exec(ctx, "TRUNCATE findings, targets, scans CASCADE")

	// 1. Test Scan Operations
	var scanID string
	t.Run("CreateScan", func(t *testing.T) {
		id, err := store.CreateScan(ctx)
		if err != nil {
			t.Fatalf("Failed to create scan: %v", err)
		}
		if id == "" {
			t.Fatal("Expected non-empty scan ID")
		}
		scanID = id
	})

	t.Run("UpdateScanStatus", func(t *testing.T) {
		err := store.UpdateScanStatus(ctx, scanID, "COMPLETED")
		if err != nil {
			t.Fatalf("Failed to update scan status: %v", err)
		}
	})

	// 2. Test Target Operations
	targetID := uuid.New().String()
	testTarget := target.Target{
		ID:    targetID,
		Type:  target.TargetTypeDomain,
		Value: "example.com",
		Org:   "TestOrg",
		Tags:  []string{"test", "env"},
	}

	t.Run("SaveTarget", func(t *testing.T) {
		err := store.SaveTarget(ctx, testTarget)
		if err != nil {
			t.Fatalf("Failed to save target: %v", err)
		}
	})

	t.Run("GetTargets", func(t *testing.T) {
		targets, err := store.GetTargets(ctx)
		if err != nil {
			t.Fatalf("Failed to get targets: %v", err)
		}
		if len(targets) != 1 {
			t.Fatalf("Expected 1 target, got %d", len(targets))
		}
		if targets[0].Value != testTarget.Value {
			t.Errorf("Expected target value %s, got %s", testTarget.Value, targets[0].Value)
		}
	})

	// 3. Test Finding Operations
	findingID := uuid.New().String()
	testFinding := finding.Finding{
		ID:          findingID,
		ModuleName:  "test_module",
		Target:      testTarget,
		Severity:    finding.SeverityHigh,
		Title:       "Test Vulnerability",
		Description: "A description of the vulnerability",
		Evidence:    map[string]any{"cve": "CVE-2026-9999", "scan_id": scanID},
		CreatedAt:   time.Now().UTC(),
	}

	t.Run("SaveFinding", func(t *testing.T) {
		err := store.SaveFinding(ctx, testFinding)
		if err != nil {
			t.Fatalf("Failed to save finding: %v", err)
		}
	})

	t.Run("GetFindings", func(t *testing.T) {
		// Test filtering by scan ID
		filter := FindingFilter{
			ScanID: scanID,
		}
		findings, err := store.GetFindings(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to get findings: %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("Expected 1 finding, got %d", len(findings))
		}
		if findings[0].Title != testFinding.Title {
			t.Errorf("Expected finding title %s, got %s", testFinding.Title, findings[0].Title)
		}
		if findings[0].Severity != testFinding.Severity {
			t.Errorf("Expected severity %v, got %v", testFinding.Severity, findings[0].Severity)
		}

		// Test filtering by non-existent severity
		filter = FindingFilter{
			Severity: finding.SeverityCritical,
		}
		findings, err = store.GetFindings(ctx, filter)
		if err != nil {
			t.Fatalf("Failed to get findings: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for CRITICAL filter, got %d", len(findings))
		}
	})
}
