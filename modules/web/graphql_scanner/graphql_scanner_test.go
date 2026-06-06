package graphql_scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/httpclient"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func TestGraphQLScanner_Run(t *testing.T) {
	tests := []struct {
		name             string
		handler          http.HandlerFunc
		expectedFindings map[string]finding.Severity
	}{
		{
			name: "Detect Introspection and Suggestion",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				bodyBytes := make([]byte, r.ContentLength)
				r.Body.Read(bodyBytes)
				body := string(bodyBytes)

				if strings.Contains(body, "{__typename}") {
					w.Write([]byte(`{"data":{"__typename":"Query"}}`))
					return
				}
				if strings.Contains(body, "__schema") {
					w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"User"},{"name":"Admin"}]}}}`))
					return
				}
				if strings.Contains(body, "usr") {
					w.Write([]byte(`{"errors":[{"message":"Cannot query field \"usr\" on type \"Query\". Did you mean \"user\"?"}]}`))
					return
				}
				w.Write([]byte(`{}`))
			},
			expectedFindings: map[string]finding.Severity{
				"GraphQL Introspection Exposed":      finding.SeverityHigh,
				"GraphQL Field Suggestions Leakage": finding.SeverityMedium,
			},
		},
		{
			name: "Detect Batching and Complexity Limits Missing",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				bodyBytes := make([]byte, r.ContentLength)
				r.Body.Read(bodyBytes)
				body := string(bodyBytes)

				if strings.Contains(body, "{__typename}") {
					if strings.HasPrefix(body, "[") {
						// Batching request
						w.Write([]byte(`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`))
					} else {
						w.Write([]byte(`{"data":{"__typename":"Query"}}`))
					}
					return
				}
				if strings.Contains(body, "f100:") {
					w.Write([]byte(`{"data":{"f1":"Query","f100":"Query"}}`))
					return
				}
				w.Write([]byte(`{}`))
			},
			expectedFindings: map[string]finding.Severity{
				"GraphQL Batching Enabled":              finding.SeverityLow,
				"GraphQL Query Complexity Limit Missing": finding.SeverityMedium,
			},
		},
		{
			name: "Detect SQL Injection in Variables",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				bodyBytes := make([]byte, r.ContentLength)
				r.Body.Read(bodyBytes)
				body := string(bodyBytes)

				if strings.Contains(body, "{__typename}") {
					w.Write([]byte(`{"data":{"__typename":"Query"}}`))
					return
				}
				if strings.Contains(body, "1 OR 1=1") || strings.Contains(body, "SQLSTATE") {
					w.Write([]byte(`{"errors":[{"message":"SQLSTATE[42000]: Syntax error or access violation: 1064"}]}`))
					return
				}
				w.Write([]byte(`{}`))
			},
			expectedFindings: map[string]finding.Severity{
				"GraphQL SQL Injection via Variables": finding.SeverityHigh,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			mod := &GraphQLScanner{
				client: httpclient.NewClient(httpclient.Options{
					Timeout:    1 * time.Second,
					MaxRetries: 0,
				}),
			}

			task := module.Task{
				ID:     "task-gql-1",
				Type:   "url",
				Target: target.Target{ID: "tgt-gql-1", Type: target.TargetTypeURL, Value: server.URL},
			}

			findings, nextTasks, err := mod.Run(context.Background(), task)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(nextTasks) != 0 {
				t.Errorf("expected 0 next tasks, got %d", len(nextTasks))
			}

			foundCount := 0
			for _, f := range findings {
				expectedSev, exists := tt.expectedFindings[f.Title]
				if !exists {
					t.Errorf("unexpected finding title %q", f.Title)
					continue
				}
				if f.Severity != expectedSev {
					t.Errorf("expected severity %v for finding %q, got %v", expectedSev, f.Title, f.Severity)
				}
				foundCount++
			}

			if foundCount != len(tt.expectedFindings) {
				t.Errorf("expected %d findings matching criteria, got %d (total=%d)", len(tt.expectedFindings), foundCount, len(findings))
			}
		})
	}
}
