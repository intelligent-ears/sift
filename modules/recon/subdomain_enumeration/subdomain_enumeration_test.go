package subdomain_enumeration

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

// RoundTripFunc allows mocking HTTP clients.
type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestSubdomainEnumeration_Run(t *testing.T) {
	tests := []struct {
		name              string
		targetValue       string
		subfinderOutput   string
		crtshResponse     string
		expectedSubCount  int
		expectedUrlsCount int
	}{
		{
			name:            "Success with results",
			targetValue:     "example.com",
			subfinderOutput: "www.example.com\napi.example.com\n",
			crtshResponse: `[
				{"common_name": "example.com", "name_value": "example.com\n*.example.com"},
				{"common_name": "blog.example.com", "name_value": "blog.example.com"}
			]`,
			expectedSubCount:  4, // www, api, blog, example.com
			expectedUrlsCount: 8, // 4 * 2 (http + https)
		},
		{
			name:              "Empty results",
			targetValue:       "example.com",
			subfinderOutput:   "",
			crtshResponse:     `[]`,
			expectedSubCount:  0,
			expectedUrlsCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod := &SubdomainEnumeration{
				runCmd: func(ctx context.Context, name string, arg ...string) ([]byte, error) {
					return []byte(tt.subfinderOutput), nil
				},
				httpClient: &http.Client{
					Transport: RoundTripFunc(func(req *http.Request) *http.Response {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(bytes.NewBufferString(tt.crtshResponse)),
							Header:     make(http.Header),
						}
					}),
				},
			}

			task := module.Task{
				ID:     "task-1",
				Type:   "domain",
				Target: target.Target{ID: "tgt-1", Type: target.TargetTypeDomain, Value: tt.targetValue},
			}

			findings, nextTasks, err := mod.Run(context.Background(), task)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}

			subCount := 0
			urlCount := 0
			for _, nt := range nextTasks {
				if nt.Type == "subdomain" {
					subCount++
				} else if nt.Type == "url" {
					urlCount++
				}
			}

			if subCount != tt.expectedSubCount {
				t.Errorf("expected %d subdomains, got %d", tt.expectedSubCount, subCount)
			}
			if urlCount != tt.expectedUrlsCount {
				t.Errorf("expected %d urls, got %d", tt.expectedUrlsCount, urlCount)
			}
		})
	}
}
