package webapp_identifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sift-scanner/sift/pkg/httpclient"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func TestWebappIdentifier_Run(t *testing.T) {
	tests := []struct {
		name            string
		mainResponse    string
		mainHeaders     map[string]string
		loginPath       string
		loginResponse   string
		expectedCMS     string
		expectedVersion string
	}{
		{
			name:            "Detect WordPress",
			mainResponse:    `<html><head><meta name="generator" content="WordPress 6.2.2" /></head><body>Welcome to the blog</body></html>`,
			loginPath:       "/wp-login.php",
			loginResponse:   `<html><form name="loginform" id="loginform"><input type="submit" name="wp-submit" /></form></html>`,
			expectedCMS:     "wordpress",
			expectedVersion: "6.2.2",
		},
		{
			name:            "Detect Joomla",
			mainResponse:    `<html><head><meta name="generator" content="Joomla! 4.3" /></head><body>Joomla page</body></html>`,
			loginPath:       "/administrator/",
			loginResponse:   `<html><body class="joomla-system">Joomla Panel</body></html>`,
			expectedCMS:     "joomla",
			expectedVersion: "4.3",
		},
		{
			name:            "Detect Drupal",
			mainResponse:    `<html><head><script>var Drupal = Drupal || {}; Drupal.settings = {};</script></head><body>Drupal Page</body></html>`,
			mainHeaders:     map[string]string{"X-Generator": "Drupal 9 (https://www.drupal.org)"},
			expectedCMS:     "drupal",
			expectedVersion: "9",
		},
		{
			name:         "No CMS Detected",
			mainResponse: `<html><body>Just a normal page</body></html>`,
			expectedCMS:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.loginPath != "" && strings.HasSuffix(r.URL.Path, tt.loginPath) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(tt.loginResponse))
					return
				}
				for k, v := range tt.mainHeaders {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.mainResponse))
			}))
			defer server.Close()

			mod := &WebappIdentifier{
				client: httpclient.NewClient(httpclient.Options{
					Timeout:    1 * time.Second,
					MaxRetries: 0,
				}),
			}

			task := module.Task{
				ID:     "task-url-1",
				Type:   "url",
				Target: target.Target{ID: "tgt-url-1", Type: target.TargetTypeURL, Value: server.URL},
			}

			findings, nextTasks, err := mod.Run(context.Background(), task)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("expected 0 findings, got %d", len(findings))
			}

			if tt.expectedCMS == "" {
				if len(nextTasks) != 0 {
					t.Errorf("expected 0 next tasks, got %d", len(nextTasks))
				}
			} else {
				if len(nextTasks) != 1 {
					t.Fatalf("expected 1 next task, got %d", len(nextTasks))
				}
				nt := nextTasks[0]
				expectedType := module.TaskType("cms_context." + tt.expectedCMS)
				if nt.Type != expectedType {
					t.Errorf("expected task type %q, got %q", expectedType, nt.Type)
				}
				cmsVal := nt.Payload["cms"].(string)
				if cmsVal != tt.expectedCMS {
					t.Errorf("expected payload cms %q, got %q", tt.expectedCMS, cmsVal)
				}
				verVal := nt.Payload["version"].(string)
				if verVal != tt.expectedVersion {
					t.Errorf("expected payload version %q, got %q", tt.expectedVersion, verVal)
				}
				confVal := nt.Payload["confidence"].(float32)
				if confVal <= 0.0 || confVal > 1.0 {
					t.Errorf("expected valid confidence score [0,1], got %v", confVal)
				}
			}
		})
	}
}
