package webapp_identifier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/httpclient"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func init() {
	registry.Register(&WebappIdentifier{})
}

// WebappIdentifier identifies content management systems (CMS).
type WebappIdentifier struct {
	client *httpclient.Client
}

// Name returns the module name.
func (w *WebappIdentifier) Name() string {
	return "webapp_identifier"
}

// Consumes returns the task types this module handles.
func (w *WebappIdentifier) Consumes() []module.TaskType {
	return []module.TaskType{"url"}
}

// Produces returns the task types this module produces.
func (w *WebappIdentifier) Produces() []module.TaskType {
	return []module.TaskType{"cms_context.wordpress", "cms_context.joomla", "cms_context.drupal"}
}

func (w *WebappIdentifier) getClient() *httpclient.Client {
	if w.client != nil {
		return w.client
	}
	return httpclient.NewClient(httpclient.Options{
		Timeout:            15,
		InsecureSkipVerify: true,
	})
}

// Run executes detection rules on the targeted URL.
func (w *WebappIdentifier) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	urlStr := strings.TrimSpace(task.Target.Value)
	if urlStr == "" {
		return nil, nil, fmt.Errorf("empty URL target")
	}

	client := w.getClient()

	// Perform initial page load GET request
	resp, err := client.Get(ctx, urlStr)
	if err != nil {
		return nil, nil, nil // return safely if network error
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyHTML := string(bodyBytes)

	// Check 1: WordPress
	isWP, wpVersion, wpConf := w.detectWordPress(ctx, client, urlStr, resp.Header, bodyHTML)
	if isWP {
		nextTask := w.buildCMSTask("wordpress", wpVersion, wpConf, urlStr, task)
		return nil, []module.Task{nextTask}, nil
	}

	// Check 2: Joomla
	isJoomla, joomlaVersion, joomlaConf := w.detectJoomla(ctx, client, urlStr, resp.Header, bodyHTML)
	if isJoomla {
		nextTask := w.buildCMSTask("joomla", joomlaVersion, joomlaConf, urlStr, task)
		return nil, []module.Task{nextTask}, nil
	}

	// Check 3: Drupal
	isDrupal, drupalVersion, drupalConf := w.detectDrupal(ctx, client, urlStr, resp.Header, bodyHTML)
	if isDrupal {
		nextTask := w.buildCMSTask("drupal", drupalVersion, drupalConf, urlStr, task)
		return nil, []module.Task{nextTask}, nil
	}

	return nil, nil, nil
}

func (w *WebappIdentifier) detectWordPress(ctx context.Context, client *httpclient.Client, baseURL string, headers http.Header, bodyHTML string) (bool, string, float32) {
	var points float32 = 0.0

	// Rule A: wp-content in HTML
	if strings.Contains(bodyHTML, "wp-content") || strings.Contains(bodyHTML, "wp-includes") {
		points += 0.6
	}

	// Rule B: X-Powered-By / Link WP headers
	if strings.Contains(strings.ToLower(headers.Get("X-Powered-By")), "wordpress") {
		points += 0.4
	}
	if strings.Contains(strings.ToLower(headers.Get("Link")), "wp-json") {
		points += 0.4
	}

	// Rule C: Probe wp-login.php endpoint
	loginURL := strings.TrimSuffix(baseURL, "/") + "/wp-login.php"
	loginResp, err := client.Get(ctx, loginURL)
	if err == nil {
		defer loginResp.Body.Close()
		if loginResp.StatusCode == http.StatusOK {
			loginBytes, _ := io.ReadAll(loginResp.Body)
			loginHTML := string(loginBytes)
			if strings.Contains(loginHTML, "wp-submit") || strings.Contains(loginHTML, "wp-login.css") {
				points += 0.7
			}
		}
	}

	if points >= 0.5 {
		// Version detection
		version := w.extractWPVersion(bodyHTML)
		return true, version, w.capConfidence(points)
	}

	return false, "", 0.0
}

func (w *WebappIdentifier) detectJoomla(ctx context.Context, client *httpclient.Client, baseURL string, headers http.Header, bodyHTML string) (bool, string, float32) {
	var points float32 = 0.0

	// Rule A: Joomla! string in HTML or meta tag
	if strings.Contains(bodyHTML, "Joomla!") || strings.Contains(bodyHTML, "joomla") {
		points += 0.3
	}
	if strings.Contains(bodyHTML, "/media/jui/") {
		points += 0.5
	}

	// Rule B: Probe /administrator/ endpoint
	adminURL := strings.TrimSuffix(baseURL, "/") + "/administrator/"
	adminResp, err := client.Get(ctx, adminURL)
	if err == nil {
		defer adminResp.Body.Close()
		if adminResp.StatusCode == http.StatusOK {
			adminBytes, _ := io.ReadAll(adminResp.Body)
			adminHTML := string(adminBytes)
			if strings.Contains(adminHTML, "mod-login") || strings.Contains(adminHTML, "joomla-system") {
				points += 0.7
			}
		}
	}

	if points >= 0.5 {
		version := w.extractJoomlaVersion(bodyHTML)
		return true, version, w.capConfidence(points)
	}

	return false, "", 0.0
}

func (w *WebappIdentifier) detectDrupal(ctx context.Context, client *httpclient.Client, baseURL string, headers http.Header, bodyHTML string) (bool, string, float32) {
	var points float32 = 0.0

	// Rule A: Drupal.settings or X-Generator header
	if strings.Contains(bodyHTML, "Drupal.settings") || strings.Contains(bodyHTML, "/sites/default/") {
		points += 0.7
	}
	if strings.Contains(strings.ToLower(headers.Get("X-Generator")), "drupal") {
		points += 0.8
	}

	if points >= 0.5 {
		version := w.extractDrupalVersion(bodyHTML, headers)
		return true, version, w.capConfidence(points)
	}

	return false, "", 0.0
}

func (w *WebappIdentifier) extractWPVersion(html string) string {
	re := regexp.MustCompile(`(?i)meta name="generator" content="WordPress\s+([0-9\.]+)"`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (w *WebappIdentifier) extractJoomlaVersion(html string) string {
	re := regexp.MustCompile(`(?i)meta name="generator" content="Joomla!\s+([0-9\.]+)"`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (w *WebappIdentifier) extractDrupalVersion(html string, headers http.Header) string {
	// Check header first
	gen := headers.Get("X-Generator")
	if strings.Contains(strings.ToLower(gen), "drupal") {
		re := regexp.MustCompile(`(?i)Drupal\s+([0-9\.]+)`)
		matches := re.FindStringSubmatch(gen)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	// Check meta tag generator in HTML
	re := regexp.MustCompile(`(?i)meta name="generator" content="Drupal\s+([0-9\.]+)"`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (w *WebappIdentifier) capConfidence(score float32) float32 {
	if score > 1.0 {
		return 1.0
	}
	return score
}

func (w *WebappIdentifier) buildCMSTask(cms string, version string, conf float32, urlStr string, parent module.Task) module.Task {
	return module.Task{
		ID:   uuid.New().String(),
		Type: module.TaskType(fmt.Sprintf("cms_context.%s", cms)),
		Target: target.Target{
			ID:    parent.Target.ID,
			Type:  target.TargetTypeURL,
			Value: urlStr,
			Org:   parent.Target.Org,
			Tags:  parent.Target.Tags,
		},
		Payload: map[string]any{
			"cms":        cms,
			"version":    version,
			"confidence": conf,
			"url":        urlStr,
		},
		ParentID: parent.ID,
	}
}

// Ensure interface compliance.
var _ module.Module = (*WebappIdentifier)(nil)
