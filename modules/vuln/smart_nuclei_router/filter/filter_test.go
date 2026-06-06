package filter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router/index"
)

func TestFilterCandidates_Corpus(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "nuclei-templates-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write 20 test templates to corpus
	templates := []struct {
		filename string
		content  string
	}{
		{
			filename: "wp-xss.yaml",
			content: `
id: wp-xss
info:
  name: WordPress Plugin XSS
  severity: medium
  tags: wordpress,xss,wp-plugin
  metadata:
    tech: wordpress
`,
		},
		{
			filename: "joomla-lfi.yaml",
			content: `
id: joomla-lfi
info:
  name: Joomla LFI
  severity: high
  tags: joomla,lfi
  metadata:
    technology: joomla
`,
		},
		{
			filename: "drupal-rce.yaml",
			content: `
id: drupal-rce
info:
  name: Drupal Core RCE
  severity: critical
  tags: drupal,rce
  metadata:
    tech: drupal
`,
		},
		{
			filename: "nginx-exposure.yaml",
			content: `
id: nginx-exposure
info:
  name: Nginx Version Exposure
  severity: low
  tags: exposure,nginx
`,
		},
		{
			filename: "default-tomcat.yaml",
			content: `
id: default-tomcat
info:
  name: Tomcat Default Login
  severity: high
  tags: default-login,tomcat
`,
		},
		{
			filename: "git-misconfig.yaml",
			content: `
id: git-misconfig
info:
  name: Git Config Exposure
  severity: medium
  tags: misconfiguration,git
`,
		},
		{
			filename: "ssh-dos.yaml",
			content: `
id: ssh-dos
info:
  name: SSH Denial of Service
  severity: high
  tags: dos,ssh
`,
		},
		{
			filename: "web-fuzz.yaml",
			content: `
id: web-fuzz
info:
  name: Web Parameter Fuzzer
  severity: medium
  tags: fuzz,web
`,
		},
		{
			filename: "port-80-http.yaml",
			content: `
id: port-80-http
info:
  name: HTTP Service Check
  severity: info
  tags: http,network
  metadata:
    classification:
      dps: "80,8080"
`,
		},
		{
			filename: "port-22-ssh.yaml",
			content: `
id: port-22-ssh
info:
  name: SSH Banner Check
  severity: info
  tags: ssh,network
  metadata:
    classification:
      dps: "22"
`,
		},
	}

	// Add 10 generic templates to make a total of 20
	for i := 1; i <= 10; i++ {
		templates = append(templates, struct {
			filename string
			content  string
		}{
			filename: fmt.Sprintf("generic-%d.yaml", i),
			content: fmt.Sprintf(`
id: generic-%d
info:
  name: Generic Scan %d
  severity: info
  tags: generic,recon
`, i, i),
		})
	}

	// Write them to temp directory
	for _, tc := range templates {
		err := os.WriteFile(filepath.Join(tempDir, tc.filename), []byte(tc.content), 0644)
		if err != nil {
			t.Fatalf("failed to write test template: %v", err)
		}
	}

	// Build index
	idx, err := index.NewTemplateIndex(tempDir)
	if err != nil {
		t.Fatalf("failed to build template index: %v", err)
	}

	if len(idx.All) != 20 {
		t.Fatalf("expected 20 templates in index, got %d", len(idx.All))
	}

	// Define test scenarios
	tests := []struct {
		name          string
		payload       NucleiJobPayload
		expectedIDs   []string
		unexpectedIDs []string
	}{
		{
			name: "WordPress Target Scenario",
			payload: NucleiJobPayload{
				CMSContext: &CMSContext{CMS: "wordpress", Confidence: 0.9},
			},
			expectedIDs:   []string{"wp-xss", "nginx-exposure", "default-tomcat", "git-misconfig"}, // wp + always-include
			unexpectedIDs: []string{"joomla-lfi", "ssh-dos", "web-fuzz"},                           // joomla + exclusions
		},
		{
			name: "Joomla Target Scenario",
			payload: NucleiJobPayload{
				CMSContext: &CMSContext{CMS: "joomla", Confidence: 0.8},
			},
			expectedIDs:   []string{"joomla-lfi", "nginx-exposure", "default-tomcat", "git-misconfig"},
			unexpectedIDs: []string{"wp-xss", "ssh-dos", "web-fuzz"},
		},
		{
			name: "Port 22 SSH Target Scenario",
			payload: NucleiJobPayload{
				OpenPorts: []int{22},
			},
			expectedIDs:   []string{"port-22-ssh", "nginx-exposure", "default-tomcat", "git-misconfig"},
			unexpectedIDs: []string{"port-80-http", "ssh-dos"}, // ssh-dos contains "dos" tag which is excluded
		},
		{
			name: "Always-include check and exclusions check",
			payload: NucleiJobPayload{
				CMSContext: &CMSContext{CMS: "nonexistent"},
				OpenPorts:  []int{9999},
			},
			expectedIDs:   []string{"nginx-exposure", "default-tomcat", "git-misconfig"},
			unexpectedIDs: []string{"ssh-dos", "web-fuzz", "wp-xss", "joomla-lfi", "drupal-rce"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterCandidates(idx, tt.payload)
			gotMap := make(map[string]bool)
			for _, id := range got {
				gotMap[id] = true
			}

			for _, exp := range tt.expectedIDs {
				if !gotMap[exp] {
					t.Errorf("expected candidate list to contain %q, but it did not", exp)
				}
			}

			for _, unexp := range tt.unexpectedIDs {
				if gotMap[unexp] {
					t.Errorf("expected candidate list NOT to contain %q, but it did", unexp)
				}
			}
		})
	}
}
