package dns_scanner

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
)

func init() {
	registry.Register(&DNSScanner{})
}

// DNSScanner performs zone transfer checks against nameservers.
type DNSScanner struct {
	runCmd   func(ctx context.Context, name string, arg ...string) ([]byte, error)
	lookupNS func(ctx context.Context, host string) ([]*net.NS, error)
}

func (d *DNSScanner) getRunCmd() func(context.Context, string, ...string) ([]byte, error) {
	if d.runCmd != nil {
		return d.runCmd
	}
	return func(ctx context.Context, name string, arg ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, arg...)
		return cmd.Output()
	}
}

func (d *DNSScanner) getLookupNS() func(context.Context, string) ([]*net.NS, error) {
	if d.lookupNS != nil {
		return d.lookupNS
	}
	return func(ctx context.Context, host string) ([]*net.NS, error) {
		return net.DefaultResolver.LookupNS(ctx, host)
	}
}

// Name returns the module name.
func (d *DNSScanner) Name() string {
	return "dns_scanner"
}

// Consumes returns the task types this module handles.
func (d *DNSScanner) Consumes() []module.TaskType {
	return []module.TaskType{"domain"}
}

// Produces returns the task types this module produces.
func (d *DNSScanner) Produces() []module.TaskType {
	return []module.TaskType{"finding"}
}

// Run executes the DNSAXFR checks.
func (d *DNSScanner) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	domain := strings.TrimSpace(task.Target.Value)
	if domain == "" {
		return nil, nil, fmt.Errorf("empty domain target")
	}

	lookupNS := d.getLookupNS()
	nss, err := lookupNS(ctx, domain)
	if err != nil {
		// Log error and return (e.g. no nameservers found)
		return nil, nil, nil
	}

	var findings []module.Finding

	for _, ns := range nss {
		nsHost := strings.TrimSuffix(ns.Host, ".")
		if nsHost == "" {
			continue
		}

		success, evidence, _ := d.checkZoneTransfer(ctx, nsHost, domain)
		if success {
			// Limit evidence snippet size
			if len(evidence) > 1000 {
				evidence = evidence[:1000] + "\n...[truncated]..."
			}

			findings = append(findings, module.Finding{
				ID:          fmt.Sprintf("axfr-%s-%s", domain, nsHost),
				ModuleName:  d.Name(),
				Target:      task.Target,
				Severity:    finding.SeverityMedium,
				Title:       "DNS Zone Transfer Allowed",
				Description: fmt.Sprintf("The nameserver %s allowed a full zone transfer (AXFR) for domain %s. This exposes all DNS records in the zone.", nsHost, domain),
				Evidence: map[string]any{
					"nameserver": nsHost,
					"output":     evidence,
				},
				CreatedAt: time.Now(),
			})
		}
	}

	return findings, nil, nil
}

func (d *DNSScanner) checkZoneTransfer(ctx context.Context, ns, domain string) (bool, string, error) {
	runCmd := d.getRunCmd()
	output, err := runCmd(ctx, "dig", "+timeout=5", "axfr", fmt.Sprintf("@%s", ns), domain)
	if err != nil {
		return false, "", err
	}

	outStr := string(output)
	if strings.Contains(outStr, "SOA") &&
		!strings.Contains(outStr, "Transfer failed") &&
		!strings.Contains(outStr, "REFUSED") &&
		!strings.Contains(outStr, "connection timed out") {
		return true, outStr, nil
	}

	return false, "", nil
}

// Ensure interface compliance.
var _ module.Module = (*DNSScanner)(nil)
