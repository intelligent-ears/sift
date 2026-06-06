package ip_lookup

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/sift-scanner/sift/pkg/target"
)

func init() {
	registry.Register(&IPLookup{})
}

// IPLookup resolves A and AAAA records for a domain or subdomain.
type IPLookup struct {
	lookupIP func(ctx context.Context, host string) ([]net.IPAddr, error)
}

func (i *IPLookup) getLookupIP() func(context.Context, string) ([]net.IPAddr, error) {
	if i.lookupIP != nil {
		return i.lookupIP
	}
	return func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return net.DefaultResolver.LookupIPAddr(ctx, host)
	}
}

// Name returns the module name.
func (i *IPLookup) Name() string {
	return "ip_lookup"
}

// Consumes returns the task types this module handles.
func (i *IPLookup) Consumes() []module.TaskType {
	return []module.TaskType{"domain", "subdomain"}
}

// Produces returns the task types this module produces.
func (i *IPLookup) Produces() []module.TaskType {
	return []module.TaskType{"ip"}
}

// Run executes the IP lookup.
func (i *IPLookup) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	host := strings.TrimSpace(task.Target.Value)
	if host == "" {
		return nil, nil, fmt.Errorf("empty target value")
	}

	lookupIP := i.getLookupIP()
	addrs, err := lookupIP(ctx, host)
	if err != nil {
		// Suppress error and return, similar to other recon modules (DNS lookup failures are common)
		return nil, nil, nil
	}

	ips := make(map[string]bool)
	for _, addr := range addrs {
		ipStr := addr.IP.String()
		if ipStr != "" {
			ips[ipStr] = true
		}
	}

	var nextTasks []module.Task
	for ip := range ips {
		nextTasks = append(nextTasks, module.Task{
			ID:   fmt.Sprintf("ip-%s-%s", host, ip),
			Type: "ip",
			Target: target.Target{
				ID:    task.Target.ID,
				Type:  target.TargetTypeIP,
				Value: ip,
				Org:   task.Target.Org,
				Tags:  task.Target.Tags,
			},
			Payload:  map[string]any{"ip": ip},
			ParentID: task.ID,
		})
	}

	return nil, nextTasks, nil
}

// Ensure interface compliance.
var _ module.Module = (*IPLookup)(nil)
