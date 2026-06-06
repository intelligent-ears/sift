package nats

import "fmt"

const (
	// SubjectTaskDomain represents a new domain ingested.
	SubjectTaskDomain = "sift.tasks.domain"

	// SubjectTaskSubdomain represents a discovered subdomain.
	SubjectTaskSubdomain = "sift.tasks.subdomain"

	// SubjectTaskIP represents a resolved IP.
	SubjectTaskIP = "sift.tasks.ip"

	// SubjectTaskURL represents a discovered URL.
	SubjectTaskURL = "sift.tasks.url"

	// SubjectTaskOpenPortWildcard is the wildcard subject for any open port.
	SubjectTaskOpenPortWildcard = "sift.tasks.open_port.*"

	// SubjectTaskService represents a fingerprinted service.
	SubjectTaskService = "sift.tasks.service"

	// SubjectTaskCMSContextWildcard is the wildcard subject for any CMS context.
	SubjectTaskCMSContextWildcard = "sift.tasks.cms_context.*"

	// SubjectTaskDeviceContext represents an identified device.
	SubjectTaskDeviceContext = "sift.tasks.device_context"

	// SubjectTaskNucleiJob represents a job ready for nuclei execution.
	SubjectTaskNucleiJob = "sift.tasks.nuclei_job"

	// SubjectFindings represents the subject where all findings are published.
	SubjectFindings = "sift.findings"

	// SubjectOutcomes represents the subject for ML feedback events.
	SubjectOutcomes = "sift.outcomes"
)

// SubjectTaskOpenPort returns the specific subject for a given port.
func SubjectTaskOpenPort(port int) string {
	return fmt.Sprintf("sift.tasks.open_port.%d", port)
}

// SubjectTaskCMSContext returns the specific subject for a given CMS.
func SubjectTaskCMSContext(cms string) string {
	return fmt.Sprintf("sift.tasks.cms_context.%s", cms)
}
