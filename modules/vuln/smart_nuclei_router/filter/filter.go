package filter

import (
	"sort"
	"strconv"
	"strings"

	"github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router/index"
)

// CMSContext describes the CMS context of the target.
type CMSContext struct {
	CMS        string  `json:"cms"`
	Version    string  `json:"version"`
	Confidence float32 `json:"confidence"`
}

// ServiceFingerprint represents a fingerprinted port/service.
type ServiceFingerprint struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// NucleiJobPayload describes the payload sent to the nuclei router.
type NucleiJobPayload struct {
	URL        string               `json:"url"`
	CMSContext *CMSContext          `json:"cms_context"`
	Services   []ServiceFingerprint `json:"services"`
	OpenPorts  []int                `json:"open_ports"`
	Headers    map[string]string    `json:"headers"`
}

// FilterCandidates filters down templates from the index based on the target payload context.
func FilterCandidates(idx *index.TemplateIndex, payload NucleiJobPayload) []string {
	candidates := make(map[string]bool)

	// Collect detected technologies
	technologies := make(map[string]bool)
	if payload.CMSContext != nil && payload.CMSContext.CMS != "" {
		technologies[strings.ToLower(payload.CMSContext.CMS)] = true
	}
	for _, svc := range payload.Services {
		if svc.Service != "" {
			technologies[strings.ToLower(svc.Service)] = true
		}
	}

	alwaysTags := map[string]bool{
		"exposure":         true,
		"misconfiguration": true,
		"default-login":    true,
	}

	excludeTags := map[string]bool{
		"dos":  true,
		"fuzz": true,
	}

	for _, entry := range idx.All {
		tagsList := strings.Split(strings.ToLower(entry.Info.Tags), ",")

		// Exclude check
		hasExclude := false
		for _, tag := range tagsList {
			tag = strings.TrimSpace(tag)
			if excludeTags[tag] {
				hasExclude = true
				break
			}
		}
		if hasExclude {
			continue
		}

		include := false

		// 1. Always-include tags check
		for _, tag := range tagsList {
			tag = strings.TrimSpace(tag)
			if alwaysTags[tag] {
				include = true
				break
			}
		}

		// 2. Intersect tags with detected technologies/CMS
		if !include {
			for _, tag := range tagsList {
				tag = strings.TrimSpace(tag)
				if technologies[tag] {
					include = true
					break
				}
			}
		}

		// 3. Check technology metadata
		if !include {
			if tech, ok := entry.Info.Metadata["tech"]; ok {
				if techStr, ok := tech.(string); ok {
					for _, t := range strings.Split(strings.ToLower(techStr), ",") {
						if technologies[strings.TrimSpace(t)] {
							include = true
							break
						}
					}
				}
			}
			if tech, ok := entry.Info.Metadata["technology"]; ok {
				if techStr, ok := tech.(string); ok {
					for _, t := range strings.Split(strings.ToLower(techStr), ",") {
						if technologies[strings.TrimSpace(t)] {
							include = true
							break
						}
					}
				}
			}
		}

		// 4. Check classification / port match
		if !include {
			if classification, ok := entry.Info.Metadata["classification"]; ok {
				if classMap, ok := classification.(map[string]any); ok {
					if dps, ok := classMap["dps"]; ok {
						if dpsStr, ok := dps.(string); ok {
							for _, p := range strings.Split(dpsStr, ",") {
								p = strings.TrimSpace(p)
								for _, openPort := range payload.OpenPorts {
									if strconv.Itoa(openPort) == p {
										include = true
										break
									}
								}
								if include {
									break
								}
							}
						}
					}
				}
			}
		}

		if include {
			candidates[entry.ID] = true
		}
	}

	var result []string
	for id := range candidates {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}
