package index

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// TemplateInfo represents the metadata block in a Nuclei template.
type TemplateInfo struct {
	Name     string         `yaml:"name"`
	Severity string         `yaml:"severity"`
	Tags     string         `yaml:"tags"`
	Metadata map[string]any `yaml:"metadata"`
}

// TemplateEntry represents a single Nuclei template entry.
type TemplateEntry struct {
	ID       string       `yaml:"id"`
	Info     TemplateInfo `yaml:"info"`
	FilePath string
}

// TemplateIndex houses the in-memory parsed templates indexed by tags, technology, and port.
type TemplateIndex struct {
	ByTag        map[string][]TemplateEntry
	ByTechnology map[string][]TemplateEntry
	ByPort       map[int][]TemplateEntry
	All          []TemplateEntry
}

// NewTemplateIndex parses all Nuclei templates in the specified directory path.
func NewTemplateIndex(path string) (*TemplateIndex, error) {
	idx := &TemplateIndex{
		ByTag:        make(map[string][]TemplateEntry),
		ByTechnology: make(map[string][]TemplateEntry),
		ByPort:       make(map[int][]TemplateEntry),
		All:          make([]TemplateEntry, 0),
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return idx, nil
	}

	err := filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(filePath, ".yaml") && !strings.HasSuffix(filePath, ".yml")) {
			return nil
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil // ignore unreadable files
		}

		var entry TemplateEntry
		if err := yaml.Unmarshal(content, &entry); err != nil {
			return nil // ignore invalid yaml files
		}

		if entry.ID == "" {
			return nil // must have an ID
		}

		entry.FilePath = filePath

		idx.All = append(idx.All, entry)

		// Parse tags
		tagsList := strings.Split(strings.ToLower(entry.Info.Tags), ",")
		for _, tag := range tagsList {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				idx.ByTag[tag] = append(idx.ByTag[tag], entry)
			}
		}

		// Parse technology from metadata
		if tech, ok := entry.Info.Metadata["tech"]; ok {
			if techStr, ok := tech.(string); ok {
				techs := strings.Split(strings.ToLower(techStr), ",")
				for _, t := range techs {
					t = strings.TrimSpace(t)
					if t != "" {
						idx.ByTechnology[t] = append(idx.ByTechnology[t], entry)
					}
				}
			}
		}
		if technology, ok := entry.Info.Metadata["technology"]; ok {
			if techStr, ok := technology.(string); ok {
				techs := strings.Split(strings.ToLower(techStr), ",")
				for _, t := range techs {
					t = strings.TrimSpace(t)
					if t != "" {
						idx.ByTechnology[t] = append(idx.ByTechnology[t], entry)
					}
				}
			}
		}

		// Parse classification ports if available
		if classification, ok := entry.Info.Metadata["classification"]; ok {
			if classMap, ok := classification.(map[string]any); ok {
				if dps, ok := classMap["dps"]; ok {
					if dpsStr, ok := dps.(string); ok {
						ports := strings.Split(dpsStr, ",")
						for _, p := range ports {
							var portVal int
							if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &portVal); err == nil {
								idx.ByPort[portVal] = append(idx.ByPort[portVal], entry)
							}
						}
					}
				}
			}
		}

		return nil
	})

	return idx, err
}
