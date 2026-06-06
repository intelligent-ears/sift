package target

// TargetType represents the type of a scanning target.
type TargetType string

const (
	TargetTypeDomain TargetType = "domain"
	TargetTypeIP     TargetType = "ip"
	TargetTypeURL    TargetType = "url"
	TargetTypeCIDR   TargetType = "cidr"
)

// Target defines the scanning target schema as described in DESIGN.md.
type Target struct {
	ID    string     `json:"id"`
	Type  TargetType `json:"type"`
	Value string     `json:"value"`
	Org   string     `json:"org"`
	Tags  []string   `json:"tags"`
}
