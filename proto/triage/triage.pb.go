package triage

type TargetContext struct {
	Technologies []string `json:"technologies,omitempty"`
	OpenPorts    []int32  `json:"open_ports,omitempty"`
	CmsType      string   `json:"cms_type,omitempty"`
	CmsVersion   string   `json:"cms_version,omitempty"`
}

type RankRequest struct {
	TemplateIds   []string       `json:"template_ids,omitempty"`
	TargetContext *TargetContext `json:"target_context,omitempty"`
}

type ScoredTemplate struct {
	TemplateId string  `json:"template_id,omitempty"`
	Score      float32 `json:"score,omitempty"`
}

type RankResponse struct {
	Templates []*ScoredTemplate `json:"templates,omitempty"`
}

type Finding struct {
	ModuleName string            `json:"module_name,omitempty"`
	Title      string            `json:"title,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

type ScoreRequest struct {
	Finding       *Finding       `json:"finding,omitempty"`
	TargetContext *TargetContext `json:"target_context,omitempty"`
}

type ScoreResponse struct {
	FalsePosProb     float32 `json:"false_pos_prob,omitempty"`
	AdjustedSeverity float32 `json:"adjusted_severity,omitempty"`
}

type OutcomeRequest struct {
	TemplateId       string `json:"template_id,omitempty"`
	TargetType       string `json:"target_type,omitempty"`
	Hit              bool   `json:"hit,omitempty"`
	AnalystConfirmed bool   `json:"analyst_confirmed,omitempty"`
}

type OutcomeResponse struct {
	Ok bool `json:"ok,omitempty"`
}
