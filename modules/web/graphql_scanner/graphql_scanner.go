package graphql_scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/httpclient"
	"github.com/sift-scanner/sift/pkg/module"
	"github.com/spf13/viper"
)

func init() {
	registry.Register(&GraphQLScanner{})
}

// GraphQLScanner implements Section 7 of DESIGN.md.
type GraphQLScanner struct {
	client *httpclient.Client
}

// Name returns the module name.
func (g *GraphQLScanner) Name() string {
	return "graphql_scanner"
}

// Consumes returns the task types this module handles.
func (g *GraphQLScanner) Consumes() []module.TaskType {
	return []module.TaskType{"url"}
}

// Produces returns the task types this module produces.
func (g *GraphQLScanner) Produces() []module.TaskType {
	return []module.TaskType{"finding"}
}

func (g *GraphQLScanner) getClient() *httpclient.Client {
	if g.client != nil {
		return g.client
	}

	viper.SetDefault("graphql.request_timeout", "10s")
	_ = viper.BindEnv("graphql.request_timeout", "GRAPHQL_REQUEST_TIMEOUT")
	timeout := viper.GetDuration("graphql.request_timeout")

	return httpclient.NewClient(httpclient.Options{
		Timeout:            timeout,
		InsecureSkipVerify: true,
		MaxRetries:         0,
	})
}

// Run scans the target URL for GraphQL security issues.
func (g *GraphQLScanner) Run(ctx context.Context, task module.Task) ([]module.Finding, []module.Task, error) {
	baseURL := strings.TrimSpace(task.Target.Value)
	if baseURL == "" {
		return nil, nil, fmt.Errorf("empty URL target")
	}

	client := g.getClient()

	// 1. Probe for GraphQL endpoints
	paths := []string{"/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query", "/gql"}
	var detectedEndpoints []string

	for _, p := range paths {
		// Respect context cancellation
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		u, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		u.Path = strings.TrimSuffix(u.Path, "/") + p
		targetURL := u.String()

		if g.probeEndpoint(ctx, client, targetURL) {
			detectedEndpoints = append(detectedEndpoints, targetURL)
		}
	}

	if len(detectedEndpoints) == 0 {
		return nil, nil, nil
	}

	viper.SetDefault("graphql.checks_enabled", "introspection,suggestion,depth,complexity,batching,auth_bypass,sqli,alias_amplification")
	_ = viper.BindEnv("graphql.checks_enabled", "GRAPHQL_CHECKS_ENABLED")
	enabledChecksStr := viper.GetString("graphql.checks_enabled")
	enabledChecks := make(map[string]bool)
	for _, c := range strings.Split(enabledChecksStr, ",") {
		enabledChecks[strings.TrimSpace(c)] = true
	}

	var findings []module.Finding

	for _, endpoint := range detectedEndpoints {
		var schemaTypes []string

		// Check 1: Introspection Check
		if enabledChecks["introspection"] {
			ok, types, f := g.checkIntrospection(ctx, client, endpoint, task)
			if ok {
				findings = append(findings, f)
				schemaTypes = types
			}
		}

		// Check 2: Field Suggestion Leakage
		if enabledChecks["suggestion"] {
			ok, f := g.checkFieldSuggestions(ctx, client, endpoint, task)
			if ok {
				findings = append(findings, f)
			}
		}

		// Check 3: Query Depth Abuse
		if enabledChecks["depth"] {
			ok, f := g.checkQueryDepth(ctx, client, endpoint, task)
			if ok {
				findings = append(findings, f)
			}
		}

		// Check 4: Query Complexity Abuse
		if enabledChecks["complexity"] {
			ok, f := g.checkQueryComplexity(ctx, client, endpoint, task)
			if ok {
				findings = append(findings, f)
			}
		}

		// Check 5: Batching Attack
		if enabledChecks["batching"] {
			ok, f := g.checkBatching(ctx, client, endpoint, task)
			if ok {
				findings = append(findings, f)
			}
		}

		// Check 6: Auth Bypass on Sensitive Resolvers
		if enabledChecks["auth_bypass"] {
			ok, f := g.checkAuthBypass(ctx, client, endpoint, schemaTypes, task)
			if ok {
				findings = append(findings, f)
			}
		}

		// Check 7: GraphQL Injection via Variables
		if enabledChecks["sqli"] {
			ok, f := g.checkVariablesInjection(ctx, client, endpoint, task)
			if ok {
				findings = append(findings, f)
			}
		}

		// Check 8: Alias Amplification
		if enabledChecks["alias_amplification"] {
			ok, f := g.checkAliasAmplification(ctx, client, endpoint, task)
			if ok {
				findings = append(findings, f)
			}
		}
	}

	return findings, nil, nil
}

func (g *GraphQLScanner) probeEndpoint(ctx context.Context, client *httpclient.Client, urlStr string) bool {
	queryPayload := map[string]string{"query": "{__typename}"}
	data, _ := json.Marshal(queryPayload)

	resp, err := client.DoWithRetry(ctx, "POST", urlStr, bytes.NewReader(data))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		if strings.Contains(contentType, "application/json") || strings.Contains(contentType, "application/graphql") {
			body, err := io.ReadAll(resp.Body)
			if err == nil && (strings.Contains(string(body), `"data"`) || strings.Contains(string(body), `"errors"`)) {
				return true
			}
		}
	}
	return false
}

// 1. Introspection Check
func (g *GraphQLScanner) checkIntrospection(ctx context.Context, client *httpclient.Client, endpoint string, parent module.Task) (bool, []string, module.Finding) {
	query := `{"query":"{__schema{types{name,fields{name}}}}"}`
	resp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(query))
	if err != nil {
		return false, nil, module.Finding{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if strings.Contains(body, "__schema") && strings.Contains(body, "types") {
		// Attempt to extract types
		var parsed struct {
			Data struct {
				Schema struct {
					Types []struct {
						Name   string `json:"name"`
						Fields []struct {
							Name string `json:"name"`
						} `json:"fields"`
					} `json:"types"`
				} `json:"__schema"`
			} `json:"data"`
		}
		var schemaTypes []string
		if err := json.Unmarshal(bodyBytes, &parsed); err == nil {
			for _, t := range parsed.Data.Schema.Types {
				if t.Name != "" && !strings.HasPrefix(t.Name, "__") {
					schemaTypes = append(schemaTypes, t.Name)
				}
			}
		}

		evidenceText := body
		if len(evidenceText) > 500 {
			evidenceText = evidenceText[:500] + "... [truncated] ..."
		}

		findingObj := module.Finding{
			ID:          uuid.New().String(),
			ModuleName:  g.Name(),
			Target:      parent.Target,
			Severity:    finding.SeverityHigh,
			Title:       "GraphQL Introspection Exposed",
			Description: fmt.Sprintf("GraphQL Introspection is enabled at %s. This allows attackers to query the complete database schema, including all types, fields, and queries.", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"response": evidenceText,
			},
			CreatedAt: time.Now(),
		}
		return true, schemaTypes, findingObj
	}
	return false, nil, module.Finding{}
}

// 2. Suggestion Leakage
func (g *GraphQLScanner) checkFieldSuggestions(ctx context.Context, client *httpclient.Client, endpoint string, parent module.Task) (bool, module.Finding) {
	// Query intentionally misspelled type "usr"
	query := `{"query":"{usr{id}}"}`
	resp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(query))
	if err != nil {
		return false, module.Finding{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if strings.Contains(body, "Did you mean") || strings.Contains(body, "didYouMean") {
		findingObj := module.Finding{
			ID:          uuid.New().String(),
			ModuleName:  g.Name(),
			Target:      parent.Target,
			Severity:    finding.SeverityMedium,
			Title:       "GraphQL Field Suggestions Leakage",
			Description: fmt.Sprintf("GraphQL field suggestion is enabled at %s. When querying incorrect fields, the server leaks actual schema structures in suggestions.", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"response": body,
			},
			CreatedAt: time.Now(),
		}
		return true, findingObj
	}
	return false, module.Finding{}
}

// 3. Query Depth Abuse
func (g *GraphQLScanner) checkQueryDepth(ctx context.Context, client *httpclient.Client, endpoint string, parent module.Task) (bool, module.Finding) {
	// Construct a 15-level deeply nested query
	// In the absence of a real recursive schema, we can construct nested query using a guessed schema or generic __typename structure nested under dummy queries.
	// E.g., nested blocks: a { a { ... } }
	// A simpler way: since any node usually rejects depth on validation before executing, if we build a nested __typename query on a schema, it might trigger.
	// But let's build a typical query using aliases or dummy nesting.
	// E.g., query { __schema { types { fields { type { fields { type { name } } } } } } }
	var sb strings.Builder
	sb.WriteString(`{"query":"query { `)
	for i := 0; i < 15; i++ {
		sb.WriteString(`__schema { types { `)
	}
	sb.WriteString(`name`)
	for i := 0; i < 15; i++ {
		sb.WriteString(` } }`)
	}
	sb.WriteString(` }"}`)

	resp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(sb.String()))
	if err != nil {
		return false, module.Finding{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// If the server accepts it and returns 200 without depth restriction errors
	if resp.StatusCode == http.StatusOK && !strings.Contains(strings.ToLower(body), "depth") && !strings.Contains(strings.ToLower(body), "limit") {
		findingObj := module.Finding{
			ID:          uuid.New().String(),
			ModuleName:  g.Name(),
			Target:      parent.Target,
			Severity:    finding.SeverityMedium,
			Title:       "GraphQL Query Depth Limit Missing",
			Description: fmt.Sprintf("The GraphQL endpoint at %s does not enforce query depth limits. Attackers can execute deeply nested resource-consuming queries to cause a Denial of Service (DoS).", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"query":    "15-level nested __schema query",
				"status":   resp.StatusCode,
			},
			CreatedAt: time.Now(),
		}
		return true, findingObj
	}
	return false, module.Finding{}
}

// 4. Query Complexity Abuse
func (g *GraphQLScanner) checkQueryComplexity(ctx context.Context, client *httpclient.Client, endpoint string, parent module.Task) (bool, module.Finding) {
	var sb strings.Builder
	sb.WriteString(`{"query":"query { `)
	for i := 1; i <= 100; i++ {
		sb.WriteString(fmt.Sprintf("f%d: __typename ", i))
	}
	sb.WriteString(`}"}`)

	resp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(sb.String()))
	if err != nil {
		return false, module.Finding{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if resp.StatusCode == http.StatusOK && !strings.Contains(strings.ToLower(body), "complexity") && !strings.Contains(strings.ToLower(body), "limit") {
		findingObj := module.Finding{
			ID:          uuid.New().String(),
			ModuleName:  g.Name(),
			Target:      parent.Target,
			Severity:    finding.SeverityMedium,
			Title:       "GraphQL Query Complexity Limit Missing",
			Description: fmt.Sprintf("The GraphQL endpoint at %s does not limit query complexity. Attackers can request hundreds of fields in a single query, overloading database/backend resources.", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"query":    "100 fields requested via aliases",
				"status":   resp.StatusCode,
			},
			CreatedAt: time.Now(),
		}
		return true, findingObj
	}
	return false, module.Finding{}
}

// 5. Batching Attack
func (g *GraphQLScanner) checkBatching(ctx context.Context, client *httpclient.Client, endpoint string, parent module.Task) (bool, module.Finding) {
	query := `[{"query":"{__typename}"},{"query":"{__typename}"}]`
	resp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(query))
	if err != nil {
		return false, module.Finding{}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	// Verify that response is a JSON array and contains expected graphql output
	if strings.HasPrefix(body, "[") && strings.Contains(body, "__typename") {
		findingObj := module.Finding{
			ID:          uuid.New().String(),
			ModuleName:  g.Name(),
			Target:      parent.Target,
			Severity:    finding.SeverityLow,
			Title:       "GraphQL Batching Enabled",
			Description: fmt.Sprintf("The GraphQL endpoint at %s allows array-based query batching. This allows execution of multiple operations in a single HTTP request, facilitating brute force and query amplification.", endpoint),
			Evidence: map[string]any{
				"endpoint": endpoint,
				"response": body,
			},
			CreatedAt: time.Now(),
		}
		return true, findingObj
	}
	return false, module.Finding{}
}

// 6. Auth Bypass on Sensitive Resolvers
func (g *GraphQLScanner) checkAuthBypass(ctx context.Context, client *httpclient.Client, endpoint string, schemaTypes []string, parent module.Task) (bool, module.Finding) {
	sensitiveKeywords := []string{"user", "admin", "password", "token", "secret", "credential", "key"}

	// Target query selection
	var targetQueries []string
	for _, st := range schemaTypes {
		lowered := strings.ToLower(st)
		for _, kw := range sensitiveKeywords {
			if strings.Contains(lowered, kw) {
				// Query fields: standard guess { id, name }
				targetQueries = append(targetQueries, fmt.Sprintf("%s { id }", st))
				break
			}
		}
	}

	// Default fallbacks if introspection failed or no matching keywords
	if len(targetQueries) == 0 {
		targetQueries = []string{"users { id }", "admin { id }", "secrets { id }"}
	}

	for _, tq := range targetQueries {
		query := fmt.Sprintf(`{"query":"{ %s }"}`, tq)
		body, statusCode, err := func() (string, int, error) {
			resp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(query))
			if err != nil {
				return "", 0, err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return string(b), resp.StatusCode, nil
		}()
		if err != nil {
			continue
		}

		// Check if response returned data and did NOT contain typical "unauthorized" or "forbidden" errors
		loweredBody := strings.ToLower(body)
		if statusCode == http.StatusOK && strings.Contains(body, `"data"`) &&
			!strings.Contains(loweredBody, "unauthorized") &&
			!strings.Contains(loweredBody, "forbidden") &&
			!strings.Contains(loweredBody, "access denied") {

			findingObj := module.Finding{
				ID:          uuid.New().String(),
				ModuleName:  g.Name(),
				Target:      parent.Target,
				Severity:    finding.SeverityHigh,
				Title:       "GraphQL Sensitive Resolver Authentication Bypass",
				Description: fmt.Sprintf("Sensitive resolver query '%s' at %s responded successfully without credentials or authentication headers.", tq, endpoint),
				Evidence: map[string]any{
					"endpoint": endpoint,
					"query":    query,
					"response": body,
				},
				CreatedAt: time.Now(),
			}
			return true, findingObj
		}
	}

	return false, module.Finding{}
}

// 7. GraphQL Injection via Variables
func (g *GraphQLScanner) checkVariablesInjection(ctx context.Context, client *httpclient.Client, endpoint string, parent module.Task) (bool, module.Finding) {
	sqlErrorPatterns := []string{
		"SQLSTATE",
		"syntax error",
		"mysql_fetch",
		"PostgreSQL query failed",
		"SQLite/JDBCDriver",
		"Microsoft OLE DB Provider for SQL Server",
		"execute query failed",
		"oracle error",
	}

	// Payload variables containing common SQL injection signatures
	payloads := []string{"1 OR 1=1", "' OR '1'='1"}

	for _, pay := range payloads {
		// Send query using variables field containing SQLi payload
		query := fmt.Sprintf(`{"query":"query($id: String){item(id: $id){name}}", "variables":{"id":"%s"}}`, pay)
		body, _, err := func() (string, int, error) {
			resp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(query))
			if err != nil {
				return "", 0, err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return string(b), resp.StatusCode, nil
		}()
		if err != nil {
			continue
		}

		for _, pattern := range sqlErrorPatterns {
			if strings.Contains(body, pattern) {
				findingObj := module.Finding{
					ID:          uuid.New().String(),
					ModuleName:  g.Name(),
					Target:      parent.Target,
					Severity:    finding.SeverityHigh,
					Title:       "GraphQL SQL Injection via Variables",
					Description: fmt.Sprintf("Variable field injection returned server-side SQL database error patterns at %s, indicating vulnerability to SQL injection.", endpoint),
					Evidence: map[string]any{
						"endpoint": endpoint,
						"payload":  pay,
						"response": body,
					},
					CreatedAt: time.Now(),
				}
				return true, findingObj
			}
		}
	}

	return false, module.Finding{}
}

// 8. Alias Amplification
func (g *GraphQLScanner) checkAliasAmplification(ctx context.Context, client *httpclient.Client, endpoint string, parent module.Task) (bool, module.Finding) {
	// Baseline: 5 aliases
	var baseSb strings.Builder
	baseSb.WriteString(`{"query":"query { `)
	for i := 1; i <= 5; i++ {
		baseSb.WriteString(fmt.Sprintf("f%d: __typename ", i))
	}
	baseSb.WriteString(`}"}`)

	startBase := time.Now()
	respBase, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(baseSb.String()))
	if err != nil {
		return false, module.Finding{}
	}
	respBase.Body.Close()
	elapsedBase := time.Since(startBase)

	// Amplified: 500 aliases
	var ampSb strings.Builder
	ampSb.WriteString(`{"query":"query { `)
	for i := 1; i <= 500; i++ {
		ampSb.WriteString(fmt.Sprintf("f%d: __typename ", i))
	}
	ampSb.WriteString(`}"}`)

	startAmp := time.Now()
	respAmp, err := client.DoWithRetry(ctx, "POST", endpoint, strings.NewReader(ampSb.String()))
	if err != nil {
		return false, module.Finding{}
	}
	respAmp.Body.Close()
	elapsedAmp := time.Since(startAmp)

	// Check if amplified is > 5x slower
	if elapsedAmp > 5*elapsedBase && elapsedAmp > 20*time.Millisecond {
		findingObj := module.Finding{
			ID:          uuid.New().String(),
			ModuleName:  g.Name(),
			Target:      parent.Target,
			Severity:    finding.SeverityMedium,
			Title:       "GraphQL Alias Amplification Vulnerability",
			Description: fmt.Sprintf("The GraphQL server at %s is vulnerable to alias-based query amplification. Processing 500 aliases was over 5x slower (%v) compared to baseline (%v).", endpoint, elapsedAmp, elapsedBase),
			Evidence: map[string]any{
				"endpoint":     endpoint,
				"baseline_ms":  elapsedBase.Milliseconds(),
				"amplified_ms": elapsedAmp.Milliseconds(),
			},
			CreatedAt: time.Now(),
		}
		return true, findingObj
	}

	return false, module.Finding{}
}

// Ensure interface compliance.
var _ module.Module = (*GraphQLScanner)(nil)
