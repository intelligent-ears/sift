package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/sift-scanner/sift/internal/registry"
	"github.com/sift-scanner/sift/internal/store"
	"github.com/sift-scanner/sift/pkg/config"
	"github.com/sift-scanner/sift/pkg/finding"
	"github.com/sift-scanner/sift/pkg/module"
	siftnats "github.com/sift-scanner/sift/pkg/nats"
	"github.com/sift-scanner/sift/pkg/target"

	// Register all modules dynamically so listing works
	_ "github.com/sift-scanner/sift/modules/cms/webapp_identifier"
	_ "github.com/sift-scanner/sift/modules/recon/dns_scanner"
	_ "github.com/sift-scanner/sift/modules/recon/ip_lookup"
	_ "github.com/sift-scanner/sift/modules/recon/port_scanner"
	_ "github.com/sift-scanner/sift/modules/recon/subdomain_enumeration"
	_ "github.com/sift-scanner/sift/modules/vuln/nuclei_module"
	_ "github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router"
	_ "github.com/sift-scanner/sift/modules/web/graphql_scanner"
)

var (
	targetFlag   string
	fileFlag     string
	severityFlag string
	scanIDFlag   string
	formatFlag   string
)

func main() {
	if err := config.Load(os.Getenv("SIFT_CONFIG_PATH")); err != nil {
		// Ignore configuration load error and rely on defaults
	}

	rootCmd := &cobra.Command{
		Use:   "sift",
		Short: "Sift is a next-generation modular vulnerability scanner.",
	}

	// 1. scan command
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Start a new vulnerability scan",
		RunE:  runScan,
	}
	scanCmd.Flags().StringVar(&targetFlag, "target", "", "Single target to scan (domain, IP, URL, CIDR)")
	scanCmd.Flags().StringVar(&fileFlag, "file", "", "Path to a file containing targets (one per line)")
	rootCmd.AddCommand(scanCmd)

	// 2. findings command
	findingsCmd := &cobra.Command{
		Use:   "findings",
		Short: "Query vulnerability scan findings",
		RunE:  runFindings,
	}
	findingsCmd.Flags().StringVar(&targetFlag, "target", "", "Filter findings by target value")
	findingsCmd.Flags().StringVar(&severityFlag, "severity", "", "Filter findings by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	rootCmd.AddCommand(findingsCmd)

	// 3. report command
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate report of a scan run",
		RunE:  runReport,
	}
	reportCmd.Flags().StringVar(&scanIDFlag, "scan-id", "", "Scan ID to generate report for")
	reportCmd.Flags().StringVar(&formatFlag, "format", "markdown", "Report format (default: markdown)")
	_ = reportCmd.MarkFlagRequired("scan-id")
	rootCmd.AddCommand(reportCmd)

	// 4. modules command
	modulesCmd := &cobra.Command{
		Use:   "modules",
		Short: "Manage Sift scanner modules",
	}

	modulesListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all registered modules and status",
		Run:   runModulesList,
	}
	modulesCmd.AddCommand(modulesListCmd)

	modulesEnableCmd := &cobra.Command{
		Use:   "enable [module-name]",
		Short: "Enable a module",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := config.SetModuleEnabled(name, true); err != nil {
				return err
			}
			fmt.Printf("Module '%s' enabled successfully.\n", name)
			return nil
		},
	}
	modulesCmd.AddCommand(modulesEnableCmd)

	modulesDisableCmd := &cobra.Command{
		Use:   "disable [module-name]",
		Short: "Disable a module",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := config.SetModuleEnabled(name, false); err != nil {
				return err
			}
			fmt.Printf("Module '%s' disabled successfully.\n", name)
			return nil
		},
	}
	modulesCmd.AddCommand(modulesDisableCmd)

	rootCmd.AddCommand(modulesCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getStore() (*store.PGStore, error) {
	viper.SetDefault("database.url", "postgres://sift:sift@localhost:5432/sift?sslmode=disable")
	_ = viper.BindEnv("database.url", "DATABASE_URL")
	dbURL := viper.GetString("database.url")
	return store.NewPGStore(dbURL)
}

func getNATS() (*siftnats.Client, error) {
	viper.SetDefault("nats.url", "nats://localhost:4222")
	_ = viper.BindEnv("nats.url", "NATS_URL")
	natsURL := viper.GetString("nats.url")
	return siftnats.Connect(natsURL)
}

func detectTargetType(val string) target.TargetType {
	val = strings.ToLower(val)
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		return target.TargetTypeURL
	}
	if strings.Contains(val, "/") {
		return target.TargetTypeCIDR
	}
	if ip := net.ParseIP(val); ip != nil {
		return target.TargetTypeIP
	}
	return target.TargetTypeDomain
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	var targetsList []string
	if targetFlag != "" {
		targetsList = append(targetsList, targetFlag)
	}

	if fileFlag != "" {
		f, err := os.Open(fileFlag)
		if err != nil {
			return fmt.Errorf("failed to open targets file: %w", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targetsList = append(targetsList, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading targets file: %w", err)
		}
	}

	if len(targetsList) == 0 {
		return fmt.Errorf("either --target or --file must be specified and contain at least one valid target")
	}

	// Connect to components
	dbStore, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to connect to store: %w", err)
	}
	defer dbStore.Close()

	natsClient, err := getNATS()
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	defer natsClient.Close()

	// 1. Create Scan in database
	scanID, err := dbStore.CreateScan(ctx)
	if err != nil {
		return fmt.Errorf("failed to create scan record: %w", err)
	}

	fmt.Printf("Scan created successfully. ID: %s\n", scanID)

	// 2. Persist targets and publish tasks
	for _, rawTarget := range targetsList {
		tType := detectTargetType(rawTarget)
		t := target.Target{
			ID:    uuid.New().String(),
			Type:  tType,
			Value: rawTarget,
			Org:   "Default",
			Tags:  []string{"cli-scan"},
		}

		err = dbStore.SaveTarget(ctx, t)
		if err != nil {
			return fmt.Errorf("failed to save target %s: %w", rawTarget, err)
		}

		// Map target type to initial task type
		var taskType module.TaskType
		switch tType {
		case target.TargetTypeDomain:
			taskType = "domain"
		case target.TargetTypeURL:
			taskType = "url"
		case target.TargetTypeIP:
			taskType = "ip"
		case target.TargetTypeCIDR:
			taskType = "cidr"
		default:
			taskType = "domain"
		}

		task := module.Task{
			ID:     uuid.New().String(),
			Type:   taskType,
			Target: t,
			Payload: map[string]any{
				"scan_id": scanID,
			},
		}

		// Publish to NATS
		subject := fmt.Sprintf("sift.tasks.%s", string(taskType))
		err = natsClient.Publish(ctx, subject, task)
		if err != nil {
			return fmt.Errorf("failed to publish task for target %s: %w", rawTarget, err)
		}

		fmt.Printf("Ingested target: %s [%s]\n", t.Value, string(t.Type))
	}

	fmt.Println("Scan initialized. Orchestrator daemon is processing tasks.")
	return nil
}

func runFindings(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	dbStore, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to connect to store: %w", err)
	}
	defer dbStore.Close()

	filter := store.FindingFilter{}

	// If --target is passed, resolve target value to target ID first
	if targetFlag != "" {
		targets, err := dbStore.GetTargets(ctx)
		if err != nil {
			return fmt.Errorf("failed to query targets: %w", err)
		}
		var foundTargetID string
		for _, t := range targets {
			if strings.EqualFold(t.Value, targetFlag) {
				foundTargetID = t.ID
				break
			}
		}
		if foundTargetID == "" {
			fmt.Printf("No targets found matching '%s'\n", targetFlag)
			return nil
		}
		filter.TargetID = foundTargetID
	}

	if severityFlag != "" {
		filter.Severity = finding.Severity(strings.ToUpper(severityFlag))
	}

	findings, err := dbStore.GetFindings(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to retrieve findings: %w", err)
	}

	if len(findings) == 0 {
		fmt.Println("No findings found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.TabIndent)
	fmt.Fprintln(w, "ID\tSEVERITY\tMODULE\tTITLE\tTARGET")
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", f.ID, string(f.Severity), f.ModuleName, f.Title, f.Target.Value)
	}
	w.Flush()
	return nil
}

func runReport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	dbStore, err := getStore()
	if err != nil {
		return fmt.Errorf("failed to connect to store: %w", err)
	}
	defer dbStore.Close()

	findings, err := dbStore.GetFindings(ctx, store.FindingFilter{ScanID: scanIDFlag})
	if err != nil {
		return fmt.Errorf("failed to query findings for scan: %w", err)
	}

	if formatFlag != "markdown" {
		return fmt.Errorf("unsupported format '%s'. Only 'markdown' is currently supported", formatFlag)
	}

	// Calculate statistics
	stats := map[finding.Severity]int{
		finding.SeverityCritical: 0,
		finding.SeverityHigh:     0,
		finding.SeverityMedium:   0,
		finding.SeverityLow:      0,
		finding.SeverityInfo:     0,
	}
	for _, f := range findings {
		stats[f.Severity]++
	}

	fmt.Printf("# Sift Scan Vulnerability Report\n")
	fmt.Printf("Scan ID: `%s`  \n", scanIDFlag)
	fmt.Printf("Generated At: %s  \n\n", time.Now().Format(time.RFC1123))

	fmt.Printf("## Severity Statistics\n\n")
	fmt.Printf("| Severity | Count |\n")
	fmt.Printf("|---|---|\n")
	fmt.Printf("| CRITICAL | %d |\n", stats[finding.SeverityCritical])
	fmt.Printf("| HIGH | %d |\n", stats[finding.SeverityHigh])
	fmt.Printf("| MEDIUM | %d |\n", stats[finding.SeverityMedium])
	fmt.Printf("| LOW | %d |\n", stats[finding.SeverityLow])
	fmt.Printf("| INFO | %d |\n\n", stats[finding.SeverityInfo])

	fmt.Printf("## Finding Details\n\n")
	if len(findings) == 0 {
		fmt.Println("No findings reported for this scan.")
		return nil
	}

	for i, f := range findings {
		fmt.Printf("### %d. %s\n\n", i+1, f.Title)
		fmt.Printf("- **Severity:** `%s`\n", string(f.Severity))
		fmt.Printf("- **Module:** `%s`\n", f.ModuleName)
		fmt.Printf("- **Target:** `%s` (`%s`)\n", f.Target.Value, string(f.Target.Type))
		fmt.Printf("- **Date:** %s\n\n", f.CreatedAt.Format(time.RFC822))
		fmt.Printf("**Description:**  \n%s\n\n", f.Description)

		if len(f.Evidence) > 0 {
			evidenceBytes, err := json.MarshalIndent(f.Evidence, "", "  ")
			if err == nil {
				fmt.Printf("**Evidence:**\n```json\n%s\n```\n\n", string(evidenceBytes))
			}
		}
		fmt.Printf("---\n\n")
	}

	return nil
}

func runModulesList(cmd *cobra.Command, args []string) {
	modules := registry.All()
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.TabIndent)
	fmt.Fprintln(w, "MODULE NAME\tCONSUMES\tPRODUCES\tSTATUS")
	for _, mod := range modules {
		status := "ENABLED"
		if !config.IsModuleEnabled(mod.Name()) {
			status = "DISABLED"
		}

		var consumes []string
		for _, c := range mod.Consumes() {
			consumes = append(consumes, string(c))
		}
		var produces []string
		for _, p := range mod.Produces() {
			produces = append(produces, string(p))
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			mod.Name(),
			strings.Join(consumes, ", "),
			strings.Join(produces, ", "),
			status,
		)
	}
	w.Flush()
}
