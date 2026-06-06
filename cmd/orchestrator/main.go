package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/sift-scanner/sift/internal/orchestrator"
	"github.com/sift-scanner/sift/pkg/config"
	siftnats "github.com/sift-scanner/sift/pkg/nats"

	// Register all implemented modules dynamically
	_ "github.com/sift-scanner/sift/modules/cms/webapp_identifier"
	_ "github.com/sift-scanner/sift/modules/recon/dns_scanner"
	_ "github.com/sift-scanner/sift/modules/recon/ip_lookup"
	_ "github.com/sift-scanner/sift/modules/recon/port_scanner"
	_ "github.com/sift-scanner/sift/modules/recon/subdomain_enumeration"
	_ "github.com/sift-scanner/sift/modules/vuln/nuclei_module"
	_ "github.com/sift-scanner/sift/modules/vuln/smart_nuclei_router"
	_ "github.com/sift-scanner/sift/modules/web/graphql_scanner"
)

func main() {
	// Initialize structured logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Load configuration
	configPath := os.Getenv("SIFT_CONFIG_PATH")
	if err := config.Load(configPath); err != nil {
		logger.Warn("Failed to load configuration file, using defaults", zap.Error(err))
	}

	viper.SetDefault("nats.url", "nats://localhost:4222")
	_ = viper.BindEnv("nats.url", "NATS_URL")
	natsURL := viper.GetString("nats.url")

	logger.Info("Connecting to NATS JetStream", zap.String("url", natsURL))
	natsClient, err := siftnats.ConnectWithLogger(natsURL, logger)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", zap.Error(err))
	}
	defer natsClient.Close()

	// Handle OS shutdown signals gracefully
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Initialize and start orchestrator
	orch := orchestrator.New(natsClient, logger)
	logger.Info("Starting Sift Orchestrator daemon...")
	if err := orch.Start(ctx); err != nil && err != context.Canceled {
		logger.Fatal("Orchestrator encountered error", zap.Error(err))
	}

	logger.Info("Orchestrator daemon stopped gracefully")
}
