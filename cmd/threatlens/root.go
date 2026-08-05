package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	logger    *zap.Logger
	cfgFile   string
	outputDir string
	verbosity string
)

var rootCmd = &cobra.Command{
	Use:   "threatlens",
	Short: "ThreatLens — cybersecurity intelligence engine",
	Long: `ThreatLens collects HTTP metadata and correlates findings with
MITRE ATT&CK, CAPEC, CWE, OWASP, and security-header best practices
to explain attack paths, risks, and mitigations.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initLogger(verbosity)
	},
}

// Execute is the CLI entry point called from main.
func Execute() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: threatlens.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "./reports", "output directory for reports")
	rootCmd.PersistentFlags().StringVarP(&verbosity, "verbosity", "v", "info", "log level: debug | info | warn | error")
}

func initLogger(level string) error {
	var cfg zap.Config
	if level == "debug" {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}

	var err error
	logger, err = cfg.Build()
	if err != nil {
		return fmt.Errorf("logger: init: %w", err)
	}
	return nil
}
