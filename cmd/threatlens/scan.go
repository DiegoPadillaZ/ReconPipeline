package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/collector"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/config"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/correlation"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/database"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/fingerprint"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/knowledge"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/parser"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/report"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/risk"
	"github.com/DiegoPadillaZ/ReconPipeline/models"
	"github.com/DiegoPadillaZ/ReconPipeline/pkg/utils"
	"go.uber.org/zap"
)

var scanFormat string
var scanName string

var scanCmd = &cobra.Command{
	Use:   "scan [url...]",
	Short: "Scan one or more URLs and produce a security intelligence report",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanFormat, "format", "f", "json",
		"report format: json|markdown|html|csv|sarif")
	scanCmd.Flags().StringVarP(&scanName, "name", "n", "",
		"output filename (without extension); defaults to \"report\"")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	cfg := loadConfig()

	store := openStore(cfg)
	if store != nil {
		defer func() {
			if err := store.Close(); err != nil {
				logger.Warn("database close error", zap.Error(err))
			}
		}()
	}

	kdb := knowledge.NewYAMLDatabase(logger)
	if err := kdb.Load(cfg.KnowledgeDB); err != nil {
		logger.Warn("knowledge DB unavailable; correlation produces no findings", zap.Error(err))
	}

	results := runConcurrentScans(ctx, cfg, kdb, store, args)

	if len(results) == 0 {
		logger.Warn("no successful scans")
		return nil
	}

	return writeReport(cfg, buildReport(results))
}

// runConcurrentScans fans out scans across cfg.Concurrency goroutines.
func runConcurrentScans(
	ctx context.Context,
	cfg *config.Config,
	kdb knowledge.DB,
	store database.Store,
	rawURLs []string,
) []*models.ScanResult {
	sem := make(chan struct{}, cfg.Concurrency)
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []*models.ScanResult
	)

	for _, rawURL := range rawURLs {
		target, err := utils.NormalizeURL(rawURL)
		if err != nil {
			logger.Error("invalid URL", zap.String("url", rawURL), zap.Error(err))
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t models.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			result, err := scanTarget(ctx, cfg, kdb, t)
			if err != nil {
				logger.Error("scan failed", zap.String("url", t.URL), zap.Error(err))
				return
			}
			if store != nil {
				if err := store.SaveResult(ctx, result); err != nil {
					logger.Warn("database save failed", zap.Error(err))
				}
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return results
}

func scanTarget(
	ctx context.Context,
	cfg *config.Config,
	kdb knowledge.DB,
	target models.Target,
) (*models.ScanResult, error) {
	logger.Info("scanning", zap.String("url", target.URL))

	col, err := collector.NewHTTPCollector(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("collector init: %w", err)
	}
	data, err := col.Collect(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}

	data, err = parser.NewHTTPParser(logger).Parse(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	fps, err := fingerprint.NewHeaderEngine(logger).Identify(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}

	result := &models.ScanResult{
		ID:            utils.NewID(),
		Target:        target,
		CollectedData: *data,
		Fingerprints:  fps,
		CollectedAt:   data.CollectedAt,
	}

	findings, err := correlation.NewHeaderCorrelator(kdb, logger).Correlate(ctx, result)
	if err != nil {
		return nil, fmt.Errorf("correlate: %w", err)
	}
	result.Findings = findings

	score, err := risk.NewDefaultEngine(logger).Score(ctx, result)
	if err != nil {
		return nil, fmt.Errorf("risk score: %w", err)
	}
	result.RiskScore = score
	result.AnalysedAt = time.Now()

	logger.Info("scan complete",
		zap.String("url", target.URL),
		zap.Int("findings", len(findings)),
		zap.Float64("risk_score", score))
	return result, nil
}

func buildReport(results []*models.ScanResult) *models.Report {
	rep := &models.Report{
		Title:       "ThreatLens Security Intelligence Report",
		Version:     version,
		GeneratedAt: time.Now(),
		Summary:     models.ReportSummary{BySeverity: make(map[models.Severity]int)},
	}
	totalRisk := 0.0
	for _, r := range results {
		rep.Results = append(rep.Results, *r)
		rep.Summary.TotalFindings += len(r.Findings)
		totalRisk += r.RiskScore
		for _, f := range r.Findings {
			rep.Summary.BySeverity[f.Severity]++
		}
	}
	rep.Summary.TotalTargets = len(results)
	if len(results) > 0 {
		rep.Summary.RiskScore = totalRisk / float64(len(results))
	}
	return rep
}

func loadConfig() *config.Config {
	if cfgFile == "" {
		return config.Default()
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		logger.Warn("config not found, using defaults", zap.Error(err))
		return config.Default()
	}
	return cfg
}

func openStore(cfg *config.Config) database.Store {
	store := database.NewSQLiteStore(logger)
	if err := store.Open(filepath.Join(cfg.OutputDir, "threatlens.db")); err != nil {
		logger.Warn("database unavailable, skipping persistence", zap.Error(err))
		return nil
	}
	return store
}

func writeReport(cfg *config.Config, rep *models.Report) error {
	name := scanName
	if name == "" {
		name = "scan-" + time.Now().Format("20060102-150405")
	}

	// Dedicated folder for this scan's artifacts.
	reportDir := filepath.Join(cfg.OutputDir, name)
	if err := os.MkdirAll(reportDir, 0750); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}

	outPath := filepath.Join(reportDir, "report."+scanFormat)
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open report file: %w", err)
	}
	defer f.Close()

	gen := report.GeneratorFor(models.ReportFormat(scanFormat), logger)
	var buf bytes.Buffer
	if err := gen.Generate(context.Background(), rep, &buf); err != nil {
		return err
	}
	if _, err = f.Write(buf.Bytes()); err != nil {
		return err
	}
	logger.Info("report saved", zap.String("path", outPath))
	return nil
}
