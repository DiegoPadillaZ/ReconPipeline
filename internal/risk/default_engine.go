package risk

import (
	"context"
	"fmt"

	"github.com/DiegoPadillaZ/ReconPipeline/models"
	"go.uber.org/zap"
)

// DefaultEngine implements Engine with rule-based risk scoring.
type DefaultEngine struct {
	log *zap.Logger
}

// NewDefaultEngine constructs a DefaultEngine.
func NewDefaultEngine(log *zap.Logger) *DefaultEngine {
	return &DefaultEngine{log: log}
}

// Score aggregates finding severities into an overall risk score (0–10).
func (e *DefaultEngine) Score(_ context.Context, result *models.ScanResult) (float64, error) {
	if result == nil {
		return 0, fmt.Errorf("risk: nil scan result")
	}
	if len(result.Findings) == 0 {
		return 0, nil
	}

	score := 0.0
	for _, f := range result.Findings {
		score += severityWeight(f.Severity) * f.Confidence
	}

	// normalise to 0–10
	max := float64(len(result.Findings)) * 10.0
	if max > 0 {
		score = (score / max) * 10.0
	}

	e.log.Debug("risk scored",
		zap.String("target", result.Target.URL),
		zap.Float64("score", score),
		zap.Int("findings", len(result.Findings)))
	return score, nil
}

// Recommend returns a one-line mitigation for a finding.
func (e *DefaultEngine) Recommend(_ context.Context, finding models.Finding) (string, error) {
	if finding.Remediation != "" {
		return finding.Remediation, nil
	}
	return fmt.Sprintf("Review and remediate %s (%s)", finding.Title, finding.ID), nil
}

func severityWeight(s models.Severity) float64 {
	switch s {
	case models.SeverityCritical:
		return 10.0
	case models.SeverityHigh:
		return 7.5
	case models.SeverityMedium:
		return 5.0
	case models.SeverityLow:
		return 2.5
	default:
		return 1.0
	}
}

var _ Engine = (*DefaultEngine)(nil)
