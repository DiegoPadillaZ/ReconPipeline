package risk_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/risk"
	"github.com/DiegoPadillaZ/ReconPipeline/models"
	"go.uber.org/zap"
)

func TestDefaultEngine_Score_Empty(t *testing.T) {
	result := &models.ScanResult{Target: models.Target{URL: "http://example.com"}}
	score, err := risk.NewDefaultEngine(zap.NewNop()).Score(context.Background(), result)
	require.NoError(t, err)
	assert.Equal(t, 0.0, score)
}

func TestDefaultEngine_Score_AllHigh(t *testing.T) {
	result := &models.ScanResult{
		Target: models.Target{URL: "http://example.com"},
		Findings: []models.Finding{
			{ID: "F1", Severity: models.SeverityHigh, Confidence: 1.0},
			{ID: "F2", Severity: models.SeverityHigh, Confidence: 1.0},
		},
	}
	score, err := risk.NewDefaultEngine(zap.NewNop()).Score(context.Background(), result)
	require.NoError(t, err)
	// two HIGH (weight 7.5 each) / max 20 * 10 = 7.5
	assert.InDelta(t, 7.5, score, 0.01)
}

func TestDefaultEngine_Recommend_UsesFindingRemediation(t *testing.T) {
	finding := models.Finding{ID: "CSP-MISSING", Title: "Missing CSP", Remediation: "Add CSP header"}
	rec, err := risk.NewDefaultEngine(zap.NewNop()).Recommend(context.Background(), finding)
	require.NoError(t, err)
	assert.Equal(t, "Add CSP header", rec)
}
