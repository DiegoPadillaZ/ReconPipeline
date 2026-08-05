package correlation

import (
	"context"

	"github.com/DiegoPadillaZ/ReconPipeline/models"
)

// Engine correlates raw findings into meaningful attack scenarios.
type Engine interface {
	Correlate(ctx context.Context, result *models.ScanResult) ([]models.Finding, error)
}
