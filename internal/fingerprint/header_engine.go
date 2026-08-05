package fingerprint

import (
	"context"
	"fmt"
	"strings"

	"github.com/DiegoPadillaZ/ReconPipeline/models"
	"go.uber.org/zap"
)

// HeaderEngine implements Engine using HTTP response headers.
type HeaderEngine struct {
	log *zap.Logger
}

// NewHeaderEngine constructs a HeaderEngine.
func NewHeaderEngine(log *zap.Logger) *HeaderEngine {
	return &HeaderEngine{log: log}
}

// Identify detects technologies from response headers.
func (e *HeaderEngine) Identify(_ context.Context, data *models.CollectedData) ([]models.Fingerprint, error) {
	if data == nil {
		return nil, fmt.Errorf("fingerprint: nil collected data")
	}

	var fps []models.Fingerprint

	header := func(name string) string {
		vals := data.Headers[name]
		if len(vals) == 0 {
			// try canonical form
			for k, v := range data.Headers {
				if strings.EqualFold(k, name) && len(v) > 0 {
					return v[0]
				}
			}
			return ""
		}
		return vals[0]
	}

	if v := header("Server"); v != "" {
		fps = append(fps, detectServer(v)...)
	}
	if v := header("X-Powered-By"); v != "" {
		fps = append(fps, detectPoweredBy(v)...)
	}
	if v := header("Via"); v != "" {
		fps = append(fps, detectCDN(v))
	}
	if v := header("X-Generator"); v != "" {
		fps = append(fps, models.Fingerprint{
			Category:   "cms",
			Name:       v,
			Confidence: 0.9,
			Evidence:   "X-Generator: " + v,
		})
	}

	e.log.Debug("fingerprinted",
		zap.String("url", data.Target.URL),
		zap.Int("count", len(fps)))
	return fps, nil
}

func detectServer(server string) []models.Fingerprint {
	l := strings.ToLower(server)
	var fps []models.Fingerprint
	switch {
	case strings.Contains(l, "nginx"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "nginx",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "apache"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "Apache",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "microsoft-iis"):
		fps = append(fps, models.Fingerprint{Category: "server", Name: "IIS",
			Version: extractVersion(server), Confidence: 0.95, Evidence: "Server: " + server})
	case strings.Contains(l, "cloudflare"):
		fps = append(fps, models.Fingerprint{Category: "cdn", Name: "Cloudflare",
			Confidence: 0.99, Evidence: "Server: " + server})
	default:
		if server != "" {
			fps = append(fps, models.Fingerprint{Category: "server", Name: server,
				Confidence: 0.6, Evidence: "Server: " + server})
		}
	}
	return fps
}

func detectPoweredBy(xpb string) []models.Fingerprint {
	l := strings.ToLower(xpb)
	var fps []models.Fingerprint
	switch {
	case strings.Contains(l, "php"):
		fps = append(fps, models.Fingerprint{Category: "language", Name: "PHP",
			Version: extractVersion(xpb), Confidence: 0.95, Evidence: "X-Powered-By: " + xpb})
	case strings.Contains(l, "express"):
		fps = append(fps, models.Fingerprint{Category: "framework", Name: "Express",
			Confidence: 0.9, Evidence: "X-Powered-By: " + xpb})
	case strings.Contains(l, "asp.net"):
		fps = append(fps, models.Fingerprint{Category: "framework", Name: "ASP.NET",
			Version: extractVersion(xpb), Confidence: 0.95, Evidence: "X-Powered-By: " + xpb})
	}
	return fps
}

func detectCDN(via string) models.Fingerprint {
	l := strings.ToLower(via)
	name := "unknown"
	switch {
	case strings.Contains(l, "cloudflare"):
		name = "Cloudflare"
	case strings.Contains(l, "akamai"):
		name = "Akamai"
	case strings.Contains(l, "fastly"):
		name = "Fastly"
	case strings.Contains(l, "varnish"):
		name = "Varnish"
	}
	return models.Fingerprint{Category: "cdn", Name: name, Confidence: 0.8, Evidence: "Via: " + via}
}

// extractVersion pulls the first /version token from a string.
func extractVersion(s string) string {
	parts := strings.Fields(s)
	for _, p := range parts {
		if idx := strings.Index(p, "/"); idx >= 0 && idx < len(p)-1 {
			return p[idx+1:]
		}
	}
	return ""
}
