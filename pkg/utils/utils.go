package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/DiegoPadillaZ/ReconPipeline/models"
)

// NewID returns a cryptographically random 32-character hex ID.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NormalizeURL parses raw into a models.Target, prepending https:// when no scheme is present.
func NormalizeURL(raw string) (models.Target, error) {
	// only prepend when there is no scheme separator in the input at all
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return models.Target{}, fmt.Errorf("utils: invalid URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return models.Target{}, fmt.Errorf("utils: URL missing host: %q", raw)
	}
	port := 0
	if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	return models.Target{
		URL:    u.String(),
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   port,
		Path:   u.Path,
	}, nil
}

// Truncate limits s to n runes, appending "…" when truncated.
func Truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
