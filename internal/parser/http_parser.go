package parser

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/DiegoPadillaZ/ReconPipeline/models"
	"go.uber.org/zap"
)

// securityHeaders are expected in every secure HTTP response.
var securityHeaders = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// weakProtocols lists TLS version strings considered insecure.
var weakProtocols = map[string]bool{
	"SSL 3.0": true,
	"TLS 1.0": true,
	"TLS 1.1": true,
}

// weakCiphers contains substrings indicating a weak cipher suite.
var weakCiphers = []string{"RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"}

// HTTPParser implements Parser for HTTP collected data.
type HTTPParser struct {
	log *zap.Logger
}

// NewHTTPParser constructs an HTTPParser.
func NewHTTPParser(log *zap.Logger) *HTTPParser {
	return &HTTPParser{log: log}
}

// Parse enriches CollectedData: marks missing security headers, flags weak TLS,
// and annotates cookie issues.
func (p *HTTPParser) Parse(_ context.Context, data *models.CollectedData) (*models.CollectedData, error) {
	if data == nil {
		return nil, fmt.Errorf("parser: nil collected data")
	}

	// mark missing security headers by injecting sentinel values
	present := make(map[string]bool, len(data.Headers))
	for k := range data.Headers {
		present[strings.ToLower(k)] = true
	}
	for _, h := range securityHeaders {
		if !present[strings.ToLower(h)] {
			// store empty slice as a marker so correlators can detect absence
			if data.Headers == nil {
				data.Headers = make(map[string][]string)
			}
			data.Headers["_missing_"+strings.ToLower(h)] = []string{""}
		}
	}

	// analyse TLS
	if data.TLS != nil {
		data.TLS.WeakProtocol = weakProtocols[data.TLS.Version]
		data.TLS.WeakCipher = isWeakCipher(data.TLS.CipherSuite)

		if !data.TLS.NotAfter.IsZero() {
			data.TLS.SelfSigned = data.TLS.Subject != "" &&
				data.TLS.Subject == data.TLS.Issuer

			// cert expired?
			if time.Now().After(data.TLS.NotAfter) {
				// record expired cert as a synthetic header for correlation
				data.Headers["_cert_expired"] = []string{"true"}
			}
		}
	}

	p.log.Debug("parsed",
		zap.String("url", data.Target.URL),
		zap.Int("status", data.StatusCode))
	return data, nil
}

func isWeakCipher(cipher string) bool {
	upper := strings.ToUpper(cipher)
	for _, w := range weakCiphers {
		if strings.Contains(upper, w) {
			return true
		}
	}
	return false
}
