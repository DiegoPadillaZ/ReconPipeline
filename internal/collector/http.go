package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/DiegoPadillaZ/ReconPipeline/internal/config"
	"github.com/DiegoPadillaZ/ReconPipeline/models"
	"go.uber.org/zap"
)

// HTTPCollector implements Collector using the standard net/http client.
type HTTPCollector struct {
	cfg    *config.Config
	client *http.Client
	log    *zap.Logger
}

// NewHTTPCollector constructs an HTTPCollector with the provided config and logger.
func NewHTTPCollector(cfg *config.Config, log *zap.Logger) (*HTTPCollector, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		Proxy:           http.ProxyFromEnvironment,
	}
	client := &http.Client{
		Timeout:   time.Duration(cfg.TimeoutSecs) * time.Second,
		Transport: transport,
		// capture redirect chain; do not follow more than 10 hops
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("collector: stopped after 10 redirects")
			}
			return nil
		},
	}
	return &HTTPCollector{cfg: cfg, client: client, log: log}, nil
}

// Collect performs an HTTP GET against target and returns raw metadata.
func (c *HTTPCollector) Collect(ctx context.Context, target models.Target) (*models.CollectedData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("collector: build request for %q: %w", target.URL, err)
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)

	// timing probes
	var (
		dnsStart, dnsDone                 time.Time
		tcpStart, tcpDone                 time.Time
		tlsStart, tlsDone                 time.Time
		firstByte                         time.Time
		tlsState                          *tls.ConnectionState
	)

	trace := &httptrace.ClientTrace{
		DNSStart:         func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:          func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart:     func(_, _ string) { tcpStart = time.Now() },
		ConnectDone:      func(_, _ string, _ error) { tcpDone = time.Now() },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			tlsDone = time.Now()
			if err == nil {
				tlsState = &state
			}
		},
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	reqStart := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("collector: request %q: %w", target.URL, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // cap body at 64 KB
	total := time.Since(reqStart)

	data := &models.CollectedData{
		Target:      target,
		StatusCode:  resp.StatusCode,
		Headers:     map[string][]string(resp.Header),
		RawBody:     body,
		HTTPVersion: resp.Proto,
		Compression: resp.Header.Get("Content-Encoding"),
		ServerBanner: resp.Header.Get("Server"),
		CollectedAt: time.Now(),
		Timing: models.TimingInfo{
			DNSLookup:    safeDur(dnsStart, dnsDone),
			TCPConnect:   safeDur(tcpStart, tcpDone),
			TLSHandshake: safeDur(tlsStart, tlsDone),
			FirstByte:    safeDur(reqStart, firstByte),
			Total:        total,
		},
	}

	for _, rc := range resp.Cookies() {
		data.Cookies = append(data.Cookies, &models.Cookie{
			Name:     rc.Name,
			Value:    rc.Value,
			Secure:   rc.Secure,
			HttpOnly: rc.HttpOnly,
			SameSite: sameSiteString(rc.SameSite),
			Path:     rc.Path,
			Domain:   rc.Domain,
			Expires:  rc.Expires,
		})
	}

	if tlsState != nil {
		data.TLS = mapTLSState(tlsState)
	}

	c.log.Debug("collected",
		zap.String("url", target.URL),
		zap.Int("status", resp.StatusCode),
		zap.Duration("total", total))
	return data, nil
}

func mapTLSState(state *tls.ConnectionState) *models.TLSInfo {
	info := &models.TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.String()
		info.Issuer = cert.Issuer.String()
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
		info.SelfSigned = cert.Subject.String() == cert.Issuer.String()
		info.SANs = cert.DNSNames
		info.CertificateChain = len(state.PeerCertificates)
	}
	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

func safeDur(start, end time.Time) time.Duration {
	if start.IsZero() || end.IsZero() {
		return 0
	}
	return end.Sub(start)
}

// weakCiphers contains cipher suite substrings considered weak.
var weakCiphers = []string{"RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "ANON"}

func isWeakCipher(cipher string) bool {
	upper := strings.ToUpper(cipher)
	for _, w := range weakCiphers {
		if strings.Contains(upper, w) {
			return true
		}
	}
	return false
}
