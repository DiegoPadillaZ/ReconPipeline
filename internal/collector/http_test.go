package collector_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/collector"
	"github.com/DiegoPadillaZ/ReconPipeline/internal/config"
	"github.com/DiegoPadillaZ/ReconPipeline/models"
	"go.uber.org/zap"
)

func TestHTTPCollector_Collect_Status(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "test-value")
		w.Header().Set("Server", "TestServer/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := collector.NewHTTPCollector(config.Default(), zap.NewNop())
	require.NoError(t, err)

	result, err := c.Collect(context.Background(), models.Target{URL: srv.URL})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, result.StatusCode)
	assert.Equal(t, "test-value", result.Headers["X-Custom"][0])
	assert.Equal(t, "TestServer/1.0", result.ServerBanner)
}

func TestHTTPCollector_Collect_Cookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Secure: false, HttpOnly: false})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := collector.NewHTTPCollector(config.Default(), zap.NewNop())
	require.NoError(t, err)

	result, err := c.Collect(context.Background(), models.Target{URL: srv.URL})
	require.NoError(t, err)
	require.Len(t, result.Cookies, 1)
	assert.Equal(t, "session", result.Cookies[0].Name)
	assert.False(t, result.Cookies[0].Secure)
}

func TestHTTPCollector_Collect_InvalidURL(t *testing.T) {
	c, err := collector.NewHTTPCollector(config.Default(), zap.NewNop())
	require.NoError(t, err)

	_, err = c.Collect(context.Background(), models.Target{URL: "://bad-url"})
	assert.Error(t, err)
}
