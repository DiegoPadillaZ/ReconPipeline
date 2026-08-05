package utils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/DiegoPadillaZ/ReconPipeline/pkg/utils"
)

func TestNewID_UniqueAndLength(t *testing.T) {
	a := utils.NewID()
	b := utils.NewID()
	assert.Len(t, a, 32)
	assert.NotEqual(t, a, b)
}

func TestNormalizeURL_WithScheme(t *testing.T) {
	target, err := utils.NormalizeURL("https://example.com/path")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/path", target.URL)
	assert.Equal(t, "https", target.Scheme)
	assert.Equal(t, "example.com", target.Host)
	assert.Equal(t, 443, target.Port)
}

func TestNormalizeURL_MissingScheme(t *testing.T) {
	target, err := utils.NormalizeURL("example.com")
	require.NoError(t, err)
	assert.Equal(t, "https", target.Scheme)
	assert.Equal(t, "example.com", target.Host)
}

func TestNormalizeURL_HTTPScheme(t *testing.T) {
	target, err := utils.NormalizeURL("http://example.com")
	require.NoError(t, err)
	assert.Equal(t, "http", target.Scheme)
	assert.Equal(t, 80, target.Port)
}

func TestNormalizeURL_Invalid(t *testing.T) {
	_, err := utils.NormalizeURL("://bad")
	assert.Error(t, err)
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", utils.Truncate("hello", 10))
	assert.Equal(t, "hel…", utils.Truncate("hello", 3))
}
