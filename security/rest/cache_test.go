package rest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsVersion(t *testing.T) {
	tests := []struct {
		name     string
		segment  string
		expected bool
	}{
		{"valid version v1", "v1", true},
		{"valid version v2", "v2", true},
		{"valid version v123", "v123", true},
		{"valid version v999", "v999", true},
		{"invalid - no v prefix", "1", false},
		{"invalid - too short", "v", false},
		{"invalid - empty string", "", false},
		{"invalid - contains letters", "v1a", false},
		{"invalid - contains special chars", "v1.0", false},
		{"invalid - uppercase V", "V1", false},
		{"invalid - multiple v", "vv1", false},
		{"invalid - negative", "v-1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isVersion(tt.segment))
		})
	}
}

func TestCalculateCacheKey(t *testing.T) {
	tests := []struct {
		name        string
		rawUrl      string
		expected    string
		expectError bool
	}{
		{
			name:     "simple host",
			rawUrl:   "https://api.example.com/resource",
			expected: "api.example.com",
		},
		{
			name:     "host with port",
			rawUrl:   "https://api.example.com:8080/resource",
			expected: "api.example.com:8080",
		},
		{
			name:     "internal-gateway with version no service",
			rawUrl:   "https://internal-gateway/v10",
			expected: "internal-gateway/v10",
		},
		{
			name:     "internal-gateway with multiple path segments",
			rawUrl:   "https://internal-gateway/some/path/to/something",
			expected: "internal-gateway/some/path/to/something",
		},
		{
			name:     "internal-gateway with trailing slash",
			rawUrl:   "https://internal-gateway/path/",
			expected: "internal-gateway/path",
		},
		{
			name:     "internal-gateway with query params",
			rawUrl:   "https://internal-gateway/path?param=value",
			expected: "internal-gateway/path",
		},
		{
			name:     "public api with complex path",
			rawUrl:   "https://google.com/v10/api/resource/service",
			expected: "google.com",
		},
		{
			name:        "invalid URL",
			rawUrl:      "://invalid-url",
			expectError: true,
		},
		{
			name:     "empty URL",
			rawUrl:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := calculateCacheKey(tt.rawUrl)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetUrlCache(t *testing.T) {
	cache := getUrlCache()
	assert.NotNil(t, cache)

	// Test basic cache operations
	key := "test-key"
	cache.Add(key, empty{})

	_, exists := cache.Get(key)
	assert.True(t, exists, "cache should contain the added key")

	cache.Invalidate(key)
	_, exists = cache.Get(key)
	assert.False(t, exists, "cache should not contain invalidated key")
}
