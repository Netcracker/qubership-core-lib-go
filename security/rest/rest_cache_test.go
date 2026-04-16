package rest

import (
	"net/url"
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
			name:     "internal-gateway with version and service",
			rawUrl:   "https://internal-gateway.namespace.svc/api/v1/service-name/resource",
			expected: "internal-gateway.namespace.svc/api/v1/service-name",
		},
		{
			name:     "internal-gateway with version no service",
			rawUrl:   "https://internal-gateway.namespace.svc/v1/resource",
			expected: "internal-gateway.namespace.svc/v1",
		},
		{
			name:     "internal-gateway without version",
			rawUrl:   "https://internal-gateway.namespace.svc/resource/path",
			expected: "internal-gateway.namespace.svc/resource/path",
		},
		{
			name:     "internal-gateway with multiple path segments",
			rawUrl:   "https://internal-gateway/api/v2/my-service/users/123",
			expected: "internal-gateway/api/v2/my-service",
		},
		{
			name:     "internal-gateway with trailing slash",
			rawUrl:   "https://internal-gateway/api/v1/service/",
			expected: "internal-gateway/api/v1/service",
		},
		{
			name:     "internal-gateway with query params",
			rawUrl:   "https://internal-gateway/api/v1/service/resource?param=value",
			expected: "internal-gateway/api/v1/service",
		},
		{
			name:     "non-internal-gateway with complex path",
			rawUrl:   "https://external-api.com/api/v1/service/resource",
			expected: "external-api.com",
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

func TestCalculateCacheKeyForInternalGateway(t *testing.T) {
	tests := []struct {
		name     string
		rawUrl   string
		expected string
	}{
		{
			name:     "api with version and service name",
			rawUrl:   "https://internal-gateway/api/v1/my-service/resource/123",
			expected: "internal-gateway/api/v1/my-service",
		},
		{
			name:     "api with version no service name",
			rawUrl:   "https://internal-gateway/api/v1",
			expected: "internal-gateway/api/v1",
		},
		{
			name:     "version without api prefix",
			rawUrl:   "https://internal-gateway/v2/resource",
			expected: "internal-gateway/v2",
		},
		{
			name:     "no version in path",
			rawUrl:   "https://internal-gateway/some/path/without/version",
			expected: "internal-gateway/some/path/without/version",
		},
		{
			name:     "root path",
			rawUrl:   "https://internal-gateway/",
			expected: "internal-gateway/",
		},
		{
			name:     "multiple segments before version",
			rawUrl:   "https://internal-gateway/prefix/api/v3/service/resource",
			expected: "internal-gateway/prefix/api/v3",
		},
		{
			name:     "version in middle of path",
			rawUrl:   "https://internal-gateway/prefix/v1/suffix/more",
			expected: "internal-gateway/prefix/v1",
		},
		{
			name:     "api prefix with service but no version",
			rawUrl:   "https://internal-gateway/api/service/resource",
			expected: "internal-gateway/api/service/resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsedUrl, err := url.Parse(tt.rawUrl)
			assert.NoError(t, err)
			result := calculateCacheKeyForInternalGateway(parsedUrl)
			assert.Equal(t, tt.expected, result)
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
