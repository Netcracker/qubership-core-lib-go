package rest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBodyReaderToBytes(t *testing.T) {
	tests := []struct {
		name        string
		bodyReader  io.Reader
		expected    []byte
		expectError bool
	}{
		{
			name:       "nil reader",
			bodyReader: nil,
			expected:   nil,
		},
		{
			name:       "empty reader",
			bodyReader: strings.NewReader(""),
			expected:   []byte{},
		},
		{
			name:       "string reader",
			bodyReader: strings.NewReader("test body"),
			expected:   []byte("test body"),
		},
		{
			name:       "bytes reader",
			bodyReader: bytes.NewReader([]byte{1, 2, 3, 4, 5}),
			expected:   []byte{1, 2, 3, 4, 5},
		},
		{
			name:       "json body",
			bodyReader: strings.NewReader(`{"key":"value"}`),
			expected:   []byte(`{"key":"value"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := bodyReaderToBytes(tt.bodyReader)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestNewHttpRequestProducer(t *testing.T) {
	tests := []struct {
		name        string
		httpMethod  string
		url         string
		headers     map[string][]string
		bodyReader  io.Reader
		expectError bool
	}{
		{
			name:       "valid GET request without body",
			httpMethod: "GET",
			url:        "https://example.com/api",
			headers:    map[string][]string{"Content-Type": {"application/json"}},
			bodyReader: nil,
		},
		{
			name:       "valid POST request with body",
			httpMethod: "POST",
			url:        "https://example.com/api",
			headers:    map[string][]string{"Content-Type": {"application/json"}},
			bodyReader: strings.NewReader(`{"key":"value"}`),
		},
		{
			name:       "PUT request with multiple headers",
			httpMethod: "PUT",
			url:        "https://example.com/api/resource/123",
			headers: map[string][]string{
				"Content-Type": {"application/json"},
				"Accept":       {"application/json", "text/plain"},
			},
			bodyReader: strings.NewReader(`{"updated":"true"}`),
		},
		{
			name:       "DELETE request",
			httpMethod: "DELETE",
			url:        "https://example.com/api/resource/123",
			headers:    nil,
			bodyReader: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producer, err := newHttpRequestProducer(tt.httpMethod, tt.url, tt.headers, tt.bodyReader)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, producer)
				assert.Equal(t, tt.httpMethod, producer.httpMethod)
				assert.Equal(t, tt.url, producer.url)
				assert.Equal(t, tt.headers, producer.headers)
			}
		})
	}
}

func TestHttpRequestProducer_GetBody(t *testing.T) {
	tests := []struct {
		name       string
		bodyBytes  []byte
		expectNil  bool
		readResult string
	}{
		{
			name:      "nil body bytes",
			bodyBytes: nil,
			expectNil: true,
		},
		{
			name:      "empty body bytes",
			bodyBytes: []byte{},
			expectNil: true,
		},
		{
			name:       "non-empty body bytes",
			bodyBytes:  []byte("test body"),
			expectNil:  false,
			readResult: "test body",
		},
		{
			name:       "json body bytes",
			bodyBytes:  []byte(`{"key":"value"}`),
			expectNil:  false,
			readResult: `{"key":"value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producer := &httpRequestProducer{bodyBytes: tt.bodyBytes}
			body := producer.getBody()

			if tt.expectNil {
				assert.Nil(t, body)
			} else {
				assert.NotNil(t, body)
				readBytes, err := io.ReadAll(body)
				assert.NoError(t, err)
				assert.Equal(t, tt.readResult, string(readBytes))
			}
		})
	}
}

func TestHttpRequestProducer_Produce(t *testing.T) {
	tests := []struct {
		name                string
		httpMethod          string
		url                 string
		headers             map[string][]string
		bodyBytes           []byte
		authHeader          func(ctx context.Context) (string, error)
		expectError         bool
		expectedAuthHeader  string
		expectTokenAcqError bool
	}{
		{
			name:       "successful request with bearer token",
			httpMethod: "GET",
			url:        "https://example.com/api",
			headers:    map[string][]string{"Content-Type": {"application/json"}},
			bodyBytes:  nil,
			authHeader: func(ctx context.Context) (string, error) {
				return "Bearer test-token", nil
			},
			expectedAuthHeader: "Bearer test-token",
		},
		{
			name:       "successful request with basic auth",
			httpMethod: "POST",
			url:        "https://example.com/api",
			headers:    map[string][]string{"Content-Type": {"application/json"}},
			bodyBytes:  []byte(`{"data":"value"}`),
			authHeader: func(ctx context.Context) (string, error) {
				return "Basic dXNlcjpwYXNz", nil
			},
			expectedAuthHeader: "Basic dXNlcjpwYXNz",
		},
		{
			name:       "auth header supplier returns error",
			httpMethod: "GET",
			url:        "https://example.com/api",
			headers:    nil,
			bodyBytes:  nil,
			authHeader: func(ctx context.Context) (string, error) {
				return "", errors.New("token acquisition failed")
			},
			expectError:         true,
			expectTokenAcqError: true,
		},
		{
			name:       "invalid HTTP method",
			httpMethod: "INVALID\nMETHOD",
			url:        "https://example.com/api",
			headers:    nil,
			bodyBytes:  nil,
			authHeader: func(ctx context.Context) (string, error) {
				return "Bearer token", nil
			},
			expectError: true,
		},
		{
			name:       "multiple custom headers",
			httpMethod: "PUT",
			url:        "https://example.com/api/resource",
			headers: map[string][]string{
				"X-Custom-Header": {"value1", "value2"},
				"Accept":          {"application/json"},
			},
			bodyBytes: []byte(`{"update":"data"}`),
			authHeader: func(ctx context.Context) (string, error) {
				return "Bearer multi-header-token", nil
			},
			expectedAuthHeader: "Bearer multi-header-token",
		},
	}

	for _, tt := range tests {
		producer := &httpRequestProducer{
			httpMethod: tt.httpMethod,
			url:        tt.url,
			headers:    tt.headers,
			bodyBytes:  tt.bodyBytes,
			authHeader: tt.authHeader,
		}

		ctx := context.Background()
		req, err := producer.produce(ctx)

		if tt.expectError {
			assert.Error(t, err)
			if tt.expectTokenAcqError {
				var tae *TokenAcquisitionError
				assert.ErrorAs(t, err, &tae)
			}
			continue
		}
		require.NoError(t, err)
		assert.NotNil(t, req)
		assert.Equal(t, tt.httpMethod, req.Method)
		assert.Equal(t, tt.url, req.URL.String())
		assert.Equal(t, tt.expectedAuthHeader, req.Header.Get("Authorization"))

		// Verify custom headers were added
		for key, values := range tt.headers {
			for _, value := range values {
				assert.Contains(t, req.Header.Values(key), value)
			}
		}

		// Verify body if present
		if len(tt.bodyBytes) > 0 {
			bodyBytes, err := io.ReadAll(req.Body)
			assert.NoError(t, err)
			assert.Equal(t, tt.bodyBytes, bodyBytes)
		}
	}
}

func TestHttpRequestProducer_ProduceReusability(t *testing.T) {
	// Test that producer can produce multiple requests with the same body
	bodyContent := []byte("test body content")
	producer := &httpRequestProducer{
		httpMethod: "POST",
		url:        "https://example.com/api",
		headers:    nil,
		bodyBytes:  bodyContent,
		authHeader: func(ctx context.Context) (string, error) {
			return "Bearer token", nil
		},
	}

	ctx := context.Background()

	// First request
	req1, err1 := producer.produce(ctx)
	require.NoError(t, err1)
	body1, err := io.ReadAll(req1.Body)
	assert.NoError(t, err)
	assert.Equal(t, bodyContent, body1)

	// Second request - body should still be available
	req2, err2 := producer.produce(ctx)
	require.NoError(t, err2)
	body2, err := io.ReadAll(req2.Body)
	assert.NoError(t, err)
	assert.Equal(t, bodyContent, body2)
}
