package rest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuthHeaderSupplier creates a mock auth header supplier for testing
func mockAuthHeaderSupplier(token string, err error) AuthHeaderSupplier {
	return func(ctx context.Context) (string, error) {
		return token, err
	}
}

func TestGetKubernetesAuthHeaderSupplier(t *testing.T) {
	// This test verifies the structure of the supplier function
	// Actual token acquisition would require tokensource setup
	supplier := getKubernetesAuthHeaderSupplier("test-audience")
	assert.NotNil(t, supplier)
}

func TestGetBasicAuthHeaderSupplier(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		expected string
	}{
		{
			name:     "valid credentials",
			username: "user",
			password: "pass",
			expected: "Basic dXNlcjpwYXNz",
		},
		{
			name:     "empty password",
			username: "admin",
			password: "",
			expected: "Basic YWRtaW46",
		},
		{
			name:     "empty username",
			username: "",
			password: "secret",
			expected: "Basic OnNlY3JldA==",
		},
		{
			name:     "special characters",
			username: "user@domain.com",
			password: "p@ss:w0rd!",
			expected: "Basic dXNlckBkb21haW4uY29tOnBAc3M6dzByZCE=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supplier := getBasicAuthHeaderSupplier(tt.username, tt.password)
			result, err := supplier(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestM2MRestClient_DoRequest_FirstCallSuccess(t *testing.T) {
	// Mock HTTP server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer new-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer new-token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback-token", nil),
	}

	ctx := context.Background()
	resp, err := client.DoRequest(ctx, "GET", server.URL+"/api/v1/resource", nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"status":"success"}`, string(body))
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_FirstCallUnauthorized_FallbackSuccess(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer new-token" {
			// First call with new auth fails
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
		} else if authHeader == "Bearer fallback-token" {
			// Fallback succeeds
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"success"}`))
		}
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer new-token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback-token", nil),
	}

	ctx := context.Background()
	resp, err := client.DoRequest(ctx, "GET", server.URL+"/api/v1/resource", nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 2, callCount, "should make two calls: new auth (401) then fallback (200)")

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"status":"success"}`, string(body))
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_TokenAcquisitionError_Fallback(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		assert.Equal(t, "Bearer fallback-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("", errors.New("token acquisition failed")),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback-token", nil),
	}

	ctx := context.Background()
	resp, err := client.DoRequest(ctx, "GET", server.URL+"/api/v1/resource", nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, callCount, "should only call once with fallback")

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, `{"status":"success"}`, string(body))
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_CachedUrl_UsesFallback(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer fallback-token", authHeader, "should use fallback for cached URLs")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer new-token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback-token", nil),
	}

	ctx := context.Background()
	url := server.URL + "/api/v1/resource"

	// Pre-populate cache
	cacheKey, err := calculateCacheKey(url)
	require.NoError(t, err)
	client.urlCache.Add(cacheKey, empty{})

	// Make request - should use fallback directly
	resp, err := client.DoRequest(ctx, "GET", url, nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 1, callCount, "should only call once with fallback")
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_WithBody(t *testing.T) {
	requestBody := `{"name":"test","value":123}`
	receivedBody := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		receivedBody = string(body)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"123"}`))
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	ctx := context.Background()
	resp, err := client.DoRequest(ctx, "POST", server.URL+"/api/resource",
		map[string][]string{"Content-Type": {"application/json"}},
		strings.NewReader(requestBody))

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, requestBody, receivedBody)
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_WithHeaders(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	ctx := context.Background()
	headers := map[string][]string{
		"Content-Type":    {"application/json"},
		"Accept":          {"application/json"},
		"X-Custom-Header": {"value1", "value2"},
	}

	resp, err := client.DoRequest(ctx, "GET", server.URL+"/api/resource", headers, nil)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
	assert.Equal(t, "application/json", receivedHeaders.Get("Accept"))
	assert.Contains(t, receivedHeaders.Values("X-Custom-Header"), "value1")
	assert.Contains(t, receivedHeaders.Values("X-Custom-Header"), "value2")
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_InvalidUrl(t *testing.T) {
	client := &m2MRestClient{
		client:                     http.DefaultClient,
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	ctx := context.Background()
	_, err := client.DoRequest(ctx, "GET", "://invalid-url", nil, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "url can not be parsed")
}

func TestM2MRestClient_DoRequest_BothAuthMethodsFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("", errors.New("new auth failed")),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("", errors.New("fallback auth failed")),
	}

	ctx := context.Background()
	_, err := client.DoRequest(ctx, "GET", server.URL+"/api/resource", nil, nil)

	assert.Error(t, err)
	var tae *TokenAcquisitionError
	assert.ErrorAs(t, err, &tae)
}

func TestM2MRestClient_DoRequest_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	ctx := context.Background()
	resp, err := client.DoRequest(ctx, "GET", server.URL+"/api/resource", nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_ConcurrentRequests(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	ctx := context.Background()
	numRequests := 10
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			resp, err := client.DoRequest(ctx, "GET", server.URL+"/api/v1/resource", nil, nil)
			assert.NoError(t, err)
			if resp != nil {
				resp.Body.Close()
			}
		}(i)
	}

	wg.Wait()
	assert.Equal(t, numRequests, callCount)
}

func TestM2MRestClient_DoRequest_DifferentHttpMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			receivedMethod := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client := &m2MRestClient{
				client:                     server.Client(),
				urlCache:                   getUrlCache(),
				newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer token", nil),
				fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
			}

			ctx := context.Background()
			resp, err := client.DoRequest(ctx, method, server.URL+"/api/resource", nil, nil)

			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, method, receivedMethod)
			resp.Body.Close()
		})
	}
}

func TestM2MRestClient_DoRequest_FallbackCachesUrl(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer new-token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback-token", nil),
	}

	ctx := context.Background()
	url := server.URL + "/api/v1/resource"

	// First request: new auth fails (401), fallback succeeds
	resp1, err1 := client.DoRequest(ctx, "GET", url, nil, nil)
	require.NoError(t, err1)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	resp1.Body.Close()
	assert.Equal(t, 2, callCount, "first request should try both auth methods")

	// Second request: should use fallback directly (cached)
	callCount = 0
	resp2, err2 := client.DoRequest(ctx, "GET", url, nil, nil)
	require.NoError(t, err2)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	resp2.Body.Close()
	assert.Equal(t, 1, callCount, "second request should only use fallback")
}

func TestM2MRestClient_DoRequest_BodyReaderError(t *testing.T) {
	client := &m2MRestClient{
		client:                     http.DefaultClient,
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	// Create an error reader
	errorReader := &errorReader{err: errors.New("read error")}

	ctx := context.Background()
	_, err := client.DoRequest(ctx, "POST", "https://example.com/api", nil, errorReader)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse request body")
}

// errorReader is a helper that always returns an error when reading
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func TestNewM2MRestClient(t *testing.T) {
	newAuth := mockAuthHeaderSupplier("Bearer new", nil)
	fallbackAuth := mockAuthHeaderSupplier("Bearer fallback", nil)

	client := newM2MRestClient(newAuth, fallbackAuth)

	assert.NotNil(t, client)
	m2mClient, ok := client.(*m2MRestClient)
	require.True(t, ok)
	assert.NotNil(t, m2mClient.client)
	assert.NotNil(t, m2mClient.urlCache)
	assert.NotNil(t, m2mClient.newAuthHeaderSupplier)
	assert.NotNil(t, m2mClient.fallbackAuthHeaderSupplier)
}

func TestM2MRestClient_DoRequest_InternalGatewayUrlCaching(t *testing.T) {
	// Test that different resources under the same service share cache
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")
		if authHeader == "Bearer new-token" {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer new-token", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback-token", nil),
	}

	ctx := context.Background()

	// Simulate internal-gateway URLs by adding the path pattern
	// The cache key calculation will extract the service name
	url1 := server.URL + "/api/v1/service1/resource"
	url2 := server.URL + "/api/v1/service1/other-resource"

	// First request - should try new auth (401) then fallback
	resp1, err1 := client.DoRequest(ctx, "GET", url1, nil, nil)
	require.NoError(t, err1)
	resp1.Body.Close()
	assert.Equal(t, 2, callCount, "first request should try both auth methods")

	// Reset counter
	callCount = 0

	// Second request to same host - should use cached fallback
	resp2, err2 := client.DoRequest(ctx, "GET", url2, nil, nil)
	require.NoError(t, err2)
	resp2.Body.Close()
	assert.Equal(t, 1, callCount, "second request should use cached fallback")
}

func TestM2MRestClient_DoRequestFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer new", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	ctx := context.Background()
	url := server.URL + "/api/resource"
	cacheKey, err := calculateCacheKey(url)
	require.NoError(t, err)

	producer, err := newHttpRequestProducer("GET", url, nil, nil)
	require.NoError(t, err)

	reason := &fallbackReason{
		desc: kubernetesTokenAcquisitionError,
		url:  url,
		err:  errors.New("test error"),
	}

	resp, err := client.doRequestFallback(ctx, cacheKey, producer, reason)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify URL was cached
	_, exists := client.urlCache.Get(cacheKey)
	assert.True(t, exists)
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_MultipleBodyReads(t *testing.T) {
	requestBody := bytes.NewReader([]byte(`{"data":"value"}`))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client := &m2MRestClient{
		client:                     server.Client(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      mockAuthHeaderSupplier("Bearer new", nil),
		fallbackAuthHeaderSupplier: mockAuthHeaderSupplier("Bearer fallback", nil),
	}

	ctx := context.Background()
	// Should handle multiple requests even when body reader is provided
	resp, err := client.DoRequest(ctx, "POST", server.URL+"/api", nil, requestBody)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	resp.Body.Close()
}
