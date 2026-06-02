package rest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokenverifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	configloader.Init(&configloader.PropertySource{
		Provider: configloader.AsPropertyProvider(confmap.Provider(map[string]interface{}{
			"security.m2m.kubernetes.enabled": true,
		}, ".")),
	})
}

// mockAuthHeaderFunc creates a mock auth header func for testing
func mockAuthHeaderFunc(token string, err error) authHeaderFunc {
	return func(ctx context.Context) (string, error) {
		return token, err
	}
}

func TestKubernetesAuthHeaderFunc(t *testing.T) {
	// This test verifies the structure of the supplier function
	// Actual token acquisition would require tokensource setup
	supplier := k8sAuthHeaderFunc("test-audience")
	assert.NotNil(t, supplier)
}

func TestM2MRestClient_DoRequest_FirstCallSuccess(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now().Unix()
	exp := time.Now().Add(time.Hour).Unix()
	claims := jwt.MapClaims{
		"aud": []string{"test"},
		"exp": exp,
		"iat": now,
		"iss": "https://kubernetes.default.svc.cluster.local",
		"kubernetes.io": map[string]interface{}{
			"namespace": "test",
			"serviceaccount": map[string]interface{}{
				"name": "test",
			},
		},
		"nbf": now,
		"sub": "system:serviceaccount:test:test",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	jwk, err := jwkset.NewJWKFromKey(privateKey.Public(), jwkset.JWKOptions{})
	require.NoError(t, err)
	storage := jwkset.NewMemoryStorage()
	require.NoError(t, storage.KeyWrite(t.Context(), jwk))
	keyFunc, err := keyfunc.New(keyfunc.Options{
		Storage: storage,
	})
	require.NoError(t, err)

	parser := jwt.NewParser(jwt.WithAudience("test"), jwt.WithExpirationRequired(), jwt.WithIssuer("https://kubernetes.default.svc.cluster.local"))
	verifier, err := tokenverifier.NewVerifier(parser, keyFunc)
	require.NoError(t, err)

	// Mock HTTP server that returns 200 OK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		_, err := verifier.Verify(t.Context(), token)
		assert.NoError(t, err)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"status":"failure"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer "+tokenString, nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback-token", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer new-token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback-token", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("", errors.New("token acquisition failed")),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback-token", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer new-token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback-token", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
	}

	ctx := context.Background()
	url := server.URL + "/api/v1/resource"

	// Pre-populate cache
	cacheKey, err := calculateCacheKey("internal-gateway-service", url)
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer token", nil),
		k8sM2mEnabled:           true,
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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
	client := &M2MRestClient{
		client:                  http.DefaultClient,
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("", errors.New("new auth failed")),
		fallbackAuthHeader:      mockAuthHeaderFunc("", errors.New("fallback auth failed")),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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

			client := &M2MRestClient{
				client:                  server.Client(),
				urlCache:                newUrlCache(),
				k8sAuthHeader:           mockAuthHeaderFunc("Bearer token", nil),
				fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
				internalGatewayHostname: "internal-gateway-service",
				k8sM2mEnabled:           true,
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer new-token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback-token", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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
	client := &M2MRestClient{
		client:                  http.DefaultClient,
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
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
	newAuth := mockAuthHeaderFunc("Bearer new", nil)
	fallbackAuth := mockAuthHeaderFunc("Bearer fallback", nil)

	m2mClient := newM2MRestClient(newAuth, fallbackAuth, "")

	assert.NotNil(t, m2mClient)
	assert.NotNil(t, m2mClient.client)
	assert.NotNil(t, m2mClient.urlCache)
	assert.NotNil(t, m2mClient.k8sAuthHeader)
	assert.NotNil(t, m2mClient.fallbackAuthHeader)
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer new-token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback-token", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
	}

	ctx := context.Background()

	// Simulate internal-gateway-service URLs by adding the path pattern
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer new", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
	}

	ctx := context.Background()
	url := server.URL + "/api/resource"
	cacheKey, err := calculateCacheKey("internal-gateway-service", url)
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

	client := &M2MRestClient{
		client:                  server.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer new", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback", nil),
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
	}

	ctx := context.Background()
	// Should handle multiple requests even when body reader is provided
	resp, err := client.DoRequest(ctx, "POST", server.URL+"/api", nil, requestBody)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	resp.Body.Close()
}

func TestM2MRestClient_DoRequest_FallbackRebasesUrl(t *testing.T) {
	agentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer agentServer.Close()

	originalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer originalServer.Close()

	client := &M2MRestClient{
		client:                  agentServer.Client(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           mockAuthHeaderFunc("Bearer new-token", nil),
		fallbackAuthHeader:      mockAuthHeaderFunc("Bearer fallback-token", nil),
		fallBackBaseUrl:         agentServer.URL,
		internalGatewayHostname: "internal-gateway-service",
		k8sM2mEnabled:           true,
	}

	ctx := context.Background()

	t.Run("first call 401 rebases to fallback agent", func(t *testing.T) {
		resp, err := client.DoRequest(ctx, "GET", originalServer.URL+"/api/v1/resource", nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("cached url also rebases to fallback agent", func(t *testing.T) {
		originalUrl := "http://original-service:9090/api/v1/resource"
		cacheKey, err := calculateCacheKey("internal-gateway-service", originalUrl)
		require.NoError(t, err)
		client.urlCache.Add(cacheKey, empty{})

		resp, err := client.DoRequest(ctx, "GET", originalUrl, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})
}
