package localdev

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsJwtExpired(t *testing.T) {
	assert.True(t, isJwtExpired("not-a-jwt"))
	assert.True(t, isJwtExpired("a.b"))

	future := buildTestJWT(time.Now().Add(2 * time.Hour))
	assert.False(t, isJwtExpired(future))

	past := buildTestJWT(time.Now().Add(-2 * time.Hour))
	assert.True(t, isJwtExpired(past))
}

func TestDiscoverTokenEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, oidc.ProviderSubPath, r.URL.Path)
		_, _ = w.Write([]byte(`{"token_endpoint":"https://idp.example/token"}`))
	}))
	defer server.Close()

	client := server.Client()
	endpoint, err := discoverTokenEndpoint(client, server.URL)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example/token", endpoint)
}

func TestDiscoverTokenEndpointErrors(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	_, err := discoverTokenEndpoint(client, "http://127.0.0.1:1")
	assert.Error(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err = discoverTokenEndpoint(server.Client(), server.URL)
	assert.Error(t, err)

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server2.Close()
	_, err = discoverTokenEndpoint(server2.Client(), server2.URL)
	assert.Error(t, err)
}

func TestRefreshIdToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = w.Write([]byte(`{"id_token":"refreshed-id-token"}`))
	}))
	defer server.Close()

	token, err := refreshIdToken(server.Client(), server.URL, "client-id", "secret", "refresh")
	require.NoError(t, err)
	assert.Equal(t, "refreshed-id-token", token)
}

func TestRefreshIdTokenAccessTokenFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"refreshed-access"}`))
	}))
	defer server.Close()

	token, err := refreshIdToken(server.Client(), server.URL, "client-id", "", "refresh")
	require.NoError(t, err)
	assert.Equal(t, "refreshed-access", token)
}

func TestRefreshIdTokenErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad grant"))
	}))
	defer server.Close()

	_, err := refreshIdToken(server.Client(), server.URL, "client", "", "refresh")
	assert.Error(t, err)

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server2.Close()
	_, err = refreshIdToken(server2.Client(), server2.URL, "client", "", "refresh")
	assert.Error(t, err)
}

func TestResolveOidcAuthProviderTokenUsesCachedNonExpired(t *testing.T) {
	t.Setenv(ProfileEnv, "")
	token := buildTestJWT(time.Now().Add(2 * time.Hour))
	got, err := resolveOidcAuthProviderToken(map[string]any{
		kubeConfigIDToken: token,
	})
	require.NoError(t, err)
	assert.Equal(t, token, got)
}

func TestResolveOidcAuthProviderTokenRefresh(t *testing.T) {
	t.Setenv(ProfileEnv, "dev")
	t.Setenv(InsecureIdpTlsEnv, "true")

	var tokenCalls int
	var tokenURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case oidc.ProviderSubPath:
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint": tokenURL,
			})
		case "/token":
			tokenCalls++
			_, _ = w.Write([]byte(`{"id_token":"new-id-token"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	tokenURL = server.URL + "/token"

	expired := buildTestJWT(time.Now().Add(-2 * time.Hour))
	got, err := resolveOidcAuthProviderToken(map[string]any{
		kubeConfigIDToken:      expired,
		kubeConfigIDPIssuerURL: server.URL,
		kubeConfigRefreshToken: "refresh-value",
		kubeConfigClientID:     "client-id",
		kubeConfigClientSecret: "secret",
	})
	require.NoError(t, err)
	assert.Equal(t, "new-id-token", got)
	assert.Equal(t, 1, tokenCalls)
}

func TestResolveOidcAuthProviderTokenFallbackToCachedOnRefreshFailure(t *testing.T) {
	t.Setenv(ProfileEnv, "")
	expired := buildTestJWT(time.Now().Add(-2 * time.Hour))
	got, err := resolveOidcAuthProviderToken(map[string]any{
		kubeConfigIDToken:      expired,
		kubeConfigIDPIssuerURL: "http://127.0.0.1:1",
		kubeConfigRefreshToken: "refresh",
		kubeConfigClientID:     "client",
	})
	require.NoError(t, err)
	assert.Equal(t, expired, got)
}

func TestResolveOidcAuthProviderTokenMissingRefreshFields(t *testing.T) {
	expired := buildTestJWT(time.Now().Add(-2 * time.Hour))
	got, err := resolveOidcAuthProviderToken(map[string]any{
		kubeConfigIDToken: expired,
	})
	require.NoError(t, err)
	assert.Equal(t, expired, got)

	got, err = resolveOidcAuthProviderToken(map[string]any{})
	require.NoError(t, err)
	assert.Equal(t, "", got)
}

func TestIdpHTTPClientWhenLocalDevEnabled(t *testing.T) {
	t.Setenv(ProfileEnv, "dev")
	t.Setenv(InsecureIdpTlsEnv, "true")
	client := idpHTTPClient()
	require.NotNil(t, client)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}
