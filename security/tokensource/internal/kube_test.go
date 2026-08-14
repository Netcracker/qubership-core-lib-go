package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPublicOidcEndpointEdgeCases(t *testing.T) {
	cfg := NewKubeLocalDevConfig()
	assert.False(t, cfg.IsPublicOidcEndpoint(""))
	assert.False(t, cfg.IsPublicOidcEndpoint("not-a-url"))
	assert.True(t, cfg.IsPublicOidcEndpoint("https://api.example/openid/v1/jwks/extra"))
}

func TestKubernetesOIDCHelpers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := writeTestKubeconfig(t, server.URL)
	t.Setenv("KUBECONFIG", path)

	cfg := NewKubeLocalDevConfig()
	apiURL, err := cfg.APIServerURL()
	require.NoError(t, err)
	assert.Equal(t, server.URL, apiURL)

	userToken, err := cfg.UserToken()
	require.NoError(t, err)
	assert.Equal(t, "kube-user-token", userToken)

	jwksURL, err := cfg.JwksURL()
	require.NoError(t, err)
	assert.Equal(t, server.URL+jwksPath, jwksURL)

	client, err := cfg.HTTPClient()
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestResolveIssuerClaimFromDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == oidc.ProviderSubPath {
			_, _ = w.Write([]byte(`{"issuer":"https://cluster.example"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	t.Setenv("KUBECONFIG", writeTestKubeconfig(t, server.URL))

	cfg := NewKubeLocalDevConfig()
	issuer, err := cfg.ResolveIssuerClaimFromDiscovery()
	require.NoError(t, err)
	assert.Equal(t, "https://cluster.example", issuer)
}

func TestResolveIssuerClaimFromDiscoveryFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv("KUBECONFIG", writeTestKubeconfig(t, server.URL))

	cfg := NewKubeLocalDevConfig()
	issuer, err := cfg.ResolveIssuerClaimFromDiscovery()
	require.NoError(t, err)
	assert.Equal(t, defaultKubernetesIssuer, issuer)
}

func TestFetchJwks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jwksPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Accept") != applicationJWKSetJSON {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"test"}]}`))
	}))
	defer server.Close()

	t.Setenv("KUBECONFIG", writeTestKubeconfig(t, server.URL))

	cfg := NewKubeLocalDevConfig()
	jwks, err := cfg.FetchJwks()
	require.NoError(t, err)
	assert.Contains(t, jwks, `"keys"`)
}
