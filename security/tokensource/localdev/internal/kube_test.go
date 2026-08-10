package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsKubernetesIssuer(t *testing.T) {
	assert.True(t, IsKubernetesIssuer("https://kubernetes.default.svc"))
	assert.True(t, IsKubernetesIssuer("https://kubernetes.default.svc.cluster.local"))
	assert.False(t, IsKubernetesIssuer("https://accounts.google.com"))
}

func TestIsPublicOidcEndpointEdgeCases(t *testing.T) {
	assert.False(t, IsPublicOidcEndpoint(""))
	assert.False(t, IsPublicOidcEndpoint("not-a-url"))
	assert.True(t, IsPublicOidcEndpoint("https://api.example/openid/v1/jwks/extra"))
}

func TestKubernetesOIDCHelpers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := writeTestKubeconfig(t, server.URL)
	t.Setenv("KUBECONFIG", path)
	ResetCache()
	defer ResetCache()

	apiURL, err := APIServerURL()
	require.NoError(t, err)
	assert.Equal(t, server.URL, apiURL)

	userToken, err := UserToken()
	require.NoError(t, err)
	assert.Equal(t, "kube-user-token", userToken)

	jwksURL, err := JwksURL()
	require.NoError(t, err)
	assert.Equal(t, server.URL+jwksPath, jwksURL)

	client, err := HTTPClient()
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

	kubeconfigPath := writeTestKubeconfig(t, server.URL)
	t.Setenv("KUBECONFIG", kubeconfigPath)
	ResetCache()
	defer ResetCache()

	issuer, err := ResolveIssuerClaimFromDiscovery()
	require.NoError(t, err)
	assert.Equal(t, "https://cluster.example", issuer)
}

func TestResolveIssuerClaimFromDiscoveryFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	kubeconfigPath := writeTestKubeconfig(t, server.URL)
	t.Setenv("KUBECONFIG", kubeconfigPath)
	ResetCache()
	defer ResetCache()

	issuer, err := ResolveIssuerClaimFromDiscovery()
	require.NoError(t, err)
	assert.Equal(t, defaultKubernetesIssuer, issuer)
}
