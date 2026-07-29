package localdev

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPublicOidcEndpoint(t *testing.T) {
	assert.True(t, IsPublicOidcEndpoint("https://api.example/openid/v1/jwks"))
	assert.True(t, IsPublicOidcEndpoint("https://api.example/.well-known/openid-configuration"))
	assert.False(t, IsPublicOidcEndpoint("https://api.example/api/v1/namespaces/default"))
}

func TestIsKubernetesIssuer(t *testing.T) {
	assert.True(t, IsKubernetesIssuer("https://kubernetes.default.svc"))
	assert.True(t, IsKubernetesIssuer("https://kubernetes.default.svc.cluster.local"))
	assert.False(t, IsKubernetesIssuer("https://accounts.google.com"))
}

func TestResolveIssuerClaimFromDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wellKnownOpenIDConfigPath {
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
	assert.Equal(t, DefaultKubernetesIssuer, issuer)
}
