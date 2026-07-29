package localdev

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.Equal(t, server.URL+JwksPath, jwksURL)

	client, err := HTTPClient()
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestIsPublicOidcEndpointEdgeCases(t *testing.T) {
	assert.False(t, IsPublicOidcEndpoint(""))
	assert.False(t, IsPublicOidcEndpoint("not-a-url"))
	assert.True(t, IsPublicOidcEndpoint("https://api.example/openid/v1/jwks/extra"))
}

func TestResolveKubeConfigPathDefaultHome(t *testing.T) {
	t.Setenv("KUBECONFIG", "")
	path, err := resolveKubeConfigPath()
	require.NoError(t, err)
	assert.Contains(t, path, ".kube")
	assert.Contains(t, path, "config")
}
