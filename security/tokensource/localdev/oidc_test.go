package localdev

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKubernetesOidcPublicAPI(t *testing.T) {
	oidc := NewKubernetesOidc()
	assert.True(t, oidc.IsPublicOidcEndpoint("https://api.example/openid/v1/jwks"))
	assert.True(t, oidc.IsPublicOidcEndpoint("https://api.example/.well-known/openid-configuration"))
	assert.False(t, oidc.IsPublicOidcEndpoint("https://api.example/api/v1/namespaces/default"))
}

func TestNewKubernetesOidcDoesNotPanicWhenLocalDevDisabled(t *testing.T) {
	assert.False(t, IsEnabled())
	oidc := NewKubernetesOidc()
	require.NotNil(t, oidc)
}

func TestNamespaceEnvIsExported(t *testing.T) {
	assert.Equal(t, "SECURITY_LOCALDEV", EnabledEnv)
	assert.Equal(t, "CLOUD_NAMESPACE", NamespaceEnv)
}

func TestIsEnabled(t *testing.T) {
	t.Setenv(EnabledEnv, "")
	assert.False(t, IsEnabled())

	t.Setenv(EnabledEnv, "false")
	assert.False(t, IsEnabled())

	t.Setenv(EnabledEnv, "true")
	assert.True(t, IsEnabled())
}
