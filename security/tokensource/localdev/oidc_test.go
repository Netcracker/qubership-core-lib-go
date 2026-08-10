package localdev

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPublicOidcEndpoint(t *testing.T) {
	assert.True(t, IsPublicOidcEndpoint("https://api.example/openid/v1/jwks"))
	assert.True(t, IsPublicOidcEndpoint("https://api.example/.well-known/openid-configuration"))
	assert.False(t, IsPublicOidcEndpoint("https://api.example/api/v1/namespaces/default"))
}
