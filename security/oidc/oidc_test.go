package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetProviderUrl(t *testing.T) {
	assert.Equal(t, "/.well-known/openid-configuration", GetProviderUrl(""))
	assert.Equal(t, "http://localhost:8080/.well-known/openid-configuration", GetProviderUrl("http://localhost:8080"))
	assert.Equal(t, "http://localhost:8080/.well-known/openid-configuration", GetProviderUrl("http://localhost:8080/"))
}
