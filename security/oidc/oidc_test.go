package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetProviderUrl(t *testing.T) {
	url, err := GetProviderUrl("")
	assert.NoError(t, err)
	assert.Equal(t, "/.well-known/openid-configuration", url)

	url, err = GetProviderUrl("some 	text")
	assert.ErrorContains(t, err, "issuer url is invalid: parse \"some \\ttext\": net/url: invalid control character in URL")

	url, err = GetProviderUrl("http://localhost:8080")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/.well-known/openid-configuration", url)

	url, err = GetProviderUrl("http://localhost:8080/")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/.well-known/openid-configuration", url)

	//Azure issuers
	url, err = GetProviderUrl("http://localhost:8080/any_uid/any_uid/")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/any_uid/any_uid/.well-known/openid-configuration", url)

	//AWS issuers(symbol '/' is absent in the end)
	url, err = GetProviderUrl("http://localhost:8080/any_uid/any_uid")
	assert.NoError(t, err)
	assert.Equal(t, "http://localhost:8080/any_uid/any_uid/.well-known/openid-configuration", url)
}
