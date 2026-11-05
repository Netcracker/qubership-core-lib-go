package utils

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The clone keeps what the standard transport configures: expiry and count of idle connections,
// handshake and continue timeouts, HTTP/2 negotiation, proxy resolution and dialling.
func TestGetTransport_KeepsTheStandardDefaults(t *testing.T) {
	standard := http.DefaultTransport.(*http.Transport)

	transport := GetTransport()

	require.NotNil(t, transport)
	assert.Equal(t, standard.IdleConnTimeout, transport.IdleConnTimeout)
	assert.Equal(t, standard.MaxIdleConns, transport.MaxIdleConns)
	assert.Equal(t, standard.TLSHandshakeTimeout, transport.TLSHandshakeTimeout)
	assert.Equal(t, standard.ExpectContinueTimeout, transport.ExpectContinueTimeout)
	assert.Equal(t, standard.ForceAttemptHTTP2, transport.ForceAttemptHTTP2)
	assert.NotNil(t, transport.Proxy)
	assert.NotNil(t, transport.DialContext)
}

func TestGetTransport_CarriesTheTlsConfig(t *testing.T) {
	transport := GetTransport()

	require.NotNil(t, transport.TLSClientConfig)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
}

// The standard transport is shared, so it does not receive the TLS configuration of this package.
// Clone fills in its HTTP/2 protocol names, as the first request through it would.
func TestGetTransport_LeavesTheStandardTransportAlone(t *testing.T) {
	standard := http.DefaultTransport.(*http.Transport)

	transport := GetTransport()

	assert.NotSame(t, transport.TLSClientConfig, standard.TLSClientConfig)
	if standard.TLSClientConfig != nil {
		assert.Nil(t, standard.TLSClientConfig.RootCAs)
	}
}

// Each call returns a separate transport.
func TestGetTransport_IsNotShared(t *testing.T) {
	first := GetTransport()
	second := GetTransport()

	assert.NotSame(t, first, second)
}

func TestGetClient_UsesTheTransport(t *testing.T) {
	client := GetClient()

	require.NotNil(t, client)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "the client must carry the transport this package builds")
	assert.NotNil(t, transport.TLSClientConfig)
	assert.Equal(t, http.DefaultTransport.(*http.Transport).IdleConnTimeout, transport.IdleConnTimeout)
}
