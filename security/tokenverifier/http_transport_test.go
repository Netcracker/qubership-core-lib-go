package tokenverifier

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/cloudprovidergetter"
	"github.com/stretchr/testify/assert"
)

type mockRoundTripper struct {
	called        bool
	token         string
	cloudProvider cloudprovidergetter.CloudProvider
}

func (m *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	m.called = true
	if m.cloudProvider != cloudprovidergetter.CloudProviderGKE {
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			return nil, fmt.Errorf("expected token %s, got %s", m.token, r.Header.Get("Authorization"))
		}
	} else {
		if r.Header.Get("Authorization") != "" {
			return nil, fmt.Errorf("expected no token, got %s", r.Header.Get("Authorization"))
		}
	}

	return &http.Response{}, nil
}

func TestNewHttpClient(t *testing.T) {
	testNewHttpClient(t, cloudprovidergetter.CloudProviderGKE)
	testNewHttpClient(t, cloudprovidergetter.CloudProviderAKS)
	testNewHttpClient(t, cloudprovidergetter.CloudProviderEKS)
	testNewHttpClient(t, cloudprovidergetter.CloudProviderOnPrem)
}

func TestHttpTransport_Failure(t *testing.T) {
	transport := newSecureTransport(func() (string, error) {
		return "", errors.New("test error")
	}, cloudprovidergetter.CloudProviderAKS)

	client := http.Client{
		Transport: transport,
	}
	_, err := client.Get("/test")
	assert.ErrorContains(t, err, "Get \"/test\": failed to get k8s sa token: test error")
}

func testNewHttpClient(t *testing.T, cloudProvider cloudprovidergetter.CloudProvider) {
	validToken := "valid_token"
	transport := newSecureTransport(func() (string, error) {
		return validToken, nil
	}, cloudProvider)
	mockTransport := &mockRoundTripper{
		token:         validToken,
		cloudProvider: cloudProvider,
	}
	transport.base = mockTransport

	client := http.Client{
		Transport: transport,
	}
	_, err := client.Get("/test")
	assert.NoError(t, err, "expected nil err, got err: %v", err)

	assert.True(t, mockTransport.called, "expected mockTransport to be called be the client")
}
