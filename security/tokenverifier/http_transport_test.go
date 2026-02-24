package tokenverifier

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/cloudprovidersource"
	"github.com/stretchr/testify/assert"
)

type mockRoundTripper struct {
	called        bool
	token         string
	cloudProvider cloudprovidersource.CloudProvider
}

func (m *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	m.called = true
	if m.cloudProvider != cloudprovidersource.CloudProviderGKE {
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
	testNewHttpClient(t, cloudprovidersource.CloudProviderGKE)
	testNewHttpClient(t, cloudprovidersource.CloudProviderAKS)
	testNewHttpClient(t, cloudprovidersource.CloudProviderEKS)
	testNewHttpClient(t, cloudprovidersource.CloudProviderOnPrem)
}

func TestHttpTransport_Failure(t *testing.T) {
	transport := newSecureTransport(func() (string, error) {
		return "", errors.New("test error")
	}, cloudprovidersource.CloudProviderAKS)

	client := http.Client{
		Transport: transport,
	}
	_, err := client.Get("/test")
	assert.ErrorContains(t, err, "Get \"/test\": failed to get k8s sa token: test error")
}

func testNewHttpClient(t *testing.T, cloudProvider cloudprovidersource.CloudProvider) {
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
