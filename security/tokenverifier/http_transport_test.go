package tokenverifier

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type mockTokenSource struct {
	token string
}

func (mt mockTokenSource) Token() (string, error) {
	return mt.token, nil
}

type mockRoundTripper struct {
	called bool
	token  string
}

func (m *mockRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	m.called = true
	if r.Header.Get("Authorization") != "Bearer "+m.token {
		return nil, fmt.Errorf("expected token %s, get %s", m.token, r.Header.Get("Authorization"))
	}
	return &http.Response{}, nil
}

func TestNewHttpClient(t *testing.T) {
	validToken := "valid_token"
	mockTs := mockTokenSource{token: validToken}
	transport := newSecureTransport(func() (string, error) {
		return mockTs.Token()
	})
	mockTransport := &mockRoundTripper{
		token: validToken,
	}
	transport.base = mockTransport

	client := http.Client{
		Transport: transport,
	}
	_, err := client.Get("/test")
	require.NoError(t, err, "expected nil err, got err: %v", err)

	require.True(t, mockTransport.called, "expected mockTransport to be called be the client")
}
