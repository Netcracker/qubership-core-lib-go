package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRequestClientSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer kube-user-token", r.Header.Get("Authorization"))
		assert.Contains(t, r.URL.Path, "/serviceaccounts/my-sa/token")
		resp := map[string]any{
			"status": map[string]any{
				"token":               "minted-token",
				"expirationTimestamp": time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &TokenRequestClient{
		httpClient: server.Client(),
		serverURL:  server.URL,
		userToken:  "kube-user-token",
	}
	result, err := client.RequestToken(t.Context(), "my-ns", "my-sa", "netcracker")
	require.NoError(t, err)
	assert.Equal(t, "minted-token", result.Token)
}

func TestTokenRequestClientUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	client := &TokenRequestClient{
		httpClient: server.Client(),
		serverURL:  server.URL,
		userToken:  "kube-user-token",
	}
	_, err := client.RequestToken(t.Context(), "my-ns", "my-sa", "netcracker")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestTokenRequestClientCanceledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client := &TokenRequestClient{
		httpClient: server.Client(),
		serverURL:  server.URL,
		userToken:  "kube-user-token",
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := client.RequestToken(ctx, "my-ns", "my-sa", "netcracker")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}
