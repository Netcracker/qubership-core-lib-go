package localdev

import (
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
		resp := map[string]interface{}{
			"status": map[string]interface{}{
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
	result, err := client.RequestToken("my-ns", "my-sa", "netcracker")
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
	_, err := client.RequestToken("my-ns", "my-sa", "netcracker")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}
