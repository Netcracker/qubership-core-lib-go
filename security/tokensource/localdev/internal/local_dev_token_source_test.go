package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalDevTokenSourceMintsAndCaches(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(NamespaceEnv, "my-ns")
	configloader.Init(configloader.EnvPropertySource())

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := map[string]any{
			"status": map[string]any{
				"token":               "minted-token",
				"expirationTimestamp": time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	source := &LocalDevTokenSource{
		cache: make(map[string]cachedAudienceToken),
		creds: &KubeConfigCredentials{
			ServerURL: server.URL,
			UserToken: "kube-user",
		},
		client: NewTokenRequestClient(&KubeConfigCredentials{
			ServerURL: server.URL,
			UserToken: "kube-user",
		}),
	}

	token, err := source.GetToken("netcracker")
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)

	token, err = source.GetToken("netcracker")
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)
	assert.Equal(t, 1, calls)
}

func TestLocalDevTokenSourceReturnsKubeUserTokenForSA(t *testing.T) {
	source := &LocalDevTokenSource{
		creds: &KubeConfigCredentials{
			ServerURL: "https://api.example",
			UserToken: "kube-user",
		},
	}
	token, err := source.GetServiceAccountToken()
	require.NoError(t, err)
	assert.Equal(t, "kube-user", token)
}

func TestLocalDevTokenSourceLoadsFromKubeconfig(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(NamespaceEnv, "my-ns")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":{"token":"minted","expirationTimestamp":"` +
			time.Now().Add(2*time.Hour).Format(time.RFC3339) + `"}}`))
	}))
	defer server.Close()

	path := writeTestKubeconfig(t, server.URL)
	t.Setenv("KUBECONFIG", path)
	ResetCache()
	defer ResetCache()

	source := &LocalDevTokenSource{
		cache: make(map[string]cachedAudienceToken),
	}

	token, err := source.GetServiceAccountToken()
	require.NoError(t, err)
	assert.Equal(t, "kube-user-token", token)

	audienceToken, err := source.GetToken("netcracker")
	require.NoError(t, err)
	assert.Equal(t, "minted", audienceToken)
}

func TestAudienceTokenRejectsEmptyAudience(t *testing.T) {
	_, err := AudienceToken("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience is empty")
}
