package localdev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubTokenSource struct {
	audienceToken string
	saToken       string
}

func (s *stubTokenSource) GetAudienceToken(_ context.Context, _ tokensource.TokenAudience) (string, error) {
	return s.audienceToken, nil
}

func (s *stubTokenSource) GetServiceAccountToken(_ context.Context) (string, error) {
	return s.saToken, nil
}

func TestLocalDevTokenSourceDelegatesWhenDisabled(t *testing.T) {
	t.Setenv(ProfileEnv, "")
	t.Setenv(EnabledEnv, "")

	source := &LocalDevTokenSource{
		fallback: &stubTokenSource{audienceToken: "file-token"},
		cache:    make(map[string]cachedAudienceToken),
	}
	token, err := source.GetAudienceToken(context.Background(), tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "file-token", token)
}

func TestLocalDevTokenSourceMintsAndCachesWhenEnabled(t *testing.T) {
	t.Setenv(ProfileEnv, "dev")
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(NamespaceEnv, "my-ns")
	configloader.Init(configloader.EnvPropertySource())

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := map[string]interface{}{
			"status": map[string]interface{}{
				"token":               "minted-token",
				"expirationTimestamp": time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	source := &LocalDevTokenSource{
		fallback: &stubTokenSource{},
		cache:    make(map[string]cachedAudienceToken),
		creds: &KubeConfigCredentials{
			ServerURL: server.URL,
			UserToken: "kube-user",
		},
		client: NewTokenRequestClient(&KubeConfigCredentials{
			ServerURL: server.URL,
			UserToken: "kube-user",
		}),
	}

	token, err := source.GetAudienceToken(context.Background(), tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)

	token, err = source.GetAudienceToken(context.Background(), tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)
	assert.Equal(t, 1, calls)
}

func TestLocalDevTokenSourceReturnsKubeUserTokenForSA(t *testing.T) {
	t.Setenv(ProfileEnv, "dev")
	source := &LocalDevTokenSource{
		fallback: &stubTokenSource{saToken: "file-sa"},
		creds: &KubeConfigCredentials{
			ServerURL: "https://api.example",
			UserToken: "kube-user",
		},
	}
	token, err := source.GetServiceAccountToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "kube-user", token)
}

func TestLocalDevTokenSourceLoadsFromKubeconfig(t *testing.T) {
	t.Setenv(ProfileEnv, "dev")
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
		fallback: &stubTokenSource{},
		cache:    make(map[string]cachedAudienceToken),
	}

	token, err := source.GetServiceAccountToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "kube-user-token", token)

	audienceToken, err := source.GetAudienceToken(context.Background(), tokensource.AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted", audienceToken)
}

func TestLocalDevTokenSourceDelegatesServiceAccountWhenDisabled(t *testing.T) {
	t.Setenv(ProfileEnv, "")
	source := &LocalDevTokenSource{
		fallback: &stubTokenSource{saToken: "file-sa"},
	}
	token, err := source.GetServiceAccountToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "file-sa", token)
}
