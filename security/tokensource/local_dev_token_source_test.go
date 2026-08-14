package tokensource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/internal"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalDevTokenSourceMintsAndCaches(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(localdev.NamespaceEnv, "my-ns")
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

	creds := &internal.KubeConfigCredentials{
		ServerURL: server.URL,
		UserToken: "kube-user",
	}
	source := &localDevTokenSource{
		cache:  make(map[TokenAudience]cachedAudienceToken),
		creds:  creds,
		client: internal.NewTokenRequestClient(creds),
	}

	token, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)

	token, err = source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)
	assert.Equal(t, 1, calls)
}

func TestLocalDevTokenSourceReturnsKubeUserTokenForSA(t *testing.T) {
	source := &localDevTokenSource{
		creds: &internal.KubeConfigCredentials{
			ServerURL: "https://api.example",
			UserToken: "kube-user",
		},
	}
	token, err := source.GetServiceAccountToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "kube-user", token)
}

func TestLocalDevTokenSourceLoadsFromKubeconfig(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(localdev.NamespaceEnv, "my-ns")
	configloader.Init(configloader.EnvPropertySource())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":{"token":"minted","expirationTimestamp":"` +
			time.Now().Add(2*time.Hour).Format(time.RFC3339) + `"}}`))
	}))
	defer server.Close()

	t.Setenv("KUBECONFIG", writeLocalDevTestKubeconfig(t, server.URL))

	source := newLocalDevTokenSource()
	token, err := source.GetServiceAccountToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "kube-user-token", token)

	audienceToken, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted", audienceToken)
}

func TestLocalDevTokenSourceCacheHitDoesNotMint(t *testing.T) {
	source := &localDevTokenSource{
		cache: map[TokenAudience]cachedAudienceToken{
			AudienceNetcracker: {
				token:        "cached-token",
				refreshAfter: time.Now().Add(time.Hour),
			},
		},
	}

	token, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "cached-token", token)
}

func TestLocalDevTokenSourceConcurrentCacheHits(t *testing.T) {
	source := &localDevTokenSource{
		cache: map[TokenAudience]cachedAudienceToken{
			AudienceNetcracker: {
				token:        "cached-token",
				refreshAfter: time.Now().Add(time.Hour),
			},
		},
	}

	const goroutines = 32
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			token, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
			if err != nil {
				errCh <- err
				return
			}
			if token != "cached-token" {
				errCh <- fmt.Errorf("unexpected token %q", token)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
}

func TestLocalDevTokenSourceRejectsEmptyAudience(t *testing.T) {
	_, err := newLocalDevTokenSource().GetAudienceToken(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience is empty")
}

func writeLocalDevTestKubeconfig(t *testing.T, serverURL string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := `apiVersion: v1
kind: Config
current-context: test
contexts:
- context:
    cluster: test
    user: test
  name: test
clusters:
- cluster:
    server: ` + serverURL + `
    insecure-skip-tls-verify: true
  name: test
users:
- name: test
  user:
    token: kube-user-token
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}
