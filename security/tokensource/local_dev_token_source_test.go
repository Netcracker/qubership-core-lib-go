package tokensource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/netcracker/qubership-core-lib-go/v3/utils"
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

	source := newTestLocalDevSource(t, server.URL)

	token, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)

	token, err = source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted-token", token)
	assert.Equal(t, 1, calls)
}

func TestLocalDevTokenSourceMintsServiceAccountToken(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(localdev.NamespaceEnv, "my-ns")
	configloader.Init(configloader.EnvPropertySource())

	var requestedAudience string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/namespaces/my-ns/serviceaccounts/my-sa/token")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var payload struct {
			Spec struct {
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		require.NoError(t, json.Unmarshal(body, &payload))
		require.Len(t, payload.Spec.Audiences, 1)
		requestedAudience = payload.Spec.Audiences[0]
		resp := map[string]any{
			"status": map[string]any{
				"token":               "sa-minted-token",
				"expirationTimestamp": time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	source := newTestLocalDevSource(t, server.URL)
	token, err := source.GetServiceAccountToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "sa-minted-token", token)
	assert.Equal(t, internal.DefaultKubernetesIssuer, requestedAudience)
}

func TestLocalDevTokenSourceLoadsFromKubeconfig(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(localdev.NamespaceEnv, "my-ns")
	configloader.Init(configloader.EnvPropertySource())

	audiences := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var payload struct {
			Spec struct {
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		require.NoError(t, json.Unmarshal(body, &payload))
		require.Len(t, payload.Spec.Audiences, 1)
		audiences = append(audiences, payload.Spec.Audiences[0])
		_, _ = w.Write([]byte(`{"status":{"token":"minted-` + payload.Spec.Audiences[0] + `","expirationTimestamp":"` +
			time.Now().Add(2*time.Hour).Format(time.RFC3339) + `"}}`))
	}))
	defer server.Close()

	t.Setenv("KUBECONFIG", writeLocalDevTestKubeconfig(t, server.URL))

	source := newLocalDevTokenSource()
	token, err := source.GetServiceAccountToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "minted-"+string(internal.DefaultKubernetesIssuer), token)

	audienceToken, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "minted-netcracker", audienceToken)
	assert.Equal(t, []string{internal.DefaultKubernetesIssuer, string(AudienceNetcracker)}, audiences)
}

func TestLocalDevTokenSourceConcurrentCacheHits(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "my-sa")
	t.Setenv(localdev.NamespaceEnv, "my-ns")
	configloader.Init(configloader.EnvPropertySource())

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		resp := map[string]any{
			"status": map[string]any{
				"token":               "cached-token",
				"expirationTimestamp": time.Now().Add(2 * time.Hour).Format(time.RFC3339),
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	source := newTestLocalDevSource(t, server.URL)
	token, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
	require.NoError(t, err)
	assert.Equal(t, "cached-token", token)

	const goroutines = 32
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			got, err := source.GetAudienceToken(context.Background(), AudienceNetcracker)
			if err != nil {
				errCh <- err
				return
			}
			if got != "cached-token" {
				errCh <- fmt.Errorf("unexpected token %q", got)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	assert.Equal(t, 1, calls)
}

func TestLocalDevTokenSourceRejectsEmptyAudience(t *testing.T) {
	_, err := newLocalDevTokenSource().GetAudienceToken(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience is empty")
}

func newTestLocalDevSource(t *testing.T, serverURL string) *localDevTokenSource {
	t.Helper()
	creds := &internal.KubeConfigCredentials{
		ServerURL: serverURL,
		UserToken: "kube-user",
	}
	source := &localDevTokenSource{
		client: internal.NewTokenRequestClient(creds),
	}
	source.tokens = utils.NewLoadingCache(source.requestToken)
	return source
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
