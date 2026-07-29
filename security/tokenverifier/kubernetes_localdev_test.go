package tokenverifier

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	qubetest "github.com/netcracker/qubership-core-lib-go/v3/security/test"
	qubetoken "github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestLocalDevTransportSkipsBearerOnPublicJwks(t *testing.T) {
	var sawAuthorization bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuthorization = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := newLocalDevTransport(func() (string, error) {
		return "kube-user", nil
	}, http.DefaultTransport)

	req, err := http.NewRequest(http.MethodGet, server.URL+localdev.JwksPath, nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.False(t, sawAuthorization)
}

func TestLocalDevKubernetesVerifierWithoutServiceAccountFile(t *testing.T) {
	t.Setenv("PROFILE", "dev")
	qubetest.MustInitDefaultTestKeys()

	issuer := "https://cluster.example"
	jwksBody, err := json.Marshal(buildTestJWKS())
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case localdev.JwksPath:
			if r.Header.Get("Authorization") != "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(jwksBody)
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{"issuer":"https://cluster.example"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	kubeconfigPath := writeLocalDevTestKubeconfig(t, server.URL)
	t.Setenv("KUBECONFIG", kubeconfigPath)
	localdev.ResetCache()
	defer localdev.ResetCache()

	ctx := context.Background()
	verifier, err := NewKubernetesVerifierOverride(ctx, tokensource.AudienceNetcracker, Override{
		RefreshUnknownKID: rate.NewLimiter(rate.Every(1*time.Second), 1),
	})
	require.NoError(t, err)

	subject := qubetoken.GetKubernetesSubject(qubetest.Namespace, qubetest.ServiceAccount)
	claims := qubetoken.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{tokensource.AudienceNetcracker},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		KubernetesIo: qubetoken.KubernetesIoClaim{
			Namespace: qubetest.Namespace,
			ServiceAccount: qubetoken.ServiceAccountClaim{
				Name: qubetest.ServiceAccount,
				Uid:  qubetest.Uuid,
			},
		},
	}
	rawToken := qubetest.MustCreateDefaultSignedToken(claims)

	_, err = verifier.Verify(ctx, rawToken)
	assert.NoError(t, err)
}

func buildTestJWKS() map[string]interface{} {
	publicKey := qubetest.DefaultPublicKeys[qubetest.DefaultKid]
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": qubetest.DefaultKid,
				"alg": jwt.SigningMethodRS256.Alg(),
				"use": "sig",
				"n":   qubetest.ToHexBase64(publicKey.N),
				"e":   qubetest.ToHexBase64(big.NewInt(int64(publicKey.E))),
			},
		},
	}
}

func writeLocalDevTestKubeconfig(t *testing.T, serverURL string) string {
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
