package tokenverifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	openid "github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	aud       = "maas"
	sa        = "test-service-account"
	sub       = "system:serviceaccount:default:test-service-account"
	namespace = "default"
	uuid      = "test-uuid"
)

var tests = []struct {
	name   string
	claims Claims
	ok     bool
}{
	{
		name: "valid token",
		claims: Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{aud},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Kubernetes: K8sClaims{
				Namespace: namespace,
				ServiceAccount: ServiceAccount{
					Name: sa,
					Uid:  uuid,
				},
			},
		},
		ok: true,
	},
	{
		name: "expired token",
		claims: Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{aud},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Kubernetes: K8sClaims{
				Namespace: namespace,
				ServiceAccount: ServiceAccount{
					Name: sa,
					Uid:  uuid,
				},
			},
		},
		ok: false,
	},
	{
		name: "wrong audience",
		claims: Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{"some-other-aud"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Kubernetes: K8sClaims{
				Namespace: namespace,
				ServiceAccount: ServiceAccount{
					Name: sa,
					Uid:  uuid,
				},
			},
		},
		ok: false,
	},
	{
		name: "wrong issuer",
		claims: Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Issuer:    "https://accounts.google.com",
				Audience:  jwt.ClaimStrings{aud},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Kubernetes: K8sClaims{
				Namespace: namespace,
				ServiceAccount: ServiceAccount{
					Name: sa,
					Uid:  uuid,
				},
			},
		},
		ok: false,
	},
}

func TestVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var tvClientToken string
	server, err := setupServer(&key.PublicKey, &tvClientToken)
	require.NoError(t, err)
	defer server.Close()

	clientToken, err := generateJwt(key, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    server.URL,
			Subject:   "system:serviceaccount:default:default",
			Audience:  jwt.ClaimStrings{"kubernetes.default.svc"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Kubernetes: K8sClaims{
			Namespace: "default",
			ServiceAccount: ServiceAccount{
				Name: "default",
				Uid:  "12345678-1234-1234-1234-1234567890ab",
			},
		},
	})
	require.NoError(t, err)
	tvClientToken = clientToken

	ctx := openid.ClientContext(context.Background(), server.Client())

	tokenFile, err := os.Create(filepath.Join(t.TempDir(), "token"))
	require.NoError(t, err)
	defer tokenFile.Close()
	_, err = tokenFile.Write([]byte(tvClientToken))
	require.NoError(t, err)

	tokenDir := filepath.Dir(tokenFile.Name())
	testTokenDir := filepath.Dir(tokenDir)

	err = os.Setenv("KUBERNETES_TOKENS_DIR", testTokenDir)
	require.NoError(t, err)
	err = os.Setenv("KUBERNETES_SERVICEACCOUNT_DIR", tokenDir)
	require.NoError(t, err)
	configloader.Init(configloader.EnvPropertySource())

	v, err := New(ctx, aud, )
	require.NoError(t, err)

	for _, test := range tests {
		if test.claims.Issuer == "" {
			test.claims.Issuer = server.URL
		}
		rawToken, err := generateJwt(key, test.claims)
		require.NoError(t, err)
		claims, err := v.Verify(context.Background(), rawToken)
		if test.ok {
			assert.NoError(t, err, "test %q: expected no error, got: %v", test.name, err)
			if assert.NotNil(t, claims, "test %q: expected claims, got nil", test.name) {
				assert.Equal(t, test.claims.Kubernetes, claims.Kubernetes, "test %q: unexpected Kubernetes claim", test.name)
			}
		} else {
			assert.Error(t, err, "test %q: expected error, got none", test.name)
		}
	}
}

func generateJwt(key crypto.PrivateKey, claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	rawToken, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return rawToken, nil
}

type jsonWebKey struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	N         string `json:"n"`
	E         string `json:"e"`
}

func setupServer(key *rsa.PublicKey, clientToken *string) (*httptest.Server, error) {
	jwks := struct {
		Keys []jsonWebKey `json:"keys"`
	}{
		Keys: []jsonWebKey{{
			KeyType:   "RSA",
			KeyID:     "key-1",
			Algorithm: string(jwt.SigningMethodRS256.Alg()),
			Use:       "sig",
			N:         toHexBase64(key.N),
			E:         toHexBase64(big.NewInt(int64(key.E))),
		}},
	}
	rawJwks, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}
	openidConf := struct {
		JwksUri string `json:"jwks_uri"`
		Issuer  string `json:"issuer"`
	}{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+*clientToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			if openidConf.Issuer == "" {
				openidConf.Issuer = server.URL
			}
			if openidConf.JwksUri == "" {
				openidConf.JwksUri = server.URL + "/jwks"
			}
			openidConfJson, err := json.Marshal(openidConf)
			if err != nil {
				panic(err)
			}
			w.Write(openidConfJson)
		case "/jwks":
			w.Write(rawJwks)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server, nil
}

func toHexBase64(a *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(a.Bytes())
}
