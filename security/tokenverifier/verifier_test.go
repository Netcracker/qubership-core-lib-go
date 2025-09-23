package tokenverifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	openid "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
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
			Claims: jwt.Claims{
				Subject:   sub,
				Audience:  jwt.Audience{aud},
				Expiry:    jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
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
			Claims: jwt.Claims{
				Subject:   sub,
				Audience:  jwt.Audience{aud},
				Expiry:    jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
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
			Claims: jwt.Claims{
				Subject:   sub,
				Audience:  jwt.Audience{"some-other-aud"},
				Expiry:    jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
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
			Claims: jwt.Claims{
				Subject:   sub,
				Issuer:    "https://accounts.google.com",
				Audience:  jwt.Audience{aud},
				Expiry:    jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
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
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}, nil)
	require.NoError(t, err)

	var tvClientToken string
	server, err := setupServer(key.Public(), &tvClientToken)
	require.NoError(t, err)
	defer server.Close()

	clientToken, err := generateJwt(signer, Claims{
		Claims: jwt.Claims{
			Issuer:    server.URL,
			Subject:   "system:serviceaccount:default:default",
			Audience:  jwt.Audience{"kubernetes.default.svc"},
			Expiry:    jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
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
	testAudience := filepath.Base(tokenDir)
	testTokenDir := filepath.Dir(tokenDir)

	err = os.Setenv("KUBERNETES_TOKENS_DIR", testTokenDir)
	require.NoError(t, err)
	configloader.Init(configloader.EnvPropertySource())

	v, err := newVerifier(ctx, aud, func() (string, error) {
		return tokensource.GetToken(ctx, testAudience)
	})
	require.NoError(t, err)

	for _, test := range tests {
		if test.claims.Issuer == "" {
			test.claims.Issuer = server.URL
		}
		rawToken, err := generateJwt(signer, test.claims)
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

func generateJwt(signer jose.Signer, claims Claims) (string, error) {
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func setupServer(key crypto.PublicKey, clientToken *string) (*httptest.Server, error) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       key,
			KeyID:     "key-1",
			Algorithm: string(jose.RS256),
			Use:       "sig",
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
