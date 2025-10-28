package tokenverifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	jwksSubPath    = "/jwks"
	serviceAccount = "test-service-account"
	namespace      = "test-namespace"
	uuid           = "test-uuid"
)

var (
	sub = token.GetKubernetesSubject(namespace, serviceAccount)
)

var scenarios = []struct {
	name         string
	claims       token.KubernetesClaims
	errorMessage string
}{
	{
		name: "valid token",
		claims: token.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			KubernetesIo: token.KubernetesIoClaim{
				Namespace: namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: serviceAccount,
					Uid:  uuid,
				},
			},
		},
		errorMessage: "",
	},
	{
		name: "expired token",
		claims: token.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			KubernetesIo: token.KubernetesIoClaim{
				Namespace: namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: serviceAccount,
					Uid:  uuid,
				},
			},
		},
		errorMessage: "token has invalid claims: token is expired",
	},
	{
		name: "wrong audience",
		claims: token.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{"some-other-aud"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			KubernetesIo: token.KubernetesIoClaim{
				Namespace: namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: serviceAccount,
					Uid:  uuid,
				},
			},
		},
		errorMessage: "token has invalid claims: token has invalid audience",
	},
	{
		name: "wrong issuer",
		claims: token.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Issuer:    "https://accounts.google.com",
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			KubernetesIo: token.KubernetesIoClaim{
				Namespace: namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: serviceAccount,
					Uid:  uuid,
				},
			},
		},
		errorMessage: "token has invalid claims: token has invalid issuer",
	},
}

func TestVerifier(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	test.StartMockServer()

	serviceAccountToken := test.CreateSignedTokenString(t, key, token.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    test.GetMockServerUrl(),
			Subject:   sub,
			Audience:  jwt.ClaimStrings{"https://kubernetes.default.svc.cluster.local"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		KubernetesIo: token.KubernetesIoClaim{
			Namespace: namespace,
			ServiceAccount: token.ServiceAccountClaim{
				Name: serviceAccount,
				Uid:  uuid,
			},
		},
	})

	prepareHandlers(&key.PublicKey, &serviceAccountToken)
	require.NoError(t, err)

	tokenStorage, err := test.NewServiceAccountTokenStorage(t.TempDir())
	require.NoError(t, err)
	tokensource.DefaultServiceAccountDir = tokenStorage.ServiceAccountTokenDir
	err, ok := tokenStorage.SaveTokenValue(serviceAccountToken)
	assert.True(t, ok)
	require.NoError(t, err)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	for _, scenario := range scenarios {
		if scenario.claims.Issuer == "" {
			scenario.claims.Issuer = test.GetMockServerUrl()
		}
		rawToken := test.CreateSignedTokenString(t, key, scenario.claims)
		actualToken, verificationErr := maasTokenVerifier.Verify(context.Background(), rawToken)
		if scenario.errorMessage == "" {
			assert.NoError(t, verificationErr, "test %q: expected no error, got: %v", scenario.name, verificationErr)
			if assert.NotNil(t, actualToken, "test %q: expected claims, got nil", scenario.name) {
				actualKubernetesIoClaim, getClaimErr := token.GetKubernetesIo(actualToken)
				assert.Nil(t, getClaimErr)
				assert.Equal(t, scenario.claims.KubernetesIo, actualKubernetesIoClaim, "test %q: unexpected Kubernetes claim", scenario.name)
			}
		} else {
			assert.ErrorContains(t, verificationErr, scenario.errorMessage)
		}
	}

	test.StopMockServer()
}

func prepareHandlers(key *rsa.PublicKey, serviceAccountToken *string) {
	test.AddHandler(test.Contains(token.OpenIdConfigurationSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+*serviceAccountToken {
				responseWriter.WriteHeader(http.StatusUnauthorized)
				return
			}
			oidcResponse := OidcResponse{
				Issuer:  test.GetMockServerUrl(),
				JwksUri: test.GetMockServerUrl() + jwksSubPath,
			}
			responseBody, _ := json.Marshal(oidcResponse)
			_, _ = responseWriter.Write(responseBody)
		})

	test.AddHandler(test.Contains(jwksSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+*serviceAccountToken {
				responseWriter.WriteHeader(http.StatusUnauthorized)
				return
			}

			jwks := &jwkset.JWKSMarshal{
				Keys: []jwkset.JWKMarshal{{
					KTY: "RSA",
					KID: "key-1",
					ALG: jwkset.ALG(jwt.SigningMethodRS256.Alg()),
					USE: "sig",
					N:   toHexBase64(key.N),
					E:   toHexBase64(big.NewInt(int64(key.E))),
				}},
			}

			responseBody, _ := json.Marshal(jwks)
			_, _ = responseWriter.Write(responseBody)
		})
}

func toHexBase64(a *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(a.Bytes())
}
