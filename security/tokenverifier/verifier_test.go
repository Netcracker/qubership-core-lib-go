package tokenverifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
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
	testDir        = "test_dir"
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

var (
	key     *rsa.PrivateKey
	storage *test.ServiceAccountTokenStorage
)

func beforeAll() {
	key, _ = rsa.GenerateKey(rand.Reader, 2048)

	storage, _ = test.NewServiceAccountTokenStorage(filepath.Join(os.TempDir(), testDir))
	tokensource.DefaultServiceAccountDir = storage.ServiceAccountTokenDir

	test.StartMockServer()
}

func afterAll() {
	_ = os.RemoveAll(storage.RootDir)
	test.StopMockServer()
}

func TestMain(m *testing.M) {
	beforeAll()
	exitCode := m.Run()
	afterAll()
	os.Exit(exitCode)
}

func TestVerifier(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	serviceAccountToken := createServiceAccountToken(t)
	err, ok := storage.SaveTokenValue(serviceAccountToken)
	assert.True(t, ok)
	require.NoError(t, err)
	addDefaultProviderHandler(serviceAccountToken)
	addDefaultJwksHandler(serviceAccountToken)

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
				assert.Equal(t, scenario.claims.KubernetesIo, actualKubernetesIoClaim, "test %q: unexpected kubernetes.io claim", scenario.name)
			}
		} else {
			assert.ErrorContains(t, verificationErr, scenario.errorMessage)
		}
	}
}

func TestValidation(t *testing.T) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()

	serviceAccountToken := createServiceAccountToken(t)
	err, ok := storage.SaveTokenValue(serviceAccountToken)
	assert.True(t, ok)
	require.NoError(t, err)
	addDefaultProviderHandler(serviceAccountToken)
	addDefaultJwksHandler(serviceAccountToken)

	var opts = []VerifierOptions{
		WithValidations([]Validation{subjectValidation})}

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS, opts...)
	require.NoError(t, err)

	claims := token.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "wrong",
			Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    test.GetMockServerUrl(),
		},
		KubernetesIo: token.KubernetesIoClaim{
			Namespace: namespace,
			ServiceAccount: token.ServiceAccountClaim{
				Name: serviceAccount,
				Uid:  uuid,
			},
		},
	}

	rawToken := test.CreateSignedTokenString(t, key, claims)
	_, verificationErr := maasTokenVerifier.Verify(context.Background(), rawToken)
	assert.ErrorContains(t, verificationErr, "subject claim is wrong")
}

func subjectValidation(jwt *jwt.Token) (bool, error) {
	subject, err := token.GetSubject(jwt)
	if err != nil {
		return false, err
	} else if subject != "wrong" {
		return true, nil
	} else {
		return false, fmt.Errorf("subject claim is wrong")
	}
}
func addDefaultJwksHandler(serviceAccountToken string) {
	test.AddHandler(test.Contains(jwksSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+serviceAccountToken {
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
func addDefaultProviderHandler(serviceAccountToken string) {
	test.AddHandler(test.Contains(oidc.ProviderSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+serviceAccountToken {
				responseWriter.WriteHeader(http.StatusUnauthorized)
				return
			}
			oidcResponse := oidc.ProviderResponse{
				Issuer:  test.GetMockServerUrl(),
				JwksUri: test.GetMockServerUrl() + jwksSubPath,
			}
			responseBody, _ := json.Marshal(oidcResponse)
			_, _ = responseWriter.Write(responseBody)
		})
}
func createServiceAccountToken(t *testing.T) string {
	return test.CreateSignedTokenString(t, key, token.KubernetesClaims{
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
}
func toHexBase64(a *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(a.Bytes())
}
