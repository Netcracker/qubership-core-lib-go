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
	jwksSubPath    = "/openid/v1/jwks"
	serviceAccount = "test-service-account"
	namespace      = "test-namespace"
	uuid           = "test-uuid"
)

var (
	sub       = token.GetKubernetesSubject(namespace, serviceAccount)
	ctx       context.Context
	cancelCtx context.CancelFunc
	key       *rsa.PrivateKey
	storage   *test.ServiceAccountTokenStorage
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
	{
		name: "no exp claim",
		claims: token.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
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
		errorMessage: "token has invalid claims: token is missing required claim: exp claim is required",
	},
	{
		name: "no iat claim",
		claims: token.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
			KubernetesIo: token.KubernetesIoClaim{
				Namespace: namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: serviceAccount,
					Uid:  uuid,
				},
			},
		},
		errorMessage: "token is missing claim: iat is missed",
	},
	{
		name: "iat after now",
		claims: token.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(1 * time.Minute)),
			},
			KubernetesIo: token.KubernetesIoClaim{
				Namespace: namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: serviceAccount,
					Uid:  uuid,
				},
			},
		},
		errorMessage: "token used before issued: current time is before issuedAt more than 30 sec",
	},
}

func beforeEach(t *testing.T) {
	key, _ = rsa.GenerateKey(rand.Reader, 2048)
	test.StartMockServer()
	storage, _ = test.NewServiceAccountTokenStorage(t.TempDir())
	tokensource.DefaultServiceAccountDir = storage.ServiceAccountTokenDir
}
func afterEach() {
	_ = storage.Clear()
	test.StopMockServer()
}
func TestMain(m *testing.M) {
	exitCode := m.Run()
	os.Exit(exitCode)
}
func TestBasicTokenValidations(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	serviceAccountToken := createServiceAccountToken(t, test.GetMockServerUrl())
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	addProviderHandlerDefaultResponse(serviceAccountToken)
	addJwksHandlerDefaultResponse(serviceAccountToken)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	for _, scenario := range scenarios {
		if scenario.claims.Issuer == "" {
			scenario.claims.Issuer = test.GetMockServerUrl()
		}
		rawToken := test.CreateSignedTokenString(t, key, scenario.claims)
		actualToken, verificationErr := maasTokenVerifier.Verify(ctx, rawToken)
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
func TestCustomValidation(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	serviceAccountToken := createServiceAccountToken(t, test.GetMockServerUrl())
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	addProviderHandlerDefaultResponse(serviceAccountToken)
	addJwksHandlerDefaultResponse(serviceAccountToken)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS, subjectValidation)
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
	_, verificationErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.ErrorContains(t, verificationErr, "subject claim is wrong")
}
func TestNoServiceAccountToken(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	_ = storage.DeleteTokenFile()

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to acquire token for kubernetes API (the possible cause is missing kubernetes service account for the microservice.): failed to get token default kubernetes service account token:")
}
func TestInvalidServiceAccountToken(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	serviceAccountToken := "token"
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "invalid jwt: token is malformed: token contains an invalid number of segments")
}
func TestNoServiceAccountTokenIssuer(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	serviceAccountToken := createServiceAccountToken(t, "")
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "jwt does not have the issuer claim value")
}
func TestInvalidServiceAccountTokenIssuer(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	serviceAccountToken := createServiceAccountToken(t, "some 	text")
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to get issuer url: issuer url is invalid: parse \"some \\ttext\": net/url: invalid control character in URL")
}
func TestOidcRequestUnauthorizedError(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	serviceAccountToken := createServiceAccountToken(t, test.GetMockServerUrl())
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	addProviderHandlerDefaultResponse("token")

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "unexpected response http status code 401 Unauthorized")

}
func TestOidcRequestCertificateError(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	test.StopMockServer()
	test.StartMockTLSServer()
	defer test.StopMockServer()

	serviceAccountToken := createServiceAccountToken(t, test.GetMockServerUrl())
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	addProviderHandlerDefaultResponse(serviceAccountToken)

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "failed to send oidc request (the possible cause is outdated base image without kubernetes service account ca.crt, please check your base image version.):")
}
func TestOidcResponseParsingError(t *testing.T) {
	ctx, cancelCtx = context.WithTimeout(context.Background(), time.Minute)
	defer cancelCtx()
	beforeEach(t)
	defer afterEach()

	serviceAccountToken := createServiceAccountToken(t, test.GetMockServerUrl())
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	addProviderHandler(serviceAccountToken, http.StatusOK, []byte("some body"))

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "oidc: failed to decode provider discovery object: expected content-type = application/json, got \"text/plain; charset=utf-8\": invalid character 's' looking for beginning of value")

	test.ClearHandlers()
	addProviderHandler(serviceAccountToken, http.StatusOK, []byte("{}"))

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "failed to create HTTP client storage for \"\": failed to parse given URL \"\": parse \"\": empty url\nfailed to create new JWK Set client")

	test.ClearHandlers()
	addProviderHandler(serviceAccountToken, http.StatusOK, nil)

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "oidc: failed to decode provider discovery object: expected content-type = application/json, got \"\": unexpected end of JSON input")

	test.ClearHandlers()
	counter := 0
	addJwksHandlerDefaultResponse(serviceAccountToken)
	test.AddHandler(test.Contains(oidc.ProviderSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if counter < 5 {
				responseWriter.WriteHeader(http.StatusInternalServerError)
			} else {
				response := oidc.ProviderResponse{
					Issuer:  test.GetMockServerUrl(),
					JwksUri: test.GetMockServerUrl() + jwksSubPath,
				}
				responseWriter.WriteHeader(http.StatusOK)
				responseBody, _ := json.Marshal(response)
				_, _ = responseWriter.Write(responseBody)
			}
			counter++
		})

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "failed to send oidc request (the possible cause is outdated base image without kubernetes service account ca.crt, please check your base image version.):")

}
func subjectValidation(jwt *jwt.Token) error {
	subject, err := token.GetSubject(jwt)
	if err != nil {
		return err
	} else if subject != "wrong" {
		return nil
	} else {
		return fmt.Errorf("subject claim is wrong")
	}
}
func createServiceAccountToken(t *testing.T, issuer string) string {
	return test.CreateSignedTokenString(t, key, token.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
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
func addProviderHandlerDefaultResponse(serviceAccountToken string) {
	response := oidc.ProviderResponse{
		Issuer:  test.GetMockServerUrl(),
		JwksUri: test.GetMockServerUrl() + jwksSubPath,
	}
	responseBody, _ := json.Marshal(response)
	addProviderHandler(serviceAccountToken, http.StatusOK, responseBody)
}
func addProviderHandler(serviceAccountToken string, statusCode int, responseBody []byte) {
	addAuthorizedHandler(oidc.ProviderSubPath, serviceAccountToken, statusCode, responseBody)
}
func addJwksHandlerDefaultResponse(serviceAccountToken string) {
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
	addJwksHandler(serviceAccountToken, http.StatusOK, responseBody)
}
func addJwksHandler(serviceAccountToken string, statusCode int, responseBody []byte) {
	addAuthorizedHandler(jwksSubPath, serviceAccountToken, statusCode, responseBody)
}
func addAuthorizedHandler(path, serviceAccountToken string, statusCode int, responseBody []byte) {
	test.AddHandler(test.Contains(path),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+serviceAccountToken {
				responseWriter.WriteHeader(http.StatusUnauthorized)
				return
			}
			if responseBody != nil {
				responseWriter.WriteHeader(statusCode)
				_, _ = responseWriter.Write(responseBody)
			}
		})
}
