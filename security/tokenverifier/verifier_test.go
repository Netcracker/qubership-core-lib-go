package tokenverifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	qubetest "github.com/netcracker/qubership-core-lib-go/v3/security/test"
	qubetoken "github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	mockServer "github.com/netcracker/qubership-core-lib-go/v3/test"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

const (
	customKid = "kid-2"
)

var (
	sub                 = qubetoken.GetKubernetesSubject(qubetest.Namespace, qubetest.ServiceAccount)
	mockTokenSource     = qubetest.MockTokenSource{}
	serviceAccountToken string
)

var scenarios = []struct {
	name         string
	claims       qubetoken.KubernetesClaims
	errorMessage string
}{
	{
		name: "valid qubetoken",
		claims: qubetoken.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
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
		},
		errorMessage: "",
	},
	{
		name: "expired token",
		claims: qubetoken.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
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
		},
		errorMessage: "token has invalid claims: token is expired",
	},
	{
		name: "wrong audience",
		claims: qubetoken.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{"some-other-aud"},
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
		},
		errorMessage: "token has invalid claims: token has invalid audience",
	},
	{
		name: "wrong issuer",
		claims: qubetoken.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Issuer:    "https://accounts.google.com",
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
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
		},
		errorMessage: "token has invalid claims: token has invalid issuer",
	},
	{
		name: "no exp claim",
		claims: qubetoken.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
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
		},
		errorMessage: "token has invalid claims: token is missing required claim: exp claim is required",
	},
	{
		name: "no iat claim",
		claims: qubetoken.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
			KubernetesIo: qubetoken.KubernetesIoClaim{
				Namespace: qubetest.Namespace,
				ServiceAccount: qubetoken.ServiceAccountClaim{
					Name: qubetest.ServiceAccount,
					Uid:  qubetest.Uuid,
				},
			},
		},
		errorMessage: "token is missing claim: iat is missed",
	},
	{
		name: "iat after now",
		claims: qubetoken.KubernetesClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   sub,
				Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(1 * time.Minute)),
			},
			KubernetesIo: qubetoken.KubernetesIoClaim{
				Namespace: qubetest.Namespace,
				ServiceAccount: qubetoken.ServiceAccountClaim{
					Name: qubetest.ServiceAccount,
					Uid:  qubetest.Uuid,
				},
			},
		},
		errorMessage: "token used before issued: current time is before issuedAt more than 30 sec",
	},
}

func beforeAll() {
	mockServer.StartMockServer()
	qubetest.MustInitDefaultTestKeys()
	serviceloader.Register(1, &mockTokenSource)
	serviceAccountToken = createServiceAccountToken(mockServer.GetMockServerUrl())
	mockTokenSource.ServiceAccountToken = serviceAccountToken

	logger.Infof("server started %s", mockServer.GetMockServerUrl())
}
func afterEach() {
	mockServer.ClearHandlers()
}
func afterAll() {
	mockServer.StopMockServer()
}
func TestMain(m *testing.M) {
	beforeAll()
	exitCode := m.Run()
	afterAll()
	os.Exit(exitCode)
}
func TestSignatureValidation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	qubetest.MustAddDefaultKubernetesJwksHandler(serviceAccountToken, qubetest.DefaultKeys)

	maasTokenVerifier, err := NewKubernetesVerifierOverride(ctx, tokensource.AudienceMaaS, Override{
		RefreshUnknownKID: rate.NewLimiter(rate.Every(1*time.Second), 1),
	})
	assert.NoError(t, err)

	claims := qubetoken.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    mockServer.GetMockServerUrl(),
		},
		KubernetesIo: qubetoken.KubernetesIoClaim{
			Namespace: qubetest.Namespace,
			ServiceAccount: qubetoken.ServiceAccountClaim{
				Name: qubetest.ServiceAccount,
				Uid:  qubetest.Uuid,
			},
		},
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rawToken := qubetest.MustCreateSignedToken(customKid, key, claims)

	token, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.NotNil(t, token)
	assert.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-2\"\nfailed keyfunc: could not read JWK from storage")

	mockServer.ClearHandlers()

	customKeys := make(map[string]*rsa.PrivateKey)
	customKeys[qubetest.DefaultKid] = qubetest.DefaultKey
	customKeys[customKid] = key
	qubetest.MustAddDefaultKubernetesJwksHandler(serviceAccountToken, customKeys)

	actualToken, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.Nil(t, vErr)
	actualKubernetesIoClaim, getClaimErr := qubetoken.GetKubernetesIo(actualToken)
	assert.Nil(t, getClaimErr)
	actualRegisteredClaims, getClaimErr := qubetoken.GetRegisteredClaims(actualToken)
	assert.Nil(t, getClaimErr)
	assert.Equal(t, claims.KubernetesIo, actualKubernetesIoClaim, "unexpected kubernetes.io claim")
	assert.Equal(t, claims.RegisteredClaims, actualRegisteredClaims, "unexpected registered claims")
}
func TestBasicTokenValidations(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	qubetest.MustAddDefaultKubernetesJwksHandler(serviceAccountToken, qubetest.DefaultKeys)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.NoError(t, err)

	for _, scenario := range scenarios {
		if scenario.claims.Issuer == "" {
			scenario.claims.Issuer = mockServer.GetMockServerUrl()
		}
		rawToken := qubetest.MustCreateDefaultSignedToken(scenario.claims)
		actualToken, vErr := maasTokenVerifier.Verify(ctx, rawToken)
		if scenario.errorMessage == "" {
			assert.NoError(t, vErr, "test %q: expected no error, got: %v", scenario.name, vErr)
			if assert.NotNil(t, actualToken, "test %q: expected claims, got nil", scenario.name) {
				actualKubernetesIoClaim, getClaimErr := qubetoken.GetKubernetesIo(actualToken)
				assert.Nil(t, getClaimErr)
				actualRegisteredClaims, getClaimErr := qubetoken.GetRegisteredClaims(actualToken)
				assert.Nil(t, getClaimErr)
				assert.Equal(t, scenario.claims.KubernetesIo, actualKubernetesIoClaim, "test %q: unexpected kubernetes.io claim", scenario.name)
				assert.Equal(t, scenario.claims.RegisteredClaims, actualRegisteredClaims, "test %q: unexpected registered claims", scenario.name)
			}
		} else {
			assert.ErrorContains(t, vErr, scenario.errorMessage)
		}
	}
}
func TestCustomValidation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	qubetest.MustAddDefaultKubernetesJwksHandler(serviceAccountToken, qubetest.DefaultKeys)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS, subjectValidation)
	assert.NoError(t, err)

	claims := qubetoken.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "wrong",
			Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    mockServer.GetMockServerUrl(),
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
	token, verificationErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.NotNil(t, token)
	assert.ErrorContains(t, verificationErr, "subject claim is wrong")
}
func TestNoServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	mockTokenSource.ServiceAccountTokenError = errors.New("failed to get token default kubernetes service account token")
	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to acquire token for kubernetes API (the possible cause is missing kubernetes service account for the microservice.): failed to get token default kubernetes service account token")
	mockTokenSource.ServiceAccountTokenError = nil
}
func TestInvalidServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	mockTokenSource.ServiceAccountToken = "token"
	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "invalid jwt: token is malformed: token contains an invalid number of segments")
	mockTokenSource.ServiceAccountToken = serviceAccountToken
}
func TestNoServiceAccountTokenIssuer(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	mockTokenSource.ServiceAccountToken = createServiceAccountToken("")
	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "jwt does not have the issuer claim value")
	mockTokenSource.ServiceAccountToken = serviceAccountToken
}
func TestInvalidServiceAccountTokenIssuer(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	mockTokenSource.ServiceAccountToken = createServiceAccountToken("some 	text")
	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to get issuer url: issuer url is invalid: parse \"some \\ttext\": net/url: invalid control character in URL")
	mockTokenSource.ServiceAccountToken = serviceAccountToken
}
func TestOidcRequestUnauthorizedError(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler("token", mockServer.GetMockServerUrl())

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "unexpected response http status code 401 Unauthorized")
}
func TestOidcResponseInvalidPlainText(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, []byte("some body"))

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "oidc: failed to decode provider discovery object: expected content-type = application/json, got \"text/plain; charset=utf-8\": invalid character 's' looking for beginning of value")
}
func TestOidcResponseInvalidJson(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, []byte("{}"))

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to create HTTP client storage for \"\": failed to parse given URL \"\": parse \"\": empty url\nfailed to create new JWK Set client")
}
func TestOidcResponseInvalidNil(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, nil)

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "oidc: failed to decode provider discovery object: expected content-type = application/json, got \"\": unexpected end of JSON input")

}
func TestOidcResponseInternalServerErrorFiveAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	counter := 0
	mockServer.AddHandler(mockServer.Contains(oidc.ProviderSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.WriteHeader(http.StatusInternalServerError)
			logger.Infof("attempt %v: request to %s, response %v", counter, oidc.ProviderSubPath, http.StatusInternalServerError)
			counter++
		})

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to send oidc request (the possible cause is outdated base image without kubernetes service account ca.crt, please check your base image version.):")
}
func TestOidcResponseInternalServerErrorFourAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	counter := 0
	qubetest.MustAddDefaultKubernetesJwksHandler(serviceAccountToken, qubetest.DefaultKeys)
	mockServer.AddHandler(mockServer.Contains(oidc.ProviderSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if counter < 4 {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				logger.Infof("attempt %v: request to %s, response %v", counter, oidc.ProviderSubPath, http.StatusInternalServerError)
			} else {
				response := oidc.ProviderResponse{
					Issuer:  mockServer.GetMockServerUrl(),
					JwksUri: mockServer.GetMockServerUrl() + qubetest.JwksSubPath,
				}
				responseWriter.WriteHeader(http.StatusOK)
				responseBody, _ := json.Marshal(response)
				_, _ = responseWriter.Write(responseBody)
				logger.Infof("attempt %v: request to %s, response %v:%s", counter, oidc.ProviderSubPath, http.StatusOK, string(responseBody))
			}
			counter++
		})

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.Nil(t, err)
}
func TestJwksRequestUnauthorizedError(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	qubetest.MustAddDefaultKubernetesJwksHandler("token", qubetest.DefaultKeys)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.NoError(t, err)

	rawToken := qubetest.MustCreateDefaultSignedToken(scenarios[0].claims)
	token, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.NotNil(t, token)
	assert.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksRequestInvalidPlainText(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	qubetest.AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, []byte("some body"))

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.NoError(t, err)

	rawToken := qubetest.MustCreateDefaultSignedToken(scenarios[0].claims)
	token, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.NotNil(t, token)
	assert.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInvalidJson(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	qubetest.AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, []byte("{}"))

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.NoError(t, err)

	rawToken := qubetest.MustCreateDefaultSignedToken(scenarios[0].claims)
	token, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.NotNil(t, token)
	assert.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInvalidNil(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	qubetest.AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, nil)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.NoError(t, err)

	rawToken := qubetest.MustCreateDefaultSignedToken(scenarios[0].claims)
	token, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.NotNil(t, token)
	assert.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInternalServerErrorFiveAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	counter := 0
	mockServer.AddHandler(mockServer.Contains(qubetest.JwksSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.WriteHeader(http.StatusInternalServerError)
			logger.Infof("attempt %v: request to %s, response %v", counter, qubetest.JwksSubPath, http.StatusInternalServerError)
			counter++
		})

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.NoError(t, err)

	rawToken := qubetest.MustCreateDefaultSignedToken(scenarios[0].claims)
	token, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.NotNil(t, token)
	assert.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInternalServerErrorFourAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); afterEach() }()

	qubetest.MustAddDefaultKubernetesProviderHandler(serviceAccountToken, mockServer.GetMockServerUrl())
	counter := 0
	mockServer.AddHandler(mockServer.Contains(qubetest.JwksSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if counter < 4 {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				logger.Infof("attempt %v: request to %s, response %v", counter, qubetest.JwksSubPath, http.StatusInternalServerError)
			} else {
				var keySet []JWKMarshal
				for kid, privateKey := range qubetest.DefaultKeys {
					keySet = append(keySet, JWKMarshal{
						KTY: "RSA",
						KID: kid,
						ALG: ALG(jwt.SigningMethodRS256.Alg()),
						USE: "sig",
						N:   qubetest.ToHexBase64(privateKey.N),
						E:   qubetest.ToHexBase64(big.NewInt(int64(privateKey.E))),
					})
				}
				jwks := &JWKSMarshal{
					Keys: keySet,
				}
				responseBody, _ := json.Marshal(jwks)
				_, _ = responseWriter.Write(responseBody)
				logger.Infof("attempt %v: request to %s, response %v:%s", counter, qubetest.JwksSubPath, http.StatusOK, string(responseBody))
			}
			counter++
		})

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.NoError(t, err)

	claims := qubetoken.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    mockServer.GetMockServerUrl(),
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
	actualToken, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.Nil(t, vErr)
	actualKubernetesIoClaim, getClaimErr := qubetoken.GetKubernetesIo(actualToken)
	assert.Nil(t, getClaimErr)
	actualRegisteredClaims, getClaimErr := qubetoken.GetRegisteredClaims(actualToken)
	assert.Nil(t, getClaimErr)
	assert.Equal(t, claims.KubernetesIo, actualKubernetesIoClaim, "unexpected kubernetes.io claim")
	assert.Equal(t, claims.RegisteredClaims, actualRegisteredClaims, "unexpected registered claims")
}
func subjectValidation(jwt *jwt.Token) error {
	subject, err := qubetoken.GetSubject(jwt)
	if err != nil {
		return err
	} else if subject != "wrong" {
		return nil
	} else {
		return fmt.Errorf("subject claim is wrong")
	}
}
func createServiceAccountToken(issuer string) string {
	return qubetest.MustCreateDefaultSignedToken(qubetoken.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   qubetoken.GetKubernetesSubject(qubetest.Namespace, qubetest.ServiceAccount),
			Audience:  jwt.ClaimStrings{qubetest.KubernetesAudience},
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
	})
}
