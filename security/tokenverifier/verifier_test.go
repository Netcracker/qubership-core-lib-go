package tokenverifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

const (
	customKid = "kid-2"
)

var (
	sub         = token.GetKubernetesSubject(test.Namespace, test.ServiceAccount)
	defaultKey  *rsa.PrivateKey
	defaultKeys map[string]*rsa.PrivateKey
	storage     *test.ServiceAccountTokenStorage
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
				Namespace: test.Namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: test.ServiceAccount,
					Uid:  test.Uuid,
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
				Namespace: test.Namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: test.ServiceAccount,
					Uid:  test.Uuid,
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
				Namespace: test.Namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: test.ServiceAccount,
					Uid:  test.Uuid,
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
				Namespace: test.Namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: test.ServiceAccount,
					Uid:  test.Uuid,
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
				Namespace: test.Namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: test.ServiceAccount,
					Uid:  test.Uuid,
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
				Namespace: test.Namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: test.ServiceAccount,
					Uid:  test.Uuid,
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
				Namespace: test.Namespace,
				ServiceAccount: token.ServiceAccountClaim{
					Name: test.ServiceAccount,
					Uid:  test.Uuid,
				},
			},
		},
		errorMessage: "token used before issued: current time is before issuedAt more than 30 sec",
	},
}

func beforeAll() {
	test.StartMockServer()
	logger.Infof("server started %s", test.GetMockServerUrl())
}
func beforeEach(t *testing.T) {
	defaultKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	defaultKeys = make(map[string]*rsa.PrivateKey)
	defaultKeys[test.DefaultKid] = defaultKey
	storage, _ = test.NewServiceAccountTokenStorage(t.TempDir())
	tokensource.DefaultServiceAccountDir = storage.ServiceAccountTokenDir
	logger.Infof("service account dir is %s", storage.ServiceAccountTokenDir)
}
func afterEach(_ *testing.T) {
	_ = storage.Clear()
	test.ClearHandlers()
}
func afterAll() {
	test.StopMockServer()
}
func TestMain(m *testing.M) {
	beforeAll()
	exitCode := m.Run()
	afterAll()
	os.Exit(exitCode)
}
func TestSignatureValidation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	test.AddDefaultKubernetesJwksHandler(serviceAccountToken, defaultKeys)

	maasTokenVerifier, err := NewKubernetesVerifierOverride(ctx, tokensource.AudienceMaaS, Override{
		RefreshUnknownKID: rate.NewLimiter(rate.Every(1*time.Second), 1),
	})
	require.NoError(t, err)

	claims := token.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    test.GetMockServerUrl(),
		},
		KubernetesIo: token.KubernetesIoClaim{
			Namespace: test.Namespace,
			ServiceAccount: token.ServiceAccountClaim{
				Name: test.ServiceAccount,
				Uid:  test.Uuid,
			},
		},
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rawToken := test.CreateSignedTokenString(t, customKid, key, claims)

	_, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-2\"\nfailed keyfunc: could not read JWK from storage")

	test.ClearHandlers()

	customKeys := make(map[string]*rsa.PrivateKey)
	customKeys[test.DefaultKid] = defaultKey
	customKeys[customKid] = key
	test.AddDefaultKubernetesJwksHandler(serviceAccountToken, customKeys)

	actualToken, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.Nil(t, vErr)
	actualKubernetesIoClaim, getClaimErr := token.GetKubernetesIo(actualToken)
	assert.Nil(t, getClaimErr)
	assert.Equal(t, claims.KubernetesIo, actualKubernetesIoClaim, "unexpected kubernetes.io claim")
}
func TestBasicTokenValidations(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	test.AddDefaultKubernetesJwksHandler(serviceAccountToken, defaultKeys)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	for _, scenario := range scenarios {
		if scenario.claims.Issuer == "" {
			scenario.claims.Issuer = test.GetMockServerUrl()
		}
		rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, scenario.claims)
		actualToken, vErr := maasTokenVerifier.Verify(ctx, rawToken)
		if scenario.errorMessage == "" {
			assert.NoError(t, vErr, "test %q: expected no error, got: %v", scenario.name, vErr)
			if assert.NotNil(t, actualToken, "test %q: expected claims, got nil", scenario.name) {
				actualKubernetesIoClaim, getClaimErr := token.GetKubernetesIo(actualToken)
				assert.Nil(t, getClaimErr)
				assert.Equal(t, scenario.claims.KubernetesIo, actualKubernetesIoClaim, "test %q: unexpected kubernetes.io claim", scenario.name)
			}
		} else {
			assert.ErrorContains(t, vErr, scenario.errorMessage)
		}
	}
}
func TestCustomValidation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	test.AddDefaultKubernetesJwksHandler(serviceAccountToken, defaultKeys)

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
			Namespace: test.Namespace,
			ServiceAccount: token.ServiceAccountClaim{
				Name: test.ServiceAccount,
				Uid:  test.Uuid,
			},
		},
	}

	rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, claims)
	_, verificationErr := maasTokenVerifier.Verify(ctx, rawToken)
	assert.ErrorContains(t, verificationErr, "subject claim is wrong")
}
func TestNoServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	_ = storage.DeleteTokenFile()

	_, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to acquire token for kubernetes API (the possible cause is missing kubernetes service account for the microservice.): failed to get token default kubernetes service account token:")
}
func TestInvalidServiceAccountToken(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := "token"
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "invalid jwt: token is malformed: token contains an invalid number of segments")
}
func TestNoServiceAccountTokenIssuer(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, "", test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "jwt does not have the issuer claim value")
}
func TestInvalidServiceAccountTokenIssuer(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, "some 	text", test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	assert.ErrorContains(t, err, "failed to get issuer url: issuer url is invalid: parse \"some \\ttext\": net/url: invalid control character in URL")
}
func TestOidcRequestUnauthorizedError(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler("token", test.GetMockServerUrl())

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "unexpected response http status code 401 Unauthorized")
}
func TestOidcResponseInvalidPlainText(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, []byte("some body"))

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "oidc: failed to decode provider discovery object: expected content-type = application/json, got \"text/plain; charset=utf-8\": invalid character 's' looking for beginning of value")
}
func TestOidcResponseInvalidJson(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, []byte("{}"))

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "failed to create HTTP client storage for \"\": failed to parse given URL \"\": parse \"\": empty url\nfailed to create new JWK Set client")
}
func TestOidcResponseInvalidNil(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, nil)

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "oidc: failed to decode provider discovery object: expected content-type = application/json, got \"\": unexpected end of JSON input")

}
func TestOidcResponseInternalServerErrorFiveAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	counter := 0
	test.AddHandler(test.Contains(oidc.ProviderSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.WriteHeader(http.StatusInternalServerError)
			logger.Infof("attempt %v: request to %s, response %v", counter, oidc.ProviderSubPath, http.StatusInternalServerError)
			counter++
		})

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.ErrorContains(t, err, "failed to send oidc request (the possible cause is outdated base image without kubernetes service account ca.crt, please check your base image version.):")
}
func TestOidcResponseInternalServerErrorFourAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	counter := 0
	test.AddDefaultKubernetesJwksHandler(serviceAccountToken, defaultKeys)
	test.AddHandler(test.Contains(oidc.ProviderSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if counter < 4 {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				logger.Infof("attempt %v: request to %s, response %v", counter, oidc.ProviderSubPath, http.StatusInternalServerError)
			} else {
				response := oidc.ProviderResponse{
					Issuer:  test.GetMockServerUrl(),
					JwksUri: test.GetMockServerUrl() + test.JwksSubPath,
				}
				responseWriter.WriteHeader(http.StatusOK)
				responseBody, _ := json.Marshal(response)
				_, _ = responseWriter.Write(responseBody)
				logger.Infof("attempt %v: request to %s, response %v:%s", counter, oidc.ProviderSubPath, http.StatusOK, string(responseBody))
			}
			counter++
		})

	_, err = NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.Nil(t, err)
}
func TestJwksRequestUnauthorizedError(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	test.AddDefaultKubernetesJwksHandler("token", defaultKeys)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, scenarios[0].claims)
	_, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksRequestInvalidPlainText(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	test.AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, []byte("some body"))

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, scenarios[0].claims)
	_, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInvalidJson(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	test.AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, []byte("{}"))

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, scenarios[0].claims)
	_, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInvalidNil(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	test.AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, nil)

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, scenarios[0].claims)
	_, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInternalServerErrorFiveAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	counter := 0
	test.AddHandler(test.Contains(test.JwksSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			responseWriter.WriteHeader(http.StatusInternalServerError)
			logger.Infof("attempt %v: request to %s, response %v", counter, test.JwksSubPath, http.StatusInternalServerError)
			counter++
		})

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, scenarios[0].claims)
	_, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.ErrorContains(t, vErr, "token is unverifiable: error while executing keyfunc: key not found \"kid-1\"\nfailed keyfunc: could not read JWK from storage")
}
func TestJwksResponseInternalServerErrorFourAttempts(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(t.Context())
	defer func() { cancelCtx(); time.Sleep(time.Millisecond * 10) }()
	beforeEach(t)
	defer afterEach(t)

	serviceAccountToken := test.CreateServiceAccountToken(t, test.GetMockServerUrl(), test.DefaultKid, defaultKey)
	err := storage.SaveTokenValue(serviceAccountToken)
	require.NoError(t, err)
	test.AddDefaultKubernetesProviderHandler(serviceAccountToken, test.GetMockServerUrl())
	counter := 0
	test.AddHandler(test.Contains(test.JwksSubPath),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if counter < 4 {
				responseWriter.WriteHeader(http.StatusInternalServerError)
				logger.Infof("attempt %v: request to %s, response %v", counter, test.JwksSubPath, http.StatusInternalServerError)
			} else {
				var keySet []JWKMarshal
				for kid, privateKey := range defaultKeys {
					keySet = append(keySet, JWKMarshal{
						KTY: "RSA",
						KID: kid,
						ALG: ALG(jwt.SigningMethodRS256.Alg()),
						USE: "sig",
						N:   test.ToHexBase64(privateKey.N),
						E:   test.ToHexBase64(big.NewInt(int64(privateKey.E))),
					})
				}
				jwks := &JWKSMarshal{
					Keys: keySet,
				}
				responseBody, _ := json.Marshal(jwks)
				_, _ = responseWriter.Write(responseBody)
				logger.Infof("attempt %v: request to %s, response %v:%s", counter, test.JwksSubPath, http.StatusOK, string(responseBody))
			}
			counter++
		})

	maasTokenVerifier, err := NewKubernetesVerifier(ctx, tokensource.AudienceMaaS)
	require.NoError(t, err)

	claims := token.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Audience:  jwt.ClaimStrings{tokensource.AudienceMaaS},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    test.GetMockServerUrl(),
		},
		KubernetesIo: token.KubernetesIoClaim{
			Namespace: test.Namespace,
			ServiceAccount: token.ServiceAccountClaim{
				Name: test.ServiceAccount,
				Uid:  test.Uuid,
			},
		},
	}

	rawToken := test.CreateSignedTokenString(t, test.DefaultKid, defaultKey, claims)
	actualToken, vErr := maasTokenVerifier.Verify(ctx, rawToken)
	require.Nil(t, vErr)
	actualKubernetesIoClaim, getClaimErr := token.GetKubernetesIo(actualToken)
	assert.Nil(t, getClaimErr)
	assert.Equal(t, claims.KubernetesIo, actualKubernetesIoClaim, "unexpected kubernetes.io claim")
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
