package tokenverifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/failsafe-go/failsafe-go/failsafehttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
)

const (
	retryMaxAttempts     = 5
	retryBackoffDelay    = time.Millisecond * 500
	retryBackoffMaxDelay = time.Second * 15
	retryJitter          = time.Millisecond * 100
)

type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*jwt.Token, error)
}

type KubernetesVerifier struct {
	parser      *jwt.Parser
	keyFunc     keyfunc.Keyfunc
	validations []Validation
}

type getTokenFunc func() (string, error)

func NewKubernetesVerifier(ctx context.Context, audience string, options ...VerifierOptions) (Verifier, error) {
	return newKubernetesVerifier(ctx, audience, func() (string, error) {
		return tokensource.GetServiceAccountToken(ctx)
	}, options)
}
func (vf *KubernetesVerifier) Verify(ctx context.Context, rawToken string) (*jwt.Token, error) {
	token, err := vf.parser.Parse(rawToken, vf.keyFunc.KeyfuncCtx(ctx))
	if err != nil {
		return nil, err
	}

	for _, validation := range vf.validations {
		if ok, validationErr := validation(token); !ok {
			return nil, validationErr
		}
	}
	return token, nil
}
func newKubernetesVerifier(ctx context.Context, audience string, getToken getTokenFunc, options []VerifierOptions) (*KubernetesVerifier, error) {
	trustedIssuer, err := getTrustedIssuer(getToken)
	if err != nil {
		return nil, err
	}
	keyFunc, err := newKeyFunction(ctx, trustedIssuer, getToken)
	if err != nil {
		return nil, err
	}
	v := &KubernetesVerifier{
		parser:  newJwtParser(trustedIssuer, audience),
		keyFunc: keyFunc,
	}
	for _, option := range options {
		option(v)
	}

	return v, nil
}
func getTrustedIssuer(getToken getTokenFunc) (string, error) {
	rawToken, err := getToken()
	if err != nil {
		return "", fmt.Errorf("failed to acquire token for kubernetes API (the possible cause is missing kubernetes service account for the microservice.): %w", err)
	}
	claims := jwt.RegisteredClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(rawToken, &claims)
	if err != nil {
		return "", fmt.Errorf("invalid jwt: %w", err)
	}
	if claims.Issuer == "" {
		return "", fmt.Errorf("jwt does not have the issuer claim value: %w", err)
	}
	return claims.Issuer, nil
}
func newKeyFunction(ctx context.Context, trustedIssuer string, getToken getTokenFunc) (keyfunc.Keyfunc, error) {
	httpClient := newHttpClient(getToken)
	request, err := http.NewRequest(http.MethodGet, oidc.GetProviderUrl(trustedIssuer), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc request: %w", err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to send oidc request (the possible cause is outdated base image without kubernetes service account ca.crt, please check your base image version.): %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read oidc response body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", response.Status, body)
	}
	var providerResponse oidc.ProviderResponse
	err = unmarshalResponse(response, body, &providerResponse)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}
	return keyfunc.NewDefaultOverrideCtx(
		ctx,
		[]string{providerResponse.JwksUri},
		keyfunc.Override{Client: &httpClient},
	)
}
func newJwtParser(trustedIssuer, audience string) *jwt.Parser {
	var opts = []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30 * time.Second),
		jwt.WithIssuer(trustedIssuer),
		jwt.WithAudience(audience)}

	return jwt.NewParser(opts...)
}
func newHttpClient(getToken getTokenFunc) http.Client {
	return http.Client{
		Transport: failsafehttp.NewRoundTripper(
			newSecureTransport(getToken),
			failsafehttp.NewRetryPolicyBuilder().
				WithMaxAttempts(retryMaxAttempts).
				WithBackoff(retryBackoffDelay, retryBackoffMaxDelay).
				WithJitter(retryJitter).
				HandleIf(isRetryNeeded).
				Build(),
		),
	}
}
func isRetryNeeded(response *http.Response, err error) bool {
	_, isUrlErr := err.(*url.Error)
	switch {
	case isUrlErr:
		return false
	case err != nil:
		return true
	case isStatus5xx(response.StatusCode):
		return true
	default:
		return false
	}
}
func isStatus5xx(code int) bool {
	statusGroup := code / 100
	if statusGroup == 5 {
		return true
	}
	return false
}
func unmarshalResponse(response *http.Response, body []byte, result interface{}) error {
	err := json.Unmarshal(body, &result)
	if err == nil {
		return nil
	}
	contentType := response.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", contentType, err)
}
