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
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	qubetoken "github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"
)

var(
	logger = logging.GetLogger("token-verifier")
)

type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*jwt.Token, error)
}

type TokenVerifier struct {
	parser      *jwt.Parser
	keyFunc     keyfunc.Keyfunc
	validations []Validation
}

type Validation func(token *jwt.Token) error

func NewVerifier(parser *jwt.Parser, keyFunc keyfunc.Keyfunc, validations ...Validation) (*TokenVerifier, error) {
	return &TokenVerifier{
		parser:      parser,
		keyFunc:     keyFunc,
		validations: validations,
	}, nil
}
func (vf *TokenVerifier) Verify(ctx context.Context, rawToken string) (*jwt.Token, error) {
	token, err := vf.parser.Parse(rawToken, vf.keyFunc.KeyfuncCtx(ctx))
	if err != nil {
		return nil, err
	}
	for _, validation := range vf.validations {
		if validationErr := validation(token); validationErr != nil {
			return nil, validationErr
		}
	}
	return token, nil
}
func CreateKeyFunction(ctx context.Context, httpClient http.Client, issuer string) (keyfunc.Keyfunc, error) {
	issuerUrl, err := oidc.GetProviderUrl(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer url: %w", err)
	}
	request, err := http.NewRequest(http.MethodGet, issuerUrl, nil)
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
		return nil, fmt.Errorf("unexpected response http status code %s", response.Status)
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
func unmarshalResponse(response *http.Response, body []byte, result interface{}) error {
	err := json.Unmarshal(body, &result)
	if err == nil {
		return nil
	}
	contentType := response.Header.Get("Content-Type")
	mediaType, _, cerr := mime.ParseMediaType(contentType)
	if cerr == nil && mediaType == "application/json" {
		return fmt.Errorf("got content-type = application/json, but could not unmarshal as json: %w", err)
	}
	return fmt.Errorf("expected content-type = application/json, got %q: %w", contentType, err)
}
func CreateHttpClient(innerRoundTripper http.RoundTripper) http.Client {
	return http.Client{
		Transport: failsafehttp.NewRoundTripper(
			innerRoundTripper,
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
func ValidateIssuedAt(token *jwt.Token) error {
	issuedAt, err := qubetoken.GetIssuedAt(token)
	if err != nil {
		return err
	}
	current := time.Now()
	if current.Before(issuedAt.Add(-leeway)) {
		return utils.NewError(fmt.Sprintf("current time is before issuedAt more than %v sec", leewaySec), jwt.ErrTokenUsedBeforeIssued)
	}
	return nil
}
