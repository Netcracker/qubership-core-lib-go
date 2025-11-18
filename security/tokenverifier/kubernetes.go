package tokenverifier

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	qubetoken "github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"golang.org/x/time/rate"
)

const (
	leewaySec                  = 30
	leeway                     = time.Second * leewaySec
	defaultRefreshInterval     = time.Hour * 24
	defaultRateLimiterInterval = time.Minute * 5
	defaultRateLimiterLimit    = 1
)

type tokenFunction func() (string, error)

func NewKubernetesVerifierOverride(ctx context.Context, audience string, override Override, validations ...Validation) (Verifier, error) {
	validations = append(validations, ValidateIssuedAt)
	return newKubernetesVerifier(ctx, audience, func() (string, error) {
		return tokensource.GetServiceAccountToken(ctx)
	}, override, validations...)
}
func NewKubernetesVerifier(ctx context.Context, audience string, validations ...Validation) (Verifier, error) {
	return NewKubernetesVerifierOverride(
		ctx,
		audience,
		Override{RefreshInterval: defaultRefreshInterval, RefreshUnknownKID: rate.NewLimiter(rate.Every(defaultRateLimiterInterval), defaultRateLimiterLimit)},
		validations...)
}
func newKubernetesVerifier(ctx context.Context, audience string, kubernetesApiToken tokenFunction, override Override, validations ...Validation) (Verifier, error) {
	trustedIssuer, err := getTrustedIssuer(kubernetesApiToken)
	if err != nil {
		return nil, err
	}
	httpClient := CreateHttpClient(newSecureTransport(kubernetesApiToken))
	refreshInterval := defaultRefreshInterval
	if override.RefreshInterval > 0 {
		refreshInterval = override.RefreshInterval
	}
	refreshUnknownKID := rate.NewLimiter(rate.Every(defaultRateLimiterInterval), defaultRateLimiterLimit)
	if override.RefreshUnknownKID != nil {
		refreshUnknownKID = override.RefreshUnknownKID
	}
	keyFunc, err := CreateKeyFunction(ctx, KeyFuncOptions{
		HttpClient:        &httpClient,
		TrustedIssuer:     trustedIssuer,
		RefreshInterval:   refreshInterval,
		RefreshUnknownKID: refreshUnknownKID})
	if err != nil {
		return nil, err
	}
	return NewVerifier(
		createJwtParser(trustedIssuer, audience),
		keyFunc,
		validations...,
	)
}
func getTrustedIssuer(kubernetesApiToken tokenFunction) (string, error) {
	rawToken, err := kubernetesApiToken()
	if err != nil {
		return "", fmt.Errorf("failed to acquire token for kubernetes API (the possible cause is missing kubernetes service account for the microservice.): %w", err)
	}
	claims := jwt.RegisteredClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(rawToken, &claims) //NOSONAR
	if err != nil {
		return "", fmt.Errorf("invalid jwt: %w", err)
	}
	if claims.Issuer == "" {
		return "", fmt.Errorf("jwt does not have the issuer claim value")
	}
	return claims.Issuer, nil
}
func createJwtParser(trustedIssuer, audience string) *jwt.Parser {
	var opts = []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		jwt.WithIssuer(trustedIssuer),
		jwt.WithAudience(audience)}
	return jwt.NewParser(opts...)
}
func ValidateIssuedAt(token *jwt.Token) error {
	issuedAt, err := qubetoken.GetIssuedAt(token)
	if err != nil {
		return err
	}
	current := time.Now()
	if current.Before(issuedAt.Add(-leeway)) {
		return fmt.Errorf("%w: current time is before issuedAt more than %v sec", jwt.ErrTokenUsedBeforeIssued, leewaySec)
	}
	return nil
}
