package tokenverifier

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
)

const (
	retryMaxAttempts     = 5
	retryBackoffDelay    = time.Millisecond * 500
	retryBackoffMaxDelay = time.Second * 15
	retryJitter          = time.Millisecond * 100
	leewaySec            = 30
	leeway               = leewaySec * time.Second
)

type tokenFunction func() (string, error)

func NewKubernetesVerifier(ctx context.Context, audience string, validations ...Validation) (Verifier, error) {
	validations = append(validations, ValidateIssuedAt)
	return newKubernetesVerifier(ctx, audience, func() (string, error) {
		return tokensource.GetServiceAccountToken(ctx)
	}, validations...)
}
func newKubernetesVerifier(ctx context.Context, audience string, kubernetesApiToken tokenFunction, validations ...Validation) (Verifier, error) {
	trustedIssuer, err := getTrustedIssuer(kubernetesApiToken)
	if err != nil {
		return nil, err
	}
	httpClient := CreateHttpClient(newSecureTransport(kubernetesApiToken))
	keyFunc, err := CreateKeyFunction(ctx, httpClient, trustedIssuer)
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
	_, _, err = jwt.NewParser().ParseUnverified(rawToken, &claims)
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
