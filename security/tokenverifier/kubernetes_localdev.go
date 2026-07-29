package tokenverifier

import (
	"context"
	"fmt"
	"net/http"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
	"golang.org/x/time/rate"
)

func newLocalDevKubernetesVerifier(ctx context.Context, audience string, override Override, validations ...Validation) (Verifier, error) {
	validations = append(validations, ValidateIssuedAt)

	trustedIssuer, err := localdev.ResolveIssuerClaimFromDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve Kubernetes issuer in local-dev: %w", err)
	}
	jwksURL, err := localdev.JwksURL()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve JWKS URL in local-dev: %w", err)
	}

	baseTransport, err := localDevBaseTransport()
	if err != nil {
		return nil, err
	}
	tokenFn := func() (string, error) {
		return localdev.UserToken()
	}
	httpClient := CreateHttpClient(newLocalDevTransport(tokenFn, baseTransport))

	refreshInterval := defaultRefreshInterval
	if override.RefreshInterval > 0 {
		refreshInterval = override.RefreshInterval
	}
	refreshUnknownKID := rate.NewLimiter(rate.Every(defaultRateLimiterInterval), defaultRateLimiterLimit)
	if override.RefreshUnknownKID != nil {
		refreshUnknownKID = override.RefreshUnknownKID
	}

	keyFunc, err := CreateKeyFunctionFromJwksURL(ctx, jwksURL, KeyFuncOptions{
		HttpClient:        &httpClient,
		RefreshInterval:   refreshInterval,
		RefreshUnknownKID: refreshUnknownKID,
	})
	if err != nil {
		return nil, err
	}

	return NewVerifier(
		createJwtParser(trustedIssuer, audience),
		keyFunc,
		validations...,
	)
}

func localDevBaseTransport() (http.RoundTripper, error) {
	client, err := localdev.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create local-dev HTTP client from kubeconfig: %w", err)
	}
	if client.Transport != nil {
		if transport, ok := client.Transport.(*http.Transport); ok {
			return transport.Clone(), nil
		}
		return client.Transport, nil
	}
	return http.DefaultTransport, nil
}
