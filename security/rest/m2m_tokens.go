package rest

import (
	"context"
	"fmt"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

// M2MTokens gives the M2M token to HTTP clients other than [M2MRestClient] and keeps the same hybrid-mode cache of
// targets that need the legacy M2M token. On a 401 response to a request whose token allowed the fallback, the caller
// resends it with [M2MTokens.LegacyToken] and calls [M2MTokens.UseLegacyToken] if the resent request succeeds.
type M2MTokens struct {
	m2mAuthMode             security.M2MAuthMode
	k8sToken                func(ctx context.Context) (string, error)
	legacyToken             func(ctx context.Context) (string, error)
	legacyTargets           cache.Cache[string, empty]
	internalGatewayHostname string
}

// NewM2MTokens returns M2MTokens whose Kubernetes token has the netcracker audience.
func NewM2MTokens() *M2MTokens {
	mode := security.MustReadM2MAuthMode()
	tokens := &M2MTokens{
		m2mAuthMode: mode,
		k8sToken: func(ctx context.Context) (string, error) {
			return tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
		},
		legacyTargets:           newUrlCache(),
		internalGatewayHostname: internalGatewayHostname(),
	}
	if mode.UsesLegacyToken() {
		tokens.legacyToken = serviceloader.MustLoad[security.TokenProvider]().GetToken
	}
	return tokens
}

// Token returns the token for a request to targetUrl. fallbackAllowed is true only in hybrid mode when token is the
// Kubernetes token. In hybrid mode Token returns the legacy M2M token for a target passed to
// [M2MTokens.UseLegacyToken] or when the Kubernetes token cannot be read, and returns an error when targetUrl cannot
// be parsed.
func (t *M2MTokens) Token(ctx context.Context, targetUrl string) (token string, fallbackAllowed bool, err error) {
	switch t.m2mAuthMode {
	case security.M2MAuthModeK8s:
		token, err = t.k8sToken(ctx)
		return token, false, err
	case security.M2MAuthModeHybrid:
		return t.hybridToken(ctx, targetUrl)
	default:
		token, err = t.legacyToken(ctx)
		return token, false, err
	}
}

func (t *M2MTokens) hybridToken(ctx context.Context, targetUrl string) (token string, fallbackAllowed bool, err error) {
	key, err := calculateCacheKey(t.internalGatewayHostname, targetUrl)
	if err != nil {
		return "", false, fmt.Errorf("url can not be parsed: %w", err)
	}
	if _, ok := t.legacyTargets.Get(key); ok {
		token, err = t.legacyToken(ctx)
		return token, false, err
	}
	token, err = t.k8sToken(ctx)
	if err != nil {
		logger.WarnC(ctx, "cannot get the Kubernetes M2M token for %s, sending the legacy M2M token instead: %v", targetUrl, err)
		token, err = t.legacyToken(ctx)
		return token, false, err
	}
	return token, true, nil
}

// LegacyToken returns an error in k8s mode, which never sends the legacy M2M token.
func (t *M2MTokens) LegacyToken(ctx context.Context) (string, error) {
	if t.legacyToken == nil {
		return "", fmt.Errorf("legacy M2M token is not used when %s is %s", security.M2MAuthModeEnv, t.m2mAuthMode)
	}
	return t.legacyToken(ctx)
}

// UseLegacyToken makes [M2MTokens.Token] in hybrid mode return the legacy M2M token for targetUrl for the next 5 hours,
// or until 400 other targets push it out of the cache.
func (t *M2MTokens) UseLegacyToken(targetUrl string) {
	key, err := calculateCacheKey(t.internalGatewayHostname, targetUrl)
	if err != nil {
		return
	}
	t.legacyTargets.Add(key, empty{})
}
