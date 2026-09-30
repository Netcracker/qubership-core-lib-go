package rest

import (
	"context"
	"fmt"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

// M2MTokens picks the token for an M2M request sent by an HTTP client other than [M2MRestClient], and remembers the
// targets that need the legacy M2M token in hybrid mode, the same way [M2MRestClient] does. Targets are keyed like
// the [M2MRestClient] cache: by host, or by the service path behind the internal gateway. It is safe for concurrent
// use.
//
// A caller that gets a 401 response to a request sent with a token for which [M2MTokens.Token] allowed the fallback
// resends the request with [M2MTokens.LegacyToken], and calls [M2MTokens.UseLegacyToken] when the resent request
// succeeds.
type M2MTokens struct {
	mode                    security.M2MAuthMode
	k8sToken                func(ctx context.Context) (string, error)
	legacyToken             func(ctx context.Context) (string, error)
	legacyTargets           cache.Cache[string, empty]
	internalGatewayHostname string
}

// NewM2MTokens returns M2MTokens for the mode that [security.MustM2MAuthModeFromEnv] reads. The Kubernetes token has
// the netcracker audience. In legacy and hybrid modes NewM2MTokens panics when no [security.TokenProvider] is
// registered.
func NewM2MTokens() *M2MTokens {
	mode := security.MustM2MAuthModeFromEnv()
	tokens := &M2MTokens{
		mode: mode,
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
// Kubernetes token; a 401 response to such a request may then be retried with [M2MTokens.LegacyToken].
//
// In hybrid mode Token returns the legacy M2M token when targetUrl was passed to [M2MTokens.UseLegacyToken] or the
// Kubernetes token cannot be read. Token returns an error when targetUrl cannot be parsed or no token can be read.
func (t *M2MTokens) Token(ctx context.Context, targetUrl string) (token string, fallbackAllowed bool, err error) {
	if !t.mode.UsesK8sToken() {
		token, err = t.legacyToken(ctx)
		return token, false, err
	}
	if !t.mode.UsesLegacyToken() {
		token, err = t.k8sToken(ctx)
		return token, false, err
	}
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

// LegacyToken returns the legacy M2M token. It returns an error in k8s mode, which never sends that token.
func (t *M2MTokens) LegacyToken(ctx context.Context) (string, error) {
	if t.legacyToken == nil {
		return "", fmt.Errorf("legacy M2M token is not used when %s is %s", security.M2MAuthModeEnv, t.mode)
	}
	return t.legacyToken(ctx)
}

// UseLegacyToken makes [M2MTokens.Token] return the legacy M2M token for targetUrl for the next 5 hours, or until
// 400 other targets push it out of the cache. Only hybrid mode reads the remembered targets. UseLegacyToken does
// nothing when targetUrl cannot be parsed.
func (t *M2MTokens) UseLegacyToken(targetUrl string) {
	key, err := calculateCacheKey(t.internalGatewayHostname, targetUrl)
	if err != nil {
		return
	}
	t.legacyTargets.Add(key, empty{})
}
