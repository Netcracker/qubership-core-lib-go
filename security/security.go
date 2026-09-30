package security

import (
	"context"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

// GetTokenFunc returns a function that gets an M2M token in the mode that [MustM2MAuthModeFromEnv] reads: the
// token of the registered [TokenProvider] in legacy mode, and the Kubernetes token with the netcracker audience in
// k8s mode. In hybrid mode the function returns the Kubernetes token, or the [TokenProvider] token when the
// Kubernetes token cannot be read.
//
// GetTokenFunc panics when M2M_AUTH_MODE has an unsupported value, and in legacy and hybrid modes when no
// [TokenProvider] is registered.
func GetTokenFunc() func(ctx context.Context) (string, error) {
	mode := MustM2MAuthModeFromEnv()
	k8sToken := func(ctx context.Context) (string, error) {
		return tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	}
	if !mode.UsesLegacyToken() {
		return k8sToken
	}
	legacyToken := serviceloader.MustLoad[TokenProvider]().GetToken
	if !mode.UsesK8sToken() {
		return legacyToken
	}
	return func(ctx context.Context) (string, error) {
		token, err := k8sToken(ctx)
		if err != nil {
			logger.WarnC(ctx, "cannot get the Kubernetes M2M token, sending the legacy M2M token instead: %v", err)
			return legacyToken(ctx)
		}
		return token, nil
	}
}
