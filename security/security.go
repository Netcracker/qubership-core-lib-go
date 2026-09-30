package security

import (
	"context"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

// GetTokenFunc returns a function that gets an M2M token in the mode set by M2M_AUTH_MODE. In hybrid mode the function
// returns the [TokenProvider] token when the Kubernetes token cannot be read. GetTokenFunc panics when M2M_AUTH_MODE
// has an unsupported value.
func GetTokenFunc() func(ctx context.Context) (string, error) {
	mode := MustReadM2MAuthMode()
	k8sToken := func(ctx context.Context) (string, error) {
		return tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
	}
	switch mode {
	case M2MAuthModeK8s:
		return k8sToken
	case M2MAuthModeHybrid:
		legacyToken := serviceloader.MustLoad[TokenProvider]().GetToken
		return func(ctx context.Context) (string, error) {
			token, err := k8sToken(ctx)
			if err != nil {
				logger.WarnC(ctx, "cannot get the Kubernetes M2M token, sending the legacy M2M token instead: %v", err)
				return legacyToken(ctx)
			}
			return token, nil
		}
	default:
		return serviceloader.MustLoad[TokenProvider]().GetToken
	}
}
