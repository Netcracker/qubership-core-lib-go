package security

import (
	"context"
	"os"
	"strconv"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

// GetTokenFunc returns a function to get an m2m token. If KUBERNETES_M2M_ENABLED is enabled it returns a k8s m2m token. Otherwise a keycloak token
func GetTokenFunc() func(ctx context.Context) (string, error) {
	rawK8sM2mEnabled := os.Getenv("KUBERNETES_M2M_ENABLED")
	k8sM2mEnabled, err := strconv.ParseBool(rawK8sM2mEnabled)
	if err != nil && rawK8sM2mEnabled != "" {
		logger.Warn("failed to parse KUBERNETES_M2M_ENABLED env var: %s", rawK8sM2mEnabled)
	}
	if k8sM2mEnabled {
		return func(ctx context.Context) (string, error) {
			return tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
		}
	}
	return serviceloader.MustLoad[TokenProvider]().GetToken
}
