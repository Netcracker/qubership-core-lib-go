package tokensource

import (
	"context"

	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

func init() {
	serviceloader.Register(0, &DefaultTokenFileProvider{})
}

type TokenSource interface {
	GetAudienceToken(ctx context.Context, audience TokenAudience) (string, error)
	GetServiceAccountToken(ctx context.Context) (string, error)
}

// GetAudienceToken gets token by audience. Do not store the token. Always call GetAudienceToken again to get a fresh token.
func GetAudienceToken(ctx context.Context, audience TokenAudience) (string, error) {
	return serviceloader.MustLoad[TokenSource]().GetAudienceToken(ctx, audience)
}

// GetServiceAccountToken gets the default service account token located at /var/run/secrets/kubernetes.io/serviceaccount. Do not store the token. Always call GetServiceAccountToken again to get a fresh token.
func GetServiceAccountToken(ctx context.Context) (string, error) {
	return serviceloader.MustLoad[TokenSource]().GetServiceAccountToken(ctx)
}
