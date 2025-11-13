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

func GetAudienceToken(ctx context.Context, audience TokenAudience) (string, error) {
	return serviceloader.MustLoad[TokenSource]().GetAudienceToken(ctx, audience)
}

func GetServiceAccountToken(ctx context.Context) (string, error) {
	return serviceloader.MustLoad[TokenSource]().GetServiceAccountToken(ctx)
}
