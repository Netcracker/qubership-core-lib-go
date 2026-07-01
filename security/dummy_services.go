package security

import (
	"context"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

var logger logging.Logger

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

type TokenProvider interface {
	GetToken(ctx context.Context) (string, error)
	ValidateToken(ctx context.Context, token string) (*jwt.Token, error)
	GetClaimValue(token *jwt.Token, key string) (interface{}, error)
	GetTokenAttribute(ctx context.Context, claim string) (string, error)
}

type DummyToken struct {
}

type TlsConfig interface {
	IsTlsEnabled() bool
}

func init() {
	logger = logging.GetLogger("dummy-services")
}

func (s *DummyToken) GetToken(ctx context.Context) (string, error) {
	logger.Info("Empty token value implementation")
	return "", nil
}

func (s *DummyToken) GetClaimValue(token *jwt.Token, key string) (interface{}, error) {
	logger.Info("Claim value 'nil' sent for key [%s] from dummy service", key)
	return nil, nil
}

func (s *DummyToken) ValidateToken(ctx context.Context, token string) (*jwt.Token, error) {
	logger.Info("DummyToken parsed unverified")
	parser := jwt.Parser{}
	parsedToken, _, _ := parser.ParseUnverified(token, jwt.MapClaims{})
	return parsedToken, nil
}

func (s *DummyToken) GetTokenAttribute(ctx context.Context, claim string) (string, error) {
	logger.Info("Empty token attribute implementation")
	return "", nil
}
