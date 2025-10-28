package security

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var logger logging.Logger

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
