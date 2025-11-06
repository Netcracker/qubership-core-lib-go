package tokenverifier

import (
	"context"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"golang.org/x/time/rate"
)

var (
	logger = logging.GetLogger("token-verifier")
)

type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*jwt.Token, error)
}

type Override struct {
	RefreshInterval   time.Duration
	RefreshUnknownKID *rate.Limiter
}

type TokenVerifier struct {
	parser      *jwt.Parser
	keyFunc     keyfunc.Keyfunc
	validations []Validation
}

type Validation func(token *jwt.Token) error

func NewVerifier(parser *jwt.Parser, keyFunc keyfunc.Keyfunc, validations ...Validation) (*TokenVerifier, error) {
	return &TokenVerifier{
		parser:      parser,
		keyFunc:     keyFunc,
		validations: validations,
	}, nil
}
func (vf *TokenVerifier) Verify(ctx context.Context, rawToken string) (*jwt.Token, error) {
	token, err := vf.parser.Parse(rawToken, vf.keyFunc.KeyfuncCtx(ctx))
	if err != nil {
		return nil, err
	}
	for _, validation := range vf.validations {
		if validationErr := validation(token); validationErr != nil {
			return nil, validationErr
		}
	}
	return token, nil
}
