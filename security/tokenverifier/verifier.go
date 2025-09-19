package tokenverifier

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
)

const (
	oidcTokenDir = "/var/run/secrets/oidc-token"
)

var logger = logging.GetLogger("oidc")

type Claims struct {
	jwt.Claims
	Kubernetes K8sClaims `json:"kubernetes.io"`
}

type K8sClaims struct {
	Namespace      string         `json:"namespace,omitempty"`
	ServiceAccount ServiceAccount `json:"serviceaccount"`
}

type ServiceAccount struct {
	Name string `json:"name,omitempty"`
	Uid  string `json:"uid,omitempty"`
}

type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Claims, error)
}

type verifier struct {
	oidcVerifier *oidc.IDTokenVerifier
}

func NewDefault(ctx context.Context, audience string) (*verifier, error) {
	fts, err := tokensource.New(ctx, oidcTokenDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize a file token source for oidcVerifier: %w", err)
	}
	return New(ctx, audience, fts)
}

func New(ctx context.Context, audience string, tokenSource tokensource.TokenSource) (*verifier, error) {
	c, err := newSecureHttpClient(tokenSource)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure http client: %w", err)
	}
	ctx = oidc.ClientContext(ctx, c)

	issuer, err := getIssuer(tokenSource)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer from the jwt token: %w", err)
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc provider: %w", err)
	}
	v := provider.Verifier(&oidc.Config{ClientID: audience})

	return &verifier{
		oidcVerifier: v,
	}, nil
}

func (vf *verifier) Verify(ctx context.Context, rawToken string) (*Claims, error) {
	token, err := vf.oidcVerifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	claims := Claims{}
	err = token.Claims(&claims)
	if err != nil {
		return nil, fmt.Errorf("required claims not present: %w", err)
	}
	return &claims, nil
}

func getIssuer(ts tokensource.TokenSource) (string, error) {
	rawToken, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get oidc token: %w", err)
	}
	token, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256, "none"})
	if err != nil {
		return "", fmt.Errorf("invalid jwt: %w", err)
	}
	claims := Claims{}
	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return "", fmt.Errorf("invalid jwt: %w", err)
	}
	if claims.Issuer == "" {
		return "", fmt.Errorf("jwt token does not have issuer value: %w", err)
	}
	return claims.Issuer, nil
}
