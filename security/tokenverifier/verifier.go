package tokenverifier

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/failsafe-go/failsafe-go/failsafehttp"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
)

const (
	oidcTokenAud = "oidc-token"
)

var logger = logging.GetLogger("oidc")

type Claims struct {
	jwt.RegisteredClaims
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

type getTokenFunc func() (string, error)

func New(ctx context.Context, audience string) (*verifier, error) {
	return newVerifier(ctx, audience, func() (string, error) {
		return tokensource.GetToken(ctx, oidcTokenAud)
	})
}

func newVerifier(ctx context.Context, audience string, getToken getTokenFunc) (*verifier, error) {
	secureTransport := newSecureTransport(getToken)
	policy := failsafehttp.NewRetryPolicyBuilder().
		WithMaxAttempts(5).
		WithBackoff(time.Millisecond*500, time.Second*15).
		Build()
	secureClient := http.Client{
		Transport: failsafehttp.NewRoundTripper(secureTransport, policy),
	}
	ctx = oidc.ClientContext(ctx, &secureClient)

	rawToken, err := getToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get k8s projected volume token oidc: %w", err)
	}
	issuer, err := getIssuer(rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get jwt issuer from the k8s projected volume token: %w", err)
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

func getIssuer(rawToken string) (string, error) {
	claims := jwt.RegisteredClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(rawToken, &claims)
	if err != nil {
		return "", fmt.Errorf("invalid jwt: %w", err)
	}
	if claims.Issuer == "" {
		return "", fmt.Errorf("jwt token does not have issuer value: %w", err)
	}
	return claims.Issuer, nil
}
