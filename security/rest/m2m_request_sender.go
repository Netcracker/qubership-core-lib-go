package rest

import (
	"context"
	"fmt"
	"net/http"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

// SendFunc sends one request with token and returns the response status code, or 0 when no response arrived.
type SendFunc func(token string) (statusCode int, err error)

// M2MRequestSender sends requests of HTTP and websocket clients other than [M2MRestClient] with the M2M token of the
// mode set by M2M_AUTH_MODE. In hybrid mode it resends a request with the legacy M2M token when the Kubernetes token
// cannot be read or the receiver answers 401, and then keeps sending the legacy token to that target, as
// [M2MRestClient] does.
type M2MRequestSender struct {
	m2mAuthMode             security.M2MAuthMode
	k8sToken                func(ctx context.Context) (string, error)
	legacyToken             func(ctx context.Context) (string, error)
	legacyTargets           cache.Cache[string, empty]
	internalGatewayHostname string
}

// NewM2MRequestSender returns a sender whose Kubernetes token has the netcracker audience. It panics when
// M2M_AUTH_MODE has an unsupported value.
func NewM2MRequestSender() *M2MRequestSender {
	mode := security.MustReadM2MAuthMode()
	sender := &M2MRequestSender{
		m2mAuthMode: mode,
		k8sToken: func(ctx context.Context) (string, error) {
			return tokensource.GetAudienceToken(ctx, tokensource.AudienceNetcracker)
		},
		legacyTargets:           newUrlCache(),
		internalGatewayHostname: internalGatewayHostname(),
	}
	if mode.UsesLegacyToken() {
		sender.legacyToken = serviceloader.MustLoad[security.TokenProvider]().GetToken
	}
	return sender
}

// Send calls send with the M2M token for targetUrl and returns the error of its last call. When a token cannot be read,
// Send returns that error instead of calling send with it. In hybrid mode send is called a second time, with the legacy
// M2M token, after a 401 to the Kubernetes token, even when the first call also returned an error.
func (s *M2MRequestSender) Send(ctx context.Context, targetUrl string, send SendFunc) error {
	switch s.m2mAuthMode {
	case security.M2MAuthModeK8s:
		return sendWithToken(ctx, s.k8sToken, send)
	case security.M2MAuthModeHybrid:
		return s.sendHybrid(ctx, targetUrl, send)
	default:
		return sendWithToken(ctx, s.legacyToken, send)
	}
}

func sendWithToken(ctx context.Context, getToken func(ctx context.Context) (string, error), send SendFunc) error {
	token, err := getToken(ctx)
	if err != nil {
		return fmt.Errorf("cannot get the M2M token: %w", err)
	}
	_, err = send(token)
	return err
}

func (s *M2MRequestSender) sendHybrid(ctx context.Context, targetUrl string, send SendFunc) error {
	key, err := calculateCacheKey(s.internalGatewayHostname, targetUrl)
	if err != nil {
		return fmt.Errorf("url can not be parsed: %w", err)
	}
	if _, ok := s.legacyTargets.Get(key); ok {
		return s.sendWithLegacyToken(ctx, key, send)
	}
	token, err := s.k8sToken(ctx)
	if err != nil {
		logger.WarnC(ctx, "cannot get the Kubernetes M2M token for %s, sending the legacy M2M token instead: %v", targetUrl, err)
		return s.sendWithLegacyToken(ctx, key, send)
	}
	status, err := send(token)
	if status != http.StatusUnauthorized {
		return err
	}
	logger.DebugC(ctx, "%s answered 401 to the Kubernetes M2M token, resending the request with the legacy M2M token", targetUrl)
	return s.sendWithLegacyToken(ctx, key, send)
}

func (s *M2MRequestSender) sendWithLegacyToken(ctx context.Context, key string, send SendFunc) error {
	token, err := s.legacyToken(ctx)
	if err != nil {
		return fmt.Errorf("cannot get the legacy M2M token: %w", err)
	}
	status, err := send(token)
	if err == nil && status < http.StatusBadRequest {
		s.legacyTargets.Add(key, empty{})
	}
	return err
}
