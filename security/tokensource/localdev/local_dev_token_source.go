package localdev

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
)

var localDevTokenLogger = logging.GetLogger("local-dev-token-source")

type cachedAudienceToken struct {
	token        string
	refreshAfter time.Time
}

func (c cachedAudienceToken) valid() bool {
	return time.Now().Before(c.refreshAfter)
}

// LocalDevTokenSource mints Kubernetes audience tokens via TokenRequest when local-dev is enabled.
type LocalDevTokenSource struct {
	fallback tokensource.TokenSource

	mu     sync.Mutex
	client *TokenRequestClient
	creds  *KubeConfigCredentials
	cache  map[string]cachedAudienceToken
}

// NewLocalDevTokenSource creates a token source with file-based fallback.
func NewLocalDevTokenSource() *LocalDevTokenSource {
	return &LocalDevTokenSource{
		fallback: &tokensource.DefaultTokenFileProvider{},
		cache:    make(map[string]cachedAudienceToken),
	}
}

func (s *LocalDevTokenSource) GetAudienceToken(ctx context.Context, audience tokensource.TokenAudience) (string, error) {
	if !IsEnabled() {
		return s.fallback.GetAudienceToken(ctx, audience)
	}
	if string(audience) == "" {
		return "", fmt.Errorf("audience is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cached, ok := s.cache[string(audience)]
	if ok && cached.valid() {
		return cached.token, nil
	}

	result, err := s.requestToken(string(audience))
	if err != nil {
		return "", err
	}

	refreshAfter := result.ExpiresAt.Add(-tokenCacheExpirySkew)
	s.cache[string(audience)] = cachedAudienceToken{
		token:        result.Token,
		refreshAfter: refreshAfter,
	}
	return result.Token, nil
}

func (s *LocalDevTokenSource) GetServiceAccountToken(ctx context.Context) (string, error) {
	if !IsEnabled() {
		return s.fallback.GetServiceAccountToken(ctx)
	}
	creds, err := s.loadCredentials()
	if err != nil {
		return "", err
	}
	return creds.UserToken, nil
}

func (s *LocalDevTokenSource) requestToken(audience string) (*TokenRequestResult, error) {
	namespace, err := RequireNamespace()
	if err != nil {
		return nil, err
	}
	serviceAccount, err := RequireServiceName()
	if err != nil {
		return nil, err
	}
	client, err := s.loadClient()
	if err != nil {
		return nil, err
	}
	localDevTokenLogger.Infof(
		"local-dev token source active: requesting token for audience=%s, sa=%s, namespace=%s",
		audience, serviceAccount, namespace,
	)
	return client.RequestToken(namespace, serviceAccount, audience)
}

func (s *LocalDevTokenSource) loadClient() (*TokenRequestClient, error) {
	if s.client != nil {
		return s.client, nil
	}
	creds, err := s.loadCredentials()
	if err != nil {
		return nil, err
	}
	s.client = NewTokenRequestClient(creds)
	return s.client, nil
}

func (s *LocalDevTokenSource) loadCredentials() (*KubeConfigCredentials, error) {
	if s.creds != nil {
		return s.creds, nil
	}
	creds, err := LoadKubeConfig()
	if err != nil {
		return nil, err
	}
	s.creds = creds
	return creds, nil
}
