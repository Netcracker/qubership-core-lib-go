package internal

import (
	"fmt"
	"sync"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var localDevTokenLogger = logging.GetLogger("local-dev-token-source")

var (
	localDevSourceInstance     *LocalDevTokenSource
	localDevSourceInstanceOnce sync.Once
)

type cachedAudienceToken struct {
	token        string
	refreshAfter time.Time
}

func (c cachedAudienceToken) valid() bool {
	return time.Now().Before(c.refreshAfter)
}

// LocalDevTokenSource mints Kubernetes audience tokens via TokenRequest in local-dev mode.
type LocalDevTokenSource struct {
	mu     sync.Mutex
	client *TokenRequestClient
	creds  *KubeConfigCredentials
	cache  map[string]cachedAudienceToken
}

// AudienceToken returns a minted audience token via kubeconfig TokenRequest.
func AudienceToken(audience string) (string, error) {
	return localDevSource().GetToken(audience)
}

// ServiceAccountToken returns the kubeconfig user token for Kubernetes API calls.
func ServiceAccountToken() (string, error) {
	return localDevSource().GetServiceAccountToken()
}

func localDevSource() *LocalDevTokenSource {
	localDevSourceInstanceOnce.Do(func() {
		localDevSourceInstance = &LocalDevTokenSource{
			cache: make(map[string]cachedAudienceToken),
		}
	})
	return localDevSourceInstance
}

func (s *LocalDevTokenSource) GetToken(audience string) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("audience is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cached, ok := s.cache[audience]
	if ok && cached.valid() {
		return cached.token, nil
	}

	result, err := s.requestToken(audience)
	if err != nil {
		return "", err
	}

	refreshAfter := result.ExpiresAt.Add(-tokenCacheExpirySkew)
	s.cache[audience] = cachedAudienceToken{
		token:        result.Token,
		refreshAfter: refreshAfter,
	}
	return result.Token, nil
}

func (s *LocalDevTokenSource) GetServiceAccountToken() (string, error) {
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
	return s.creds, nil
}
