package tokensource

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	constants "github.com/netcracker/qubership-core-lib-go/v3/const"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/internal"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
)

var localDevTokenLogger = logging.GetLogger("local-dev-token-source")

const tokenCacheExpirySkew = 5 * time.Minute

type cachedAudienceToken struct {
	token        string
	refreshAfter time.Time
}

func (c cachedAudienceToken) valid() bool {
	return time.Now().Before(c.refreshAfter)
}

// localDevTokenSource mints Kubernetes audience tokens via TokenRequest in local-dev mode.
type localDevTokenSource struct {
	mu     sync.RWMutex
	client *internal.TokenRequestClient
	creds  *internal.KubeConfigCredentials
	cache  map[TokenAudience]cachedAudienceToken
}

func newLocalDevTokenSource() *localDevTokenSource {
	return &localDevTokenSource{
		cache: make(map[TokenAudience]cachedAudienceToken),
	}
}

func (s *localDevTokenSource) GetAudienceToken(_ context.Context, audience TokenAudience) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("audience is empty")
	}

	if token, ok := s.lookupCached(audience); ok {
		return token, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if cached, ok := s.cache[audience]; ok && cached.valid() {
		return cached.token, nil
	}

	result, err := s.requestToken(audience)
	if err != nil {
		return "", err
	}

	s.cache[audience] = cachedAudienceToken{
		token:        result.Token,
		refreshAfter: result.ExpiresAt.Add(-tokenCacheExpirySkew),
	}
	return result.Token, nil
}

func (s *localDevTokenSource) lookupCached(audience TokenAudience) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cached, ok := s.cache[audience]
	if !ok || !cached.valid() {
		return "", false
	}
	return cached.token, true
}

func (s *localDevTokenSource) GetServiceAccountToken(_ context.Context) (string, error) {
	if token, ok := s.lookupUserToken(); ok {
		return token, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	creds, err := s.loadCredentials()
	if err != nil {
		return "", err
	}
	return creds.UserToken, nil
}

func (s *localDevTokenSource) lookupUserToken() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.creds == nil {
		return "", false
	}
	return s.creds.UserToken, true
}

func (s *localDevTokenSource) requestToken(audience TokenAudience) (*internal.TokenRequestResult, error) {
	namespace, err := requireNamespace()
	if err != nil {
		return nil, err
	}

	serviceAccount, err := requireServiceName()
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

	return client.RequestToken(namespace, serviceAccount, string(audience))
}

func (s *localDevTokenSource) loadClient() (*internal.TokenRequestClient, error) {
	if s.client != nil {
		return s.client, nil
	}
	creds, err := s.loadCredentials()
	if err != nil {
		return nil, err
	}
	s.client = internal.NewTokenRequestClient(creds)
	return s.client, nil
}

func (s *localDevTokenSource) loadCredentials() (*internal.KubeConfigCredentials, error) {
	if s.creds != nil {
		return s.creds, nil
	}
	creds, err := internal.LoadKubeConfig()
	if err != nil {
		return nil, err
	}
	s.creds = creds
	return s.creds, nil
}

func requireServiceName() (string, error) {
	name := strings.TrimSpace(configloader.GetOrDefaultString(constants.MicroserviceNameProperty, ""))
	if name == "" || name == constants.DefaultMicroserviceName {
		return "", fmt.Errorf(
			"local-dev M2M requires %s (application.yaml or env MICROSERVICE_NAME) with the Kubernetes service account name",
			constants.MicroserviceNameProperty,
		)
	}
	return name, nil
}

func requireNamespace() (string, error) {
	namespace := strings.TrimSpace(os.Getenv(localdev.NamespaceEnv))
	if namespace == "" {
		return "", fmt.Errorf(
			"local-dev M2M requires env %s with the Kubernetes namespace of the service account",
			localdev.NamespaceEnv,
		)
	}
	return namespace, nil
}
