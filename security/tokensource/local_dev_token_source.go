package tokensource

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	constants "github.com/netcracker/qubership-core-lib-go/v3/const"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/internal"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"
)

var localDevTokenLogger = logging.GetLogger("local-dev-token-source")

const tokenCacheExpirySkew = 5 * time.Minute

// localDevTokenSource mints Kubernetes tokens via TokenRequest in local-dev mode.
type localDevTokenSource struct {
	tokens *utils.LoadingCache[TokenAudience, string]
	client *utils.Lazy[*internal.TokenRequestClient]
}

func newLocalDevTokenSource() *localDevTokenSource {
	source := &localDevTokenSource{}
	source.tokens = utils.NewLoadingCache(source.requestToken)
	source.client = utils.NewLazy(source.loadClient)
	return source
}

func (s *localDevTokenSource) GetAudienceToken(ctx context.Context, audience TokenAudience) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("audience is empty")
	}
	return s.tokens.Get(ctx, audience)
}

func (s *localDevTokenSource) GetServiceAccountToken(ctx context.Context) (string, error) {
	return s.GetAudienceToken(ctx, internal.DefaultKubernetesIssuer)
}

func (s *localDevTokenSource) requestToken(_ context.Context, audience TokenAudience) (string, time.Time, error) {
	namespace, err := requireNamespace()
	if err != nil {
		return "", time.Time{}, err
	}
	serviceAccount, err := requireServiceName()
	if err != nil {
		return "", time.Time{}, err
	}
	client, err := s.loadClient()
	if err != nil {
		return "", time.Time{}, err
	}
	localDevTokenLogger.Infof(
		"local-dev token source active: requesting token for audience=%s, sa=%s, namespace=%s",
		audience, serviceAccount, namespace,
	)
	result, err := client.RequestToken(namespace, serviceAccount, string(audience))
	if err != nil {
		return "", time.Time{}, err
	}
	return result.Token, result.ExpiresAt.Add(-tokenCacheExpirySkew), nil
}

func (s *localDevTokenSource) loadClient() (*internal.TokenRequestClient, error) {
	creds, err := internal.LoadKubeConfig()
	if err != nil {
		return nil, err
	}
	return internal.NewTokenRequestClient(creds), nil
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
