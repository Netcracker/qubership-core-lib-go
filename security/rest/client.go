package rest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

const (
	DbaasAgentUrlProperty = "dbaas.agent"
	MaasAgentUrlProperty  = "maas.agent.url"
)

var (
	logger logging.Logger

	DefaultDbaasAgentUrl = "http://dbaas-agent:8080"
	DefaultMaasAgentUrl  = "http://maas-agent:8080"
)

func init() {
	logger = logging.GetLogger("rest-client")
}

// NewM2MRestClient returns a *M2MRestClient for making requests to internal services in the mode that
// [security.MustM2MAuthModeFromEnv] reads. The Kubernetes token has the netcracker audience; in hybrid mode the client
// falls back to the legacy M2M token when the Kubernetes token is not available or a service rejects it.
func NewM2MRestClient() *M2MRestClient {
	return newM2MRestClient(security.MustM2MAuthModeFromEnv(), tokensource.AudienceNetcracker, "")
}

// NewDbaasRestClient returns a *M2MRestClient for making requests to dbaas in the mode that
// [security.MustM2MAuthModeFromEnv] reads. The Kubernetes token has the dbaas audience. In legacy mode, and in hybrid
// mode when the Kubernetes token is not available or dbaas rejects it, the request goes through dbaas-agent instead.
func NewDbaasRestClient() *M2MRestClient {
	dbaasAgentUrl := configloader.GetOrDefaultString(DbaasAgentUrlProperty, DefaultDbaasAgentUrl)
	return newM2MRestClient(security.MustM2MAuthModeFromEnv(), tokensource.AudienceDBaaS, dbaasAgentUrl)
}

// NewMaasRestClient returns a *M2MRestClient for making requests to maas in the mode that
// [security.MustM2MAuthModeFromEnv] reads. The Kubernetes token has the maas audience. In legacy mode, and in hybrid
// mode when the Kubernetes token is not available or maas rejects it, the request goes through maas-agent instead.
func NewMaasRestClient() *M2MRestClient {
	maasAgentUrl := configloader.GetOrDefaultString(MaasAgentUrlProperty, DefaultMaasAgentUrl)
	return newM2MRestClient(security.MustM2MAuthModeFromEnv(), tokensource.AudienceMaaS, maasAgentUrl)
}

type authHeaderFunc func(ctx context.Context) (string, error)

type M2MRestClient struct {
	client                  *http.Client
	urlCache                cache.Cache[string, empty]
	k8sAuthHeader           authHeaderFunc
	fallbackAuthHeader      authHeaderFunc
	fallBackBaseUrl         string
	internalGatewayHostname string
	mode                    security.M2MAuthMode
}

func newM2MRestClient(mode security.M2MAuthMode, audience tokensource.TokenAudience, fallBackBaseUrl string) *M2MRestClient {
	client := &M2MRestClient{
		client:                  utils.GetClient(),
		urlCache:                newUrlCache(),
		k8sAuthHeader:           k8sAuthHeaderFunc(audience),
		fallBackBaseUrl:         fallBackBaseUrl,
		internalGatewayHostname: internalGatewayHostname(),
		mode:                    mode,
	}
	if mode.UsesLegacyToken() {
		client.fallbackAuthHeader = keycloakAuthHeaderFunc()
	}
	return client
}

// DoRequest performs an HTTP request with automatic authentication handling and fallback.
func (m *M2MRestClient) DoRequest(ctx context.Context, httpMethod, url string, headers map[string][]string, bodyReader io.Reader) (*http.Response, error) {
	cacheKey, err := calculateCacheKey(m.internalGatewayHostname, url)
	if err != nil {
		return nil, fmt.Errorf("url can not be parsed: %w", err)
	}
	requestProducer, err := newHttpRequestProducer(httpMethod, url, headers, bodyReader)
	if err != nil {
		return nil, err
	}
	if !m.mode.UsesK8sToken() {
		return m.doRequestFallback(ctx, cacheKey, requestProducer, nil)
	}
	if !m.mode.UsesLegacyToken() {
		requestProducer.authHeader = m.k8sAuthHeader
		return m.doRequest(ctx, requestProducer)
	}
	_, ok := m.urlCache.Get(cacheKey)
	if !ok {
		logger.Debugf("trying to send %s request to %s using new authentication method", httpMethod, url)
		//first call (no information) / new authentication method is applicable
		requestProducer.authHeader = m.k8sAuthHeader
		response, requestError := m.doRequest(ctx, requestProducer)
		if requestError != nil {
			tae := &TokenAcquisitionError{}
			if errors.As(requestError, &tae) {
				return m.doRequestFallback(ctx, cacheKey, requestProducer, &fallbackReason{desc: kubernetesTokenAcquisitionError, url: url, err: tae})
			}
			return nil, requestError
		}

		if response.StatusCode == http.StatusUnauthorized {
			//authentication failed, need to use fallback approach
			if response.Body != nil {
				response.Body.Close()
			}
			return m.doRequestFallback(ctx, cacheKey, requestProducer, &fallbackReason{desc: kubernetesTokenUnauthorizedError, url: url})
		}
		return response, nil
	}

	//new authentication method is not applicable (we already know it from cache), need to use fallback approach
	return m.doRequestFallback(ctx, cacheKey, requestProducer, nil)
}

func (m *M2MRestClient) doRequestFallback(ctx context.Context, cacheKey string, requestProducer *httpRequestProducer, reason *fallbackReason) (*http.Response, error) {
	logger.Debugf("fallback: trying to send %s request to %s using fallback authentication method", requestProducer.httpMethod, requestProducer.url)

	if m.fallBackBaseUrl != "" {
		rebasedUrl, err := rebaseUrl(requestProducer.url, m.fallBackBaseUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to rebase url %q to fallback base url %q: %w", requestProducer.url, m.fallBackBaseUrl, err)
		}
		requestProducer.url = rebasedUrl
	}
	requestProducer.authHeader = m.fallbackAuthHeader
	response, err := m.doRequest(ctx, requestProducer)

	if err == nil && response.StatusCode < 400 {
		m.urlCache.Add(cacheKey, empty{})
	}
	if reason != nil {
		if reason.desc == kubernetesTokenAcquisitionError {
			logger.WarnC(ctx, "%s", reason.Message())
		} else {
			logger.DebugC(ctx, "%s", reason.Message())
		}
	}

	return response, err
}

func (m *M2MRestClient) doRequest(ctx context.Context, requestProducer *httpRequestProducer) (*http.Response, error) {
	httpRequest, err := requestProducer.produce(ctx)
	if err != nil {
		return nil, err
	}

	httpResponse, err := m.client.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("cannot perform request: %w", err)
	}

	return httpResponse, nil
}

func internalGatewayHostname() string {
	return configloader.GetOrDefaultString("security.m2m.kubernetes.url-cache.internal-gateway-hostname", "internal-gateway-service")
}

func k8sAuthHeaderFunc(audience tokensource.TokenAudience) authHeaderFunc {
	return func(ctx context.Context) (string, error) {
		token, err := tokensource.GetAudienceToken(ctx, audience)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Bearer %s", token), nil
	}
}

func keycloakAuthHeaderFunc() authHeaderFunc {
	tokenProvider := serviceloader.MustLoad[security.TokenProvider]()
	return func(ctx context.Context) (string, error) {
		token, err := tokenProvider.GetToken(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Bearer %s", token), nil
	}
}

func rebaseUrl(originalUrl, fallbackBase string) (string, error) {
	original, err := url.Parse(originalUrl)
	if err != nil {
		return "", fmt.Errorf("cannot parse url: %w", err)
	}
	base, err := url.Parse(fallbackBase)
	if err != nil {
		return "", fmt.Errorf("cannot parse fallback base url: %w", err)
	}
	original.Scheme = base.Scheme
	original.Host = base.Host
	return original.String(), nil
}
