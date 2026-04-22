package rest

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var logger logging.Logger

func init() {
	logger = logging.GetLogger("rest-client")
}

// RestClient represents a generic rest client to make requests to services. Use DefaultM2MRestClient, DefaultDbaasRestClient, DefaultMaasRestClient functions to get a RestClient for your task. All of them support Kubernetes tokens and falling back to old approach if they are not available either in client or server
type RestClient interface {
	DoRequest(ctx context.Context, httpMethod, url string, headers map[string][]string, body io.Reader) (*http.Response, error)
}

// DefaultM2MRestClient returns a RestClient for making requests to internal services using kubernetes token with netcracker audience. If token is not available or a service doesn't support kubernetes tokens then it falls back to old m2m tokens
func DefaultM2MRestClient() RestClient {
	return newM2MRestClient(k8sAuthHeaderFunc(tokensource.AudienceNetcracker), keycloakAuthHeaderFunc())
}

// DefaultDbaasRestClient returns a RestClient for making requests to dbaas using kubernetes token with dbaas audience. If token is not available or the current dbaas version doesn't support kubernetes tokens then it falls back to old approach with basic creds `username` and `password`.
func DefaultDbaasRestClient(username, password string) RestClient {
	return newM2MRestClient(k8sAuthHeaderFunc(tokensource.AudienceDBaaS), basicAuthHeaderFunc(username, password))
}

// DefaultMaasRestClient returns a RestClient for making requests to maas using kubernetes token with maas audience. If token is not available or the current maas version doesn't support kubernetes tokens then it falls back to old approach with basic creds `username` and `password`.
func DefaultMaasRestClient(username, password string) RestClient {
	return newM2MRestClient(k8sAuthHeaderFunc(tokensource.AudienceMaaS), basicAuthHeaderFunc(username, password))
}

type authHeaderFunc func(ctx context.Context) (string, error)

type m2MRestClient struct {
	client             *http.Client
	urlCache           cache.Cache[string, empty]
	k8sAuthHeader      authHeaderFunc
	fallbackAuthHeader authHeaderFunc
}

func newM2MRestClient(k8sAuthHeader, fallbackAuthHeader authHeaderFunc) RestClient {
	return &m2MRestClient{
		client:             utils.GetClient(),
		urlCache:           getUrlCache(),
		k8sAuthHeader:      k8sAuthHeader,
		fallbackAuthHeader: fallbackAuthHeader,
	}
}

func (m *m2MRestClient) DoRequest(ctx context.Context, httpMethod, url string, headers map[string][]string, bodyReader io.Reader) (*http.Response, error) {
	cacheKey, err := calculateCacheKey(url)
	if err != nil {
		return nil, fmt.Errorf("url can not be parsed: %w", err)
	}
	requestProducer, err := newHttpRequestProducer(httpMethod, url, headers, bodyReader)
	if err != nil {
		return nil, err
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
			return m.doRequestFallback(ctx, cacheKey, requestProducer, &fallbackReason{desc: kubernetesTokenUnauthorizedError, url: url})
		}
		return response, requestError
	}

	//new authentication method is not applicable (we already know it from cache), need to use fallback approach
	requestProducer.authHeader = m.fallbackAuthHeader
	logger.Debugf("trying to send %s request to %s using fallback authentication method", httpMethod, url)
	return m.doRequest(ctx, requestProducer)
}

func (m *m2MRestClient) doRequestFallback(ctx context.Context, cacheKey string, requestProducer *httpRequestProducer, reason *fallbackReason) (*http.Response, error) {
	logger.Debugf("fallback: trying to send %s request to %s using fallback authentication method", requestProducer.httpMethod, requestProducer.url)
	requestProducer.authHeader = m.fallbackAuthHeader
	response, err := m.doRequest(ctx, requestProducer)

	if err == nil && response.StatusCode < 400 {
		m.urlCache.Add(cacheKey, empty{})
		logger.WarnC(ctx, "%s", reason.Message())
	}

	return response, err
}

func (m *m2MRestClient) doRequest(ctx context.Context, requestProducer *httpRequestProducer) (*http.Response, error) {
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

func basicAuthHeaderFunc(username, password string) authHeaderFunc {
	credentials := username + ":" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	authHeader := "Basic " + encoded
	return func(ctx context.Context) (string, error) {
		return authHeader, nil
	}
}
