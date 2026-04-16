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

type RestClient interface {
	DoRequest(ctx context.Context, httpMethod, url string, headers map[string][]string, body io.Reader) (*http.Response, error)
}

func DefaultM2MRestClient() RestClient {
	return newM2MRestClient(getKubernetesAuthHeaderSupplier(tokensource.AudienceNetcracker), getKeycloakAuthHeaderSupplier())
}

func DefaultDbaasRestClient(username, password string) RestClient {
	return newM2MRestClient(getKubernetesAuthHeaderSupplier(tokensource.AudienceDBaaS), getBasicAuthHeaderSupplier(username, password))
}

func DefaultMaasRestClient(username, password string) RestClient {
	return newM2MRestClient(getKubernetesAuthHeaderSupplier(tokensource.AudienceMaaS), getBasicAuthHeaderSupplier(username, password))
}

type AuthHeaderSupplier func(ctx context.Context) (string, error)

type m2MRestClient struct {
	client                     *http.Client
	urlCache                   cache.Cache[string, empty]
	newAuthHeaderSupplier      AuthHeaderSupplier
	fallbackAuthHeaderSupplier AuthHeaderSupplier
}

func newM2MRestClient(newAuthHeaderSupplier, fallbackAuthHeaderSupplier AuthHeaderSupplier) RestClient {
	return &m2MRestClient{
		client:                     utils.GetClient(),
		urlCache:                   getUrlCache(),
		newAuthHeaderSupplier:      newAuthHeaderSupplier,
		fallbackAuthHeaderSupplier: fallbackAuthHeaderSupplier,
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
		requestProducer.authHeaderSupplier = m.newAuthHeaderSupplier
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
	requestProducer.authHeaderSupplier = m.fallbackAuthHeaderSupplier
	logger.Debugf("trying to send %s request to %s using fallback authentication method", httpMethod, url)
	return m.doRequest(ctx, requestProducer)
}

func (m *m2MRestClient) doRequestFallback(ctx context.Context, cacheKey string, requestProducer *httpRequestProducer, reason *fallbackReason) (*http.Response, error) {
	logger.Debugf("fallback: trying to send %s request to %s using fallback authentication method", requestProducer.httpMethod, requestProducer.url)
	requestProducer.authHeaderSupplier = m.fallbackAuthHeaderSupplier
	response, err := m.doRequest(ctx, requestProducer)

	if err == nil && response.StatusCode < 400 {
		m.urlCache.Add(cacheKey, empty{})
		logger.WarnC(ctx, reason.Message())
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

func getKubernetesAuthHeaderSupplier(audience tokensource.TokenAudience) AuthHeaderSupplier {
	return func(ctx context.Context) (string, error) {
		token, err := tokensource.GetAudienceToken(ctx, audience)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Bearer %s", token), nil
	}
}

func getKeycloakAuthHeaderSupplier() AuthHeaderSupplier {
	tokenProvider := serviceloader.MustLoad[security.TokenProvider]()
	return func(ctx context.Context) (string, error) {
		token, err := tokenProvider.GetToken(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Bearer %s", token), nil
	}
}

func getBasicAuthHeaderSupplier(username, password string) AuthHeaderSupplier {
	credentials := username + ":" + password
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	authHeader := "Basic " + encoded
	return func(ctx context.Context) (string, error) {
		return authHeader, nil
	}
}
