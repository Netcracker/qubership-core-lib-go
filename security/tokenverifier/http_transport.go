package tokenverifier

import (
	"fmt"
	"net/http"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/cloudprovidersource"
)

type secureTransport struct {
	base          http.RoundTripper
	token         tokenFunction
	cloudProvider cloudprovidersource.CloudProvider
}

func newSecureTransport(token tokenFunction, cloudProvider cloudprovidersource.CloudProvider) *secureTransport {
	base := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &secureTransport{
		base:          base,
		token:         token,
		cloudProvider: cloudProvider,
	}
}

func (s *secureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if s.cloudProvider != cloudprovidersource.CloudProviderGKE { //GKE requires anonymous call
		token, err := s.token()
		if err != nil {
			return nil, fmt.Errorf("failed to get k8s sa token: %w", err)
		}
		request.Header.Add("Authorization", "Bearer "+token)
	}
	return s.base.RoundTrip(request)
}
