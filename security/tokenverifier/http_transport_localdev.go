package tokenverifier

import (
	"fmt"
	"net/http"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
)

type localDevTransport struct {
	base  http.RoundTripper
	token tokenFunction
}

func newLocalDevTransport(token tokenFunction, base http.RoundTripper) *localDevTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &localDevTransport{
		base:  base,
		token: token,
	}
}

func (t *localDevTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if localdev.IsPublicOidcEndpoint(request.URL.String()) {
		return t.base.RoundTrip(request)
	}
	token, err := t.token()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig user token for local-dev Kubernetes API call: %w", err)
	}
	request.Header.Add("Authorization", "Bearer "+token)
	return t.base.RoundTrip(request)
}
