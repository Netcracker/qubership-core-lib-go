package tokenverifier

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev"
)

type localDevTransport struct {
	base  http.RoundTripper
	token tokenFunction
	oidc  *localdev.KubernetesOidc
}

func newLocalDevTransport(token tokenFunction, base http.RoundTripper, oidc *localdev.KubernetesOidc) *localDevTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	if oidc == nil {
		oidc = localdev.NewKubernetesOidc()
	}
	return &localDevTransport{
		base:  base,
		token: token,
		oidc:  oidc,
	}
}

func (t *localDevTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.oidc.IsPublicOidcEndpoint(request.URL.String()) {
		if request.Header.Get("Accept") == "" && strings.Contains(request.URL.Path, "/openid/v1/jwks") {
			request.Header.Set("Accept", "application/jwk-set+json")
		}
		return t.base.RoundTrip(request)
	}
	token, err := t.token()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig user token for local-dev Kubernetes API call: %w", err)
	}
	request.Header.Add("Authorization", "Bearer "+token)
	return t.base.RoundTrip(request)
}
