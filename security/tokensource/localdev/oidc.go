package localdev

import (
	"net/http"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/internal"
)

// KubernetesOidc is the local-dev Kubernetes OIDC helper used by security consumers
// (JWKS URL rewrite, issuer discovery). Analogous to Java LocalDevKubernetesOidc.
type KubernetesOidc struct {
	config *internal.KubeLocalDevConfig
}

func NewKubernetesOidc() *KubernetesOidc {
	return &KubernetesOidc{config: internal.NewKubeLocalDevConfig()}
}

func (o *KubernetesOidc) UserToken() (string, error) {
	return o.config.UserToken()
}

func (o *KubernetesOidc) JwksURL() (string, error) {
	return o.config.JwksURL()
}

func (o *KubernetesOidc) HTTPClient() (*http.Client, error) {
	return o.config.HTTPClient()
}

func (o *KubernetesOidc) IsPublicOidcEndpoint(rawURL string) bool {
	return o.config.IsPublicOidcEndpoint(rawURL)
}

func (o *KubernetesOidc) ResolveIssuerClaimFromDiscovery() (string, error) {
	return o.config.ResolveIssuerClaimFromDiscovery()
}
