package localdev

import (
	"net/http"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev/internal"
)

// UserToken returns the kubeconfig user token for Kubernetes API calls.
func UserToken() (string, error) {
	return internal.UserToken()
}

// JwksURL returns the reachable JWKS URL on the kube API server.
func JwksURL() (string, error) {
	return internal.JwksURL()
}

// HTTPClient returns an HTTP client configured with kubeconfig TLS (cached).
func HTTPClient() (*http.Client, error) {
	return internal.HTTPClient()
}

// IsPublicOidcEndpoint reports whether the URL is served without authentication on the kube API.
func IsPublicOidcEndpoint(rawURL string) bool {
	return internal.IsPublicOidcEndpoint(rawURL)
}

// ResolveIssuerClaimFromDiscovery reads issuer from kube API OIDC discovery (no projected SA token required).
func ResolveIssuerClaimFromDiscovery() (string, error) {
	return internal.ResolveIssuerClaimFromDiscovery()
}

// ResetCache clears cached kubeconfig credentials (tests).
func ResetCache() {
	internal.ResetCache()
}
