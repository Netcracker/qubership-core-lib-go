package oidc

import (
	"fmt"
	"net/url"
)

// ProviderResponse represents the JSON object returned by the OpenID Provider Configuration endpoint.
// It contains metadata about the OpenID Provider, such as the issuer identifier
// and the location of the JSON Web Key Set (JWKS).
//   - OpenID Connect Discovery 1.0, Section 4.2 “OpenID Provider Configuration Response”:
//     https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
type ProviderResponse struct {
	JwksUri string `json:"jwks_uri"`
	Issuer  string `json:"issuer"`
}

const (
	// ProviderSubPath defines the standard well-known subpath for OpenID Provider metadata discovery.
	// The OpenID Provider Configuration document must be accessible at:
	//     {issuer}/.well-known/openid-configuration
	//   - OpenID Connect Discovery 1.0, Section 4.1 “OpenID Provider Configuration Request”:
	//     https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
	ProviderSubPath = "/.well-known/openid-configuration"
)

var (
	providerUrl = &url.URL{Path: ProviderSubPath}
)

// GetProviderUrl returns the full OpenID Provider Configuration endpoint URL for a given issuer.
// It ensures the issuer does not end with a trailing slash, and then appends
// the standard well-known configuration subpath.
func GetProviderUrl(issuer string) (string, error) {
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("issuer url is invalid: %w", err)
	}
	return issuerUrl.ResolveReference(providerUrl).String(), nil
}
