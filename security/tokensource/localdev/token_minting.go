package localdev

import "github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev/internal"

// GetAudienceToken mints an audience token via kubeconfig TokenRequest (local-dev only).
func GetAudienceToken(audience string) (string, error) {
	return internal.AudienceToken(audience)
}

// GetServiceAccountToken returns the kubeconfig user token (local-dev only).
func GetServiceAccountToken() (string, error) {
	return internal.ServiceAccountToken()
}
