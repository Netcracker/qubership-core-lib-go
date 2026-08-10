package localdev

import (
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource/localdev/internal"
)

// NamespaceEnv is the Kubernetes namespace env var for local-dev TokenRequest (used by security consumers).
const NamespaceEnv = "CLOUD_NAMESPACE"

// IsEnabled reports whether local-dev TokenRequest mode is active (PROFILE=dev).
func IsEnabled() bool {
	return internal.IsDevEnabled()
}
