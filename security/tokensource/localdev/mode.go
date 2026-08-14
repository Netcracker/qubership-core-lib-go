package localdev

import (
	"os"
	"strings"
)

// NamespaceEnv is the Kubernetes namespace env var for local-dev TokenRequest.
// Used by security consumers (for example allowed-namespace resolution).
const (
	ProfileEnv   = "PROFILE"
	NamespaceEnv = "CLOUD_NAMESPACE"
	DevProfile   = "dev"
)

// IsEnabled reports whether local-dev TokenRequest mode is active (PROFILE=dev).
func IsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(ProfileEnv)), DevProfile)
}
