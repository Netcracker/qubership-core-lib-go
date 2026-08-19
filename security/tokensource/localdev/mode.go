package localdev

import (
	"os"
	"strconv"
	"strings"
)

// NamespaceEnv is the Kubernetes namespace env var for local-dev TokenRequest.
// Used by security consumers (for example allowed-namespace resolution).
const (
	EnabledEnv   = "SECURITY_LOCALDEV"
	NamespaceEnv = "CLOUD_NAMESPACE"
)

// IsEnabled reports whether local-dev TokenRequest mode is active (SECURITY_LOCALDEV=true).
func IsEnabled() bool {
	enabled, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(EnabledEnv)))
	return err == nil && enabled
}
