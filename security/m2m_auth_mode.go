package security

import (
	"fmt"
	"os"
	"strings"
)

const M2MAuthModeEnv = "M2M_AUTH_MODE"

type M2MAuthMode string

const (
	// M2MAuthModeLegacy sends the legacy M2M token; DBaaS and MaaS requests go through their agents.
	M2MAuthModeLegacy M2MAuthMode = "legacy"
	// M2MAuthModeHybrid sends the Kubernetes token and falls back to the legacy M2M token when the Kubernetes token
	// cannot be read or the receiver answers 401.
	M2MAuthModeHybrid M2MAuthMode = "hybrid"
	// M2MAuthModeK8s sends only the Kubernetes token, without a fallback.
	M2MAuthModeK8s M2MAuthMode = "k8s"
)

func (m M2MAuthMode) UsesLegacyToken() bool {
	return m == M2MAuthModeLegacy || m == M2MAuthModeHybrid
}

// ReadM2MAuthMode reads the mode from the M2M_AUTH_MODE environment variable. The value is matched
// case-insensitively with surrounding whitespace ignored, and an unset or empty variable selects
// [M2MAuthModeLegacy]. Any other value than legacy, hybrid, or k8s is an error.
func ReadM2MAuthMode() (M2MAuthMode, error) {
	value := os.Getenv(M2MAuthModeEnv)
	switch mode := M2MAuthMode(strings.ToLower(strings.TrimSpace(value))); mode {
	case "":
		return M2MAuthModeLegacy, nil
	case M2MAuthModeLegacy, M2MAuthModeHybrid, M2MAuthModeK8s:
		return mode, nil
	default:
		return "", fmt.Errorf("%s has unsupported value %q: set it to legacy, hybrid, or k8s", M2MAuthModeEnv, value)
	}
}

// MustReadM2MAuthMode is like [ReadM2MAuthMode], but logs the error and panics instead of returning it. Clients call
// it when they are created, so a service with an unsupported M2M_AUTH_MODE fails to start.
func MustReadM2MAuthMode() M2MAuthMode {
	mode, err := ReadM2MAuthMode()
	if err != nil {
		logger.Panic("%v", err)
	}
	return mode
}
