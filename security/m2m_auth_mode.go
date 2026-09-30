package security

import (
	"fmt"
	"os"
	"strings"
)

// M2MAuthModeEnv is the environment variable that sets the [M2MAuthMode] of a service.
const M2MAuthModeEnv = "M2M_AUTH_MODE"

const removedM2MFlagEnv = "KUBERNETES_M2M_ENABLED"

// M2MAuthMode selects the token a service sends in machine-to-machine requests. One mode applies to the whole
// installation, so legacy M2M tokens and Kubernetes tokens are never mixed.
type M2MAuthMode string

const (
	// M2MAuthModeLegacy sends the legacy M2M token of the registered [TokenProvider] and reaches DBaaS and MaaS
	// through their agents. It is the default.
	M2MAuthModeLegacy M2MAuthMode = "legacy"
	// M2MAuthModeHybrid sends the Kubernetes token and falls back to the legacy M2M token when the Kubernetes token
	// cannot be read or the receiver rejects it.
	M2MAuthModeHybrid M2MAuthMode = "hybrid"
	// M2MAuthModeK8s sends only the Kubernetes token and never reads a legacy M2M token.
	M2MAuthModeK8s M2MAuthMode = "k8s"
)

// UsesK8sToken reports whether the mode sends the Kubernetes token.
func (m M2MAuthMode) UsesK8sToken() bool {
	return m == M2MAuthModeHybrid || m == M2MAuthModeK8s
}

// UsesLegacyToken reports whether the mode sends the legacy M2M token, as the only token or as the fallback.
func (m M2MAuthMode) UsesLegacyToken() bool {
	return m == M2MAuthModeLegacy || m == M2MAuthModeHybrid
}

// M2MAuthModeFromEnv returns the mode that the M2M_AUTH_MODE environment variable sets. The value is matched
// case-insensitively with surrounding whitespace ignored, and an unset or empty variable selects
// [M2MAuthModeLegacy]. Any other value than legacy, hybrid, or k8s is an error.
//
// KUBERNETES_M2M_ENABLED is no longer read: when it is set, M2MAuthModeFromEnv logs a warning and ignores its value.
func M2MAuthModeFromEnv() (M2MAuthMode, error) {
	if value, ok := os.LookupEnv(removedM2MFlagEnv); ok {
		logger.Warn("%s=%q is ignored because the variable is no longer read; set %s to legacy, hybrid, or k8s instead",
			removedM2MFlagEnv, value, M2MAuthModeEnv)
	}
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

// MustM2MAuthModeFromEnv is like [M2MAuthModeFromEnv], but logs the error and panics instead of returning it.
// Clients call it when they are created, so a service with an unsupported M2M_AUTH_MODE fails to start.
func MustM2MAuthModeFromEnv() M2MAuthMode {
	mode, err := M2MAuthModeFromEnv()
	if err != nil {
		logger.Panic("%v", err)
	}
	return mode
}
