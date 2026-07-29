package localdev

import (
	"fmt"
	"os"
	"strings"

	constants "github.com/netcracker/qubership-core-lib-go/v3/const"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
)

const (
	EnabledEnv     = "SECURITY_LOCAL_DEV_ENABLED"
	ProfileEnv     = "PROFILE"
	NamespaceEnv   = "CLOUD_NAMESPACE"
	DevProfile     = "dev"

	InsecureIdpTlsEnv = "SECURITY_LOCAL_DEV_INSECURE_IDP_TLS"
)

// IsEnabled reports whether local-dev TokenRequest mode is active.
func IsEnabled() bool {
	if isTrue(os.Getenv(EnabledEnv)) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv(ProfileEnv)), DevProfile)
}

func RequireServiceName() (string, error) {
	name := strings.TrimSpace(configloader.GetOrDefaultString(constants.MicroserviceNameProperty, ""))
	if name == "" || name == constants.DefaultMicroserviceName {
		return "", fmt.Errorf(
			"local-dev M2M requires %s (application.yaml or env MICROSERVICE_NAME) with the Kubernetes service account name",
			constants.MicroserviceNameProperty,
		)
	}
	return name, nil
}

func RequireNamespace() (string, error) {
	namespace := strings.TrimSpace(os.Getenv(NamespaceEnv))
	if namespace == "" {
		return "", fmt.Errorf(
			"local-dev M2M requires env %s with the Kubernetes namespace of the service account",
			NamespaceEnv,
		)
	}
	return namespace, nil
}

func isInsecureIdpTlsEnabled() bool {
	configured := strings.TrimSpace(os.Getenv(InsecureIdpTlsEnv))
	if configured == "" {
		return true
	}
	return !strings.EqualFold(configured, "false") && configured != "0"
}

func isTrue(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "true") || strings.TrimSpace(value) == "1"
}
