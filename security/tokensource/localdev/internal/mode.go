package internal

import (
	"fmt"
	"os"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	constants "github.com/netcracker/qubership-core-lib-go/v3/const"
)

const (
	ProfileEnv   = "PROFILE"
	NamespaceEnv = "CLOUD_NAMESPACE"
	DevProfile   = "dev"
)

func IsDevEnabled() bool {
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
