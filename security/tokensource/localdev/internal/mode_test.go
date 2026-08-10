package internal

import (
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
)

func TestIsDevEnabled(t *testing.T) {
	t.Setenv(ProfileEnv, "")
	assert.False(t, IsDevEnabled())

	t.Setenv(ProfileEnv, "dev")
	assert.True(t, IsDevEnabled())

	t.Setenv(ProfileEnv, "DEV")
	assert.True(t, IsDevEnabled())
}

func TestRequireServiceNameAndNamespace(t *testing.T) {
	t.Setenv("MICROSERVICE_NAME", "")
	t.Setenv(NamespaceEnv, "")
	configloader.Init(configloader.EnvPropertySource())
	_, err := RequireServiceName()
	assert.Error(t, err)
	_, err = RequireNamespace()
	assert.Error(t, err)

	t.Setenv("MICROSERVICE_NAME", "my-service")
	configloader.Init(configloader.EnvPropertySource())
	name, err := RequireServiceName()
	assert.NoError(t, err)
	assert.Equal(t, "my-service", name)

	t.Setenv(NamespaceEnv, "my-ns")
	namespace, err := RequireNamespace()
	assert.NoError(t, err)
	assert.Equal(t, "my-ns", namespace)
}
