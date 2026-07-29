package localdev

import (
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
)

func TestIsEnabled(t *testing.T) {
	t.Setenv(EnabledEnv, "")
	t.Setenv(ProfileEnv, "")
	assert.False(t, IsEnabled())

	t.Setenv(EnabledEnv, "true")
	assert.True(t, IsEnabled())
	t.Setenv(EnabledEnv, "")

	t.Setenv(ProfileEnv, "dev")
	assert.True(t, IsEnabled())

	t.Setenv(ProfileEnv, "DEV")
	assert.True(t, IsEnabled())
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
	t.Setenv(NamespaceEnv, "my-ns")
	configloader.Init(configloader.EnvPropertySource())

	name, err := RequireServiceName()
	assert.NoError(t, err)
	assert.Equal(t, "my-service", name)
	ns, err := RequireNamespace()
	assert.NoError(t, err)
	assert.Equal(t, "my-ns", ns)
}
