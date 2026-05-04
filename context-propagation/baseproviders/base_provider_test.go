package baseproviders

import (
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/stretchr/testify/assert"
)

func init() {
	configloader.Init(configloader.EnvPropertySource())
}

func TestProviders(t *testing.T) {
	assert.Equal(t, 11, len(Get()))
}
