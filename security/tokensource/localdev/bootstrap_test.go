package localdev

import (
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/stretchr/testify/assert"
)

func TestBootstrapWhenDisabled(t *testing.T) {
	t.Setenv(ProfileEnv, "")
	Bootstrap()
}

func TestBootstrapWhenEnabled(t *testing.T) {
	t.Setenv(ProfileEnv, "dev")
	Bootstrap()

	_, found := serviceloader.Load[tokensource.TokenSource]()
	assert.True(t, found)
}
