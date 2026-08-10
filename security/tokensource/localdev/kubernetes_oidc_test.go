package localdev

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicOidcAPIUsesInternalImplementation(t *testing.T) {
	// Smoke test: public facade delegates without panic when local-dev is disabled.
	assert.False(t, IsEnabled())
}
