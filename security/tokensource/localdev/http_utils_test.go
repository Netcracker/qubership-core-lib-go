package localdev

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUnauthorizedOrForbidden(t *testing.T) {
	assert.True(t, isUnauthorizedOrForbidden(http.StatusUnauthorized))
	assert.True(t, isUnauthorizedOrForbidden(http.StatusForbidden))
	assert.False(t, isUnauthorizedOrForbidden(http.StatusOK))
}

func TestIsFailed(t *testing.T) {
	assert.False(t, isFailed(http.StatusOK))
	assert.False(t, isFailed(http.StatusCreated))
	assert.True(t, isFailed(http.StatusBadRequest))
	assert.True(t, isFailed(http.StatusInternalServerError))
}
