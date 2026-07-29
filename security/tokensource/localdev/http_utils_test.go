package localdev

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUnauthorized(t *testing.T) {
	assert.True(t, isUnauthorized(http.StatusUnauthorized))
	assert.True(t, isUnauthorized(http.StatusForbidden))
	assert.False(t, isUnauthorized(http.StatusOK))
}

func TestIsFailed(t *testing.T) {
	assert.False(t, isFailed(http.StatusOK))
	assert.False(t, isFailed(http.StatusCreated))
	assert.True(t, isFailed(http.StatusBadRequest))
	assert.True(t, isFailed(http.StatusInternalServerError))
}
