package internal

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsFailed(t *testing.T) {
	assert.False(t, isFailed(http.StatusOK))
	assert.False(t, isFailed(http.StatusCreated))
	assert.True(t, isFailed(http.StatusBadRequest))
	assert.True(t, isFailed(http.StatusInternalServerError))
}

func TestGetStringField(t *testing.T) {
	assert.Equal(t, "", getStringField(nil, "key"))
	assert.Equal(t, "", getStringField(map[string]any{}, "key"))
	assert.Equal(t, "", getStringField(map[string]any{"key": nil}, "key"))
	assert.Equal(t, "", getStringField(map[string]any{"key": 42}, "key"))
	assert.Equal(t, "value", getStringField(map[string]any{"key": " value "}, "key"))
}

func TestGetBoolField(t *testing.T) {
	ok, present := getBoolField(nil, "flag")
	assert.False(t, ok)
	assert.False(t, present)

	ok, present = getBoolField(map[string]any{"flag": true}, "flag")
	assert.True(t, ok)
	assert.True(t, present)

	ok, present = getBoolField(map[string]any{"flag": "true"}, "flag")
	assert.False(t, ok)
	assert.False(t, present)
}

func TestTruncateResponseBody(t *testing.T) {
	short := []byte("short body")
	assert.Equal(t, "short body", truncateResponseBody(short))

	long := []byte(strings.Repeat("x", maxErrorBodyLength+10))
	truncated := truncateResponseBody(long)
	assert.True(t, strings.HasSuffix(truncated, "..."))
	assert.LessOrEqual(t, len(truncated), maxErrorBodyLength+3)
}
