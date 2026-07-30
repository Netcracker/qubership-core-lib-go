package localdev

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetKubeConfigStringField(t *testing.T) {
	assert.Equal(t, "", getKubeConfigStringField(nil, "key"))
	assert.Equal(t, "", getKubeConfigStringField(map[string]any{}, "key"))
	assert.Equal(t, "", getKubeConfigStringField(map[string]any{"key": nil}, "key"))
	assert.Equal(t, "", getKubeConfigStringField(map[string]any{"key": 42}, "key"))
	assert.Equal(t, "value", getKubeConfigStringField(map[string]any{"key": " value "}, "key"))
}

func TestGetKubeConfigBoolField(t *testing.T) {
	ok, present := getKubeConfigBoolField(nil, "flag")
	assert.False(t, ok)
	assert.False(t, present)

	ok, present = getKubeConfigBoolField(map[string]any{"flag": true}, "flag")
	assert.True(t, ok)
	assert.True(t, present)

	ok, present = getKubeConfigBoolField(map[string]any{"flag": "true"}, "flag")
	assert.False(t, ok)
	assert.False(t, present)
}

func TestFirstNonBlank(t *testing.T) {
	assert.Equal(t, "first", firstNonBlank("first", "second"))
	assert.Equal(t, "second", firstNonBlank("", "second"))
	assert.Equal(t, "second", firstNonBlank("  ", "second"))
}

func TestTruncateResponseBody(t *testing.T) {
	short := []byte("short body")
	assert.Equal(t, "short body", truncateResponseBody(short))

	long := []byte(strings.Repeat("x", maxErrorBodyLength+10))
	truncated := truncateResponseBody(long)
	assert.True(t, strings.HasSuffix(truncated, "..."))
	assert.LessOrEqual(t, len(truncated), maxErrorBodyLength+3)
}

func TestPadBase64Url(t *testing.T) {
	assert.Equal(t, "abcd", padBase64Url("abcd"))
	assert.Equal(t, "abc=", padBase64Url("abc"))
}
