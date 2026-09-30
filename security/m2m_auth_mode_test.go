package security

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadM2MAuthMode(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  M2MAuthMode
	}{
		{name: "legacy", value: "legacy", want: M2MAuthModeLegacy},
		{name: "hybrid", value: "hybrid", want: M2MAuthModeHybrid},
		{name: "k8s", value: "k8s", want: M2MAuthModeK8s},
		{name: "empty value selects legacy", value: "", want: M2MAuthModeLegacy},
		{name: "case is ignored", value: "Hybrid", want: M2MAuthModeHybrid},
		{name: "surrounding whitespace is ignored", value: " K8S\t", want: M2MAuthModeK8s},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(M2MAuthModeEnv, tt.value)

			mode, err := ReadM2MAuthMode()

			require.NoError(t, err)
			assert.Equal(t, tt.want, mode, "M2M_AUTH_MODE=%q", tt.value)
		})
	}
}

func TestReadM2MAuthMode_UnsetVariableSelectsLegacy(t *testing.T) {
	t.Setenv(M2MAuthModeEnv, "")
	require.NoError(t, os.Unsetenv(M2MAuthModeEnv))

	mode, err := ReadM2MAuthMode()

	require.NoError(t, err)
	assert.Equal(t, M2MAuthModeLegacy, mode)
}

func TestReadM2MAuthMode_UnsupportedValueIsAnError(t *testing.T) {
	for _, value := range []string{"true", "false", "kubernetes"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(M2MAuthModeEnv, value)

			_, err := ReadM2MAuthMode()

			assert.ErrorContains(t, err, `M2M_AUTH_MODE has unsupported value "`+value+`"`)
		})
	}
}

func TestMustReadM2MAuthMode_UnsupportedValuePanics(t *testing.T) {
	t.Setenv(M2MAuthModeEnv, "true")

	assert.Panics(t, func() { MustReadM2MAuthMode() })
}

func TestM2MAuthMode_UsesLegacyToken(t *testing.T) {
	tests := []struct {
		mode M2MAuthMode
		want bool
	}{
		{mode: M2MAuthModeLegacy, want: true},
		{mode: M2MAuthModeHybrid, want: true},
		{mode: M2MAuthModeK8s, want: false},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mode.UsesLegacyToken())
		})
	}
}
