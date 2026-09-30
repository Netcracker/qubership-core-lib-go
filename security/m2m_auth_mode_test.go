package security

import (
	"os"
	"sync"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestM2MAuthModeFromEnv(t *testing.T) {
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

			mode, err := M2MAuthModeFromEnv()

			require.NoError(t, err)
			assert.Equal(t, tt.want, mode, "M2M_AUTH_MODE=%q", tt.value)
		})
	}
}

func TestM2MAuthModeFromEnv_UnsetVariableSelectsLegacy(t *testing.T) {
	t.Setenv(M2MAuthModeEnv, "")
	require.NoError(t, os.Unsetenv(M2MAuthModeEnv))

	mode, err := M2MAuthModeFromEnv()

	require.NoError(t, err)
	assert.Equal(t, M2MAuthModeLegacy, mode)
}

func TestM2MAuthModeFromEnv_UnsupportedValueIsAnError(t *testing.T) {
	for _, value := range []string{"true", "false", "kubernetes"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(M2MAuthModeEnv, value)

			_, err := M2MAuthModeFromEnv()

			assert.ErrorContains(t, err, `M2M_AUTH_MODE has unsupported value "`+value+`"`)
		})
	}
}

// captureWarnings records the messages the package logger writes at warn level until the test ends.
func captureWarnings(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var warnings []string
	logger.SetLogFormat(func(r *logging.Record) []byte {
		if r.Lvl == logging.LvlWarn {
			mu.Lock()
			warnings = append(warnings, r.Message)
			mu.Unlock()
		}
		return nil
	})
	t.Cleanup(func() { logger.SetLogFormat(nil) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return warnings
	}
}

func TestM2MAuthModeFromEnv_RemovedVariableIsIgnoredWithWarning(t *testing.T) {
	warnings := captureWarnings(t)
	t.Setenv("KUBERNETES_M2M_ENABLED", "true")
	t.Setenv(M2MAuthModeEnv, "")

	mode, err := M2MAuthModeFromEnv()

	require.NoError(t, err)
	assert.Equal(t, M2MAuthModeLegacy, mode)
	require.Len(t, warnings(), 1)
	assert.Contains(t, warnings()[0], "KUBERNETES_M2M_ENABLED")
	assert.Contains(t, warnings()[0], M2MAuthModeEnv)
}

func TestM2MAuthModeFromEnv_NoWarningWithoutRemovedVariable(t *testing.T) {
	warnings := captureWarnings(t)
	t.Setenv("KUBERNETES_M2M_ENABLED", "")
	require.NoError(t, os.Unsetenv("KUBERNETES_M2M_ENABLED"))
	t.Setenv(M2MAuthModeEnv, "hybrid")

	_, err := M2MAuthModeFromEnv()

	require.NoError(t, err)
	assert.Empty(t, warnings())
}

func TestMustM2MAuthModeFromEnv_UnsupportedValuePanics(t *testing.T) {
	t.Setenv(M2MAuthModeEnv, "true")

	assert.Panics(t, func() { MustM2MAuthModeFromEnv() })
}

func TestM2MAuthMode_Tokens(t *testing.T) {
	tests := []struct {
		mode            M2MAuthMode
		usesK8sToken    bool
		usesLegacyToken bool
	}{
		{mode: M2MAuthModeLegacy, usesK8sToken: false, usesLegacyToken: true},
		{mode: M2MAuthModeHybrid, usesK8sToken: true, usesLegacyToken: true},
		{mode: M2MAuthModeK8s, usesK8sToken: true, usesLegacyToken: false},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			assert.Equal(t, tt.usesK8sToken, tt.mode.UsesK8sToken(), "UsesK8sToken")
			assert.Equal(t, tt.usesLegacyToken, tt.mode.UsesLegacyToken(), "UsesLegacyToken")
		})
	}
}
