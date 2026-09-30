package rest

import (
	"context"
	"errors"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stubToken(token string, err error) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		return token, err
	}
}

func newTestM2MTokens(mode security.M2MAuthMode, k8sErr error) *M2MTokens {
	tokens := &M2MTokens{
		mode:                    mode,
		k8sToken:                stubToken("k8s-token", k8sErr),
		legacyTargets:           newUrlCache(),
		internalGatewayHostname: "internal-gateway-service",
	}
	if mode.UsesLegacyToken() {
		tokens.legacyToken = stubToken("legacy-token", nil)
	}
	return tokens
}

func TestM2MTokens_Token(t *testing.T) {
	tests := []struct {
		name                string
		mode                security.M2MAuthMode
		k8sErr              error
		wantToken           string
		wantFallbackAllowed bool
	}{
		{name: "legacy mode sends the legacy token", mode: security.M2MAuthModeLegacy, wantToken: "legacy-token"},
		{name: "hybrid mode sends the k8s token and allows the fallback", mode: security.M2MAuthModeHybrid, wantToken: "k8s-token", wantFallbackAllowed: true},
		{name: "hybrid mode sends the legacy token when the k8s token is unreadable", mode: security.M2MAuthModeHybrid, k8sErr: errors.New("token file is missing"), wantToken: "legacy-token"},
		{name: "k8s mode sends the k8s token without the fallback", mode: security.M2MAuthModeK8s, wantToken: "k8s-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := newTestM2MTokens(tt.mode, tt.k8sErr)

			token, fallbackAllowed, err := tokens.Token(context.Background(), "http://tenant-manager:8080/api/v4/tenants")

			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
			assert.Equal(t, tt.wantFallbackAllowed, fallbackAllowed)
		})
	}
}

func TestM2MTokens_Token_K8sModeReturnsK8sTokenError(t *testing.T) {
	k8sErr := errors.New("token file is missing")
	tokens := newTestM2MTokens(security.M2MAuthModeK8s, k8sErr)

	_, _, err := tokens.Token(context.Background(), "http://tenant-manager:8080/api/v4/tenants")

	assert.ErrorIs(t, err, k8sErr)
}

func TestM2MTokens_Token_HybridModeRejectsUnparsableUrl(t *testing.T) {
	tokens := newTestM2MTokens(security.M2MAuthModeHybrid, nil)

	_, _, err := tokens.Token(context.Background(), "://invalid-url")

	assert.ErrorContains(t, err, "url can not be parsed")
}

func TestM2MTokens_UseLegacyToken_HybridModeSendsLegacyTokenToThatTargetOnly(t *testing.T) {
	tokens := newTestM2MTokens(security.M2MAuthModeHybrid, nil)

	tokens.UseLegacyToken("http://tenant-manager:8080/api/v4/tenants")

	token, fallbackAllowed, err := tokens.Token(context.Background(), "http://tenant-manager:8080/api/v4/tenants/1")
	require.NoError(t, err)
	assert.Equal(t, "legacy-token", token, "remembered target")
	assert.False(t, fallbackAllowed, "remembered target")
	token, _, err = tokens.Token(context.Background(), "http://paas-mediation:8080/api/v2/routes")
	require.NoError(t, err)
	assert.Equal(t, "k8s-token", token, "other target")
}

func TestM2MTokens_UseLegacyToken_KeysInternalGatewayTargetsByService(t *testing.T) {
	tokens := newTestM2MTokens(security.M2MAuthModeHybrid, nil)

	tokens.UseLegacyToken("http://internal-gateway-service:8080/api/v1/tenant-manager/tenants")

	token, _, err := tokens.Token(context.Background(), "http://internal-gateway-service:8080/api/v1/tenant-manager/routes")
	require.NoError(t, err)
	assert.Equal(t, "legacy-token", token, "same service behind the gateway")
	token, _, err = tokens.Token(context.Background(), "http://internal-gateway-service:8080/api/v1/site-management/routes")
	require.NoError(t, err)
	assert.Equal(t, "k8s-token", token, "other service behind the gateway")
}

func TestM2MTokens_LegacyToken(t *testing.T) {
	tokens := newTestM2MTokens(security.M2MAuthModeHybrid, nil)

	token, err := tokens.LegacyToken(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "legacy-token", token)
}

func TestNewM2MTokens_K8sMode_LegacyTokenIsAnError(t *testing.T) {
	t.Setenv(security.M2MAuthModeEnv, "k8s")

	_, err := NewM2MTokens().LegacyToken(context.Background())

	assert.ErrorContains(t, err, security.M2MAuthModeEnv)
}

func TestNewM2MTokens_HybridMode_SendsRegisteredTokens(t *testing.T) {
	registerStubTokens()
	t.Setenv(security.M2MAuthModeEnv, "hybrid")
	tokens := NewM2MTokens()

	token, _, err := tokens.Token(context.Background(), "http://tenant-manager:8080/api/v4/tenants")
	require.NoError(t, err)
	legacyToken, legacyErr := tokens.LegacyToken(context.Background())
	require.NoError(t, legacyErr)

	assert.Equal(t, "k8s-token", token)
	assert.Equal(t, "legacy-token", legacyToken)
}

func TestNewM2MTokens_UnsupportedMode_Panics(t *testing.T) {
	t.Setenv(security.M2MAuthModeEnv, "false")

	assert.Panics(t, func() { NewM2MTokens() })
}
