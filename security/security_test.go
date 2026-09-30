package security

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/test"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKeycloakToken struct {
	token string
}

func (s *mockKeycloakToken) GetToken(ctx context.Context) (string, error) {
	return s.token, nil
}

func (s *mockKeycloakToken) GetClaimValue(token *jwt.Token, key string) (interface{}, error) {
	return nil, nil
}

func (s *mockKeycloakToken) ValidateToken(ctx context.Context, token string) (*jwt.Token, error) {
	return nil, nil
}

func (s *mockKeycloakToken) GetTokenAttribute(ctx context.Context, claim string) (string, error) {
	return "", nil
}

var (
	keycloakToken = &mockKeycloakToken{token: "keycloakToken"}
	k8sToken      = &test.MockTokenSource{AudienceToken: "k8sToken"}
)

func init() {
	serviceloader.Register(10, k8sToken)
	serviceloader.Register(10, keycloakToken)
}

func failK8sToken(t *testing.T, err error) {
	t.Helper()
	k8sToken.AudienceTokenError = err
	t.Cleanup(func() { k8sToken.AudienceTokenError = nil })
}

func TestGetTokenFunc(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		wantToken string
	}{
		{name: "legacy mode returns the keycloak token", mode: "legacy", wantToken: "keycloakToken"},
		{name: "unset mode returns the keycloak token", mode: "", wantToken: "keycloakToken"},
		{name: "hybrid mode returns the k8s token", mode: "hybrid", wantToken: "k8sToken"},
		{name: "k8s mode returns the k8s token", mode: "k8s", wantToken: "k8sToken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(M2MAuthModeEnv, tt.mode)

			token, err := GetTokenFunc()(t.Context())

			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

func TestGetTokenFunc_HybridModeFallsBackToKeycloakTokenWhenK8sTokenIsUnreadable(t *testing.T) {
	t.Setenv(M2MAuthModeEnv, "hybrid")
	failK8sToken(t, errors.New("token file is missing"))

	token, err := GetTokenFunc()(t.Context())

	require.NoError(t, err)
	assert.Equal(t, "keycloakToken", token)
}

func TestGetTokenFunc_K8sModeReturnsK8sTokenError(t *testing.T) {
	t.Setenv(M2MAuthModeEnv, "k8s")
	k8sErr := errors.New("token file is missing")
	failK8sToken(t, k8sErr)

	_, err := GetTokenFunc()(t.Context())

	assert.ErrorIs(t, err, k8sErr)
}

func TestGetTokenFunc_UnsupportedModePanics(t *testing.T) {
	t.Setenv(M2MAuthModeEnv, "true")

	assert.Panics(t, func() { GetTokenFunc() })
}
