package security

import (
	"context"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"

	"github.com/netcracker/qubership-core-lib-go/v3/security/test"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/stretchr/testify/assert"
)

type mockKeycloakToken struct {
	token string
}

func init() {
	logger = logging.GetLogger("dummy-services")
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

func TestGetTokenFunc(t *testing.T) {
	keycloakToken := &mockKeycloakToken{token: "keycloakToken"}
	k8sToken := &test.MockTokenSource{AudienceToken: "k8sToken"}
	serviceloader.Register(10, k8sToken)
	serviceloader.Register(10, keycloakToken)

	tests := []struct {
		name          string
		envValue      string
		k8sM2mEnabled bool
	}{
		{
			name:          "K8s M2M Enabled",
			envValue:      "true",
			k8sM2mEnabled: true,
		},
		{
			name:          "K8s M2M Disabled",
			envValue:      "false",
			k8sM2mEnabled: false,
		},
		{
			name:          "Invalid Env Value defaults to Keycloak",
			envValue:      "invalid-boolean",
			k8sM2mEnabled: false,
		},
		{
			name:          "Empty Env Value defaults to Keycloak",
			envValue:      "",
			k8sM2mEnabled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv("KUBERNETES_M2M_ENABLED", tt.envValue)
			}
			defer os.Unsetenv("KUBERNETES_M2M_ENABLED")

			tokenFunc := GetTokenFunc()
			token, err := tokenFunc(t.Context())
			assert.NoError(t, err)

			if tt.k8sM2mEnabled {
				assert.Equal(t, k8sToken.AudienceToken, token)
			} else {
				assert.Equal(t, keycloakToken.token, token)
			}
		})
	}
}
