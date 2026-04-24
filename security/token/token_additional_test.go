package token

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/test"
	"github.com/stretchr/testify/assert"
)

func Test_GetNumericDateValue_ZeroAndJSONNumber(t *testing.T) {
	claims := jwt.MapClaims{Exp: float64(0)}
	value, err := GetNumericDateValue(&jwt.Token{Claims: claims}, Exp)
	assert.NoError(t, err)
	assert.Nil(t, value)

	claims = jwt.MapClaims{Exp: json.Number("1757656985")}
	value, err = GetNumericDateValue(&jwt.Token{Claims: claims}, Exp)
	assert.NoError(t, err)
	assert.Equal(t, jwt.NewNumericDate(time.Unix(1757656985, 0)), value)
}

func Test_GetRegisteredClaims_InvalidInputs(t *testing.T) {
	value, err := GetRegisteredClaims(nil)
	assert.Equal(t, jwt.RegisteredClaims{}, value)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetRegisteredClaims(&jwt.Token{})
	assert.Equal(t, jwt.RegisteredClaims{}, value)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetRegisteredClaims(&jwt.Token{Claims: KubernetesClaims{}})
	assert.Equal(t, jwt.RegisteredClaims{}, value)
	assert.ErrorIs(t, err, ErrTokenClaimsUnsupported)
}

func Test_GetRegisteredClaims_PartialClaims(t *testing.T) {
	token := &jwt.Token{Claims: jwt.MapClaims{
		Iss: "issuer",
		Aud: float64(123),
		Exp: float64(0),
	}}

	value, err := GetRegisteredClaims(token)
	assert.NoError(t, err)
	assert.Equal(t, jwt.RegisteredClaims{
		Issuer: "issuer",
	}, value)
}

func Test_GetNamespace_MissingNamespace(t *testing.T) {
	token := test.MustCreateUnsignedToken(k8sNoNamespacePayload)

	value, err := GetNamespace(token)
	assert.Empty(t, value)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: namespace is missed")
}

func Test_GetServiceAccount_MissingBlock(t *testing.T) {
	token := test.MustCreateUnsignedToken(k8sNoServiceAccountPayload)

	value, err := GetServiceAccount(token)
	assert.Equal(t, ServiceAccountClaim{}, value)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: serviceaccount is missed")
}

func Test_GetNode_MissingBlock(t *testing.T) {
	token := test.MustCreateUnsignedToken(k8sNoNodePayload)

	value, err := GetNode(token)
	assert.Equal(t, NodeClaim{}, value)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: node is missed")
}

func Test_GetPod_MissingBlock(t *testing.T) {
	token := test.MustCreateUnsignedToken(k8sNoPodPayload)

	value, err := GetPod(token)
	assert.Equal(t, PodClaim{}, value)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: pod is missed")
}

func Test_GetKubernetesIo_WarnAfter(t *testing.T) {
	token := &jwt.Token{Claims: jwt.MapClaims{
		KubernetesIo: map[string]any{
			Namespace: Namespace,
			ServiceAccount: map[string]any{
				Name: "service",
				Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
			},
			Warnafter: float64(1757656385),
		},
	}}

	value, err := GetKubernetesIo(token)
	assert.NoError(t, err)
	assert.Equal(t, KubernetesIoClaim{
		Namespace: Namespace,
		ServiceAccount: ServiceAccountClaim{
			Name: "service",
			Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
		},
		WarnAfter: jwt.NewNumericDate(time.Unix(1757656385, 0)),
	}, value)
}
