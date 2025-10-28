package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/test"
	"github.com/stretchr/testify/assert"
)

const (
	noClaimsPayload                = "../token/test_data/noClaims.json"
	k8sMultiAudPayload             = "../token/test_data/k8sMultiAudPayload.json"
	k8sNoServiceAccountPayload     = "../token/test_data/k8sNoServiceAccountPayload.json"
	k8sNoServiceAccountIdPayload   = "../token/test_data/k8sNoServiceAccountIdPayload.json"
	k8sNoServiceAccountNamePayload = "../token/test_data/k8sNoServiceAccountNamePayload.json"
	k8sNoPodPayload                = "../token/test_data/k8sNoPodPayload.json"
	k8sNoPodIdPayload              = "../token/test_data/k8sNoPodIdPayload.json"
	k8sNoPodNamePayload            = "../token/test_data/k8sNoPodNamePayload.json"
	k8sNoNodePayload               = "../token/test_data/k8sNoNodePayload.json"
	k8sNoNodeIdPayload             = "../token/test_data/k8sNoNodeIdPayload.json"
	k8sNoNodeNamePayload           = "../token/test_data/k8sNoNodeNamePayload.json"
	k8sNoNamespacePayload          = "../token/test_data/k8sNoNamespacePayload.json"
	k8sPayload                     = "../token/test_data/k8sPayload.json"
	keycloakPayload                = "../token/test_data/keycloakPayload.json"
	keycloakNoRolesPayload         = "../token/test_data/keycloakNoRolesPayload.json"
)

func Test_GetOidcEndpointUrl(t *testing.T) {
	assert.Equal(t, "/.well-known/openid-configuration", GetOidcEndpointUrl(""))
	assert.Equal(t, "http://localhost:8080/.well-known/openid-configuration", GetOidcEndpointUrl("http://localhost:8080"))
	assert.Equal(t, "http://localhost:8080/.well-known/openid-configuration", GetOidcEndpointUrl("http://localhost:8080/"))
}
func Test_GetValue(t *testing.T) {
	value, err := GetValue(nil, Iss)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetValue(&jwt.Token{}, Iss)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetValue(&jwt.Token{Claims: KubernetesClaims{}}, Iss)
	assert.ErrorIs(t, err, ErrTokenClaimsUnsupported)
	assert.ErrorContains(t, err, "token has unsupported claims implementation: expected jwt.MapClaims, but got token.KubernetesClaims")

	token := test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetValue(token, Iss)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: iss is missed")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetValue(token, Iss)
	assert.Nil(t, err)
	assert.Equal(t, "https://kubernetes.default.svc.cluster.local", value)
}
func Test_GetStringValue(t *testing.T) {
	value, err := GetStringValue(nil, Iss)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetStringValue(&jwt.Token{}, Iss)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetStringValue(&jwt.Token{Claims: KubernetesClaims{}}, Iss)
	assert.ErrorIs(t, err, ErrTokenClaimsUnsupported)
	assert.ErrorContains(t, err, "token has unsupported claims implementation: expected jwt.MapClaims, but got token.KubernetesClaims")

	token := test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetStringValue(token, Iss)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: iss is missed")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetStringValue(token, Aud)
	assert.ErrorIs(t, err, jwt.ErrInvalidType)
	assert.ErrorContains(t, err, "invalid type for claim: aud is invalid, expected string, but got []interface {}")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetStringValue(token, Iss)
	assert.Nil(t, err)
	assert.Equal(t, "https://kubernetes.default.svc.cluster.local", value)
}
func Test_GetClaimStringsValue(t *testing.T) {
	value, err := GetClaimStringsValue(nil, Aud)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetClaimStringsValue(&jwt.Token{}, Aud)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetClaimStringsValue(&jwt.Token{Claims: KubernetesClaims{}}, Aud)
	assert.ErrorIs(t, err, ErrTokenClaimsUnsupported)
	assert.ErrorContains(t, err, "token has unsupported claims implementation: expected jwt.MapClaims, but got token.KubernetesClaims")

	token := test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetClaimStringsValue(token, Aud)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: aud is missed")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetClaimStringsValue(token, Exp)
	assert.ErrorIs(t, err, jwt.ErrInvalidType)
	assert.ErrorContains(t, err, "invalid type for claim: exp is invalid, expected string or []string, but got float64")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetClaimStringsValue(token, Aud)
	assert.Nil(t, err)
	assert.Equal(t, jwt.ClaimStrings{"audience1", "audience2"}, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value, err = GetClaimStringsValue(token, Aud)
	assert.Nil(t, err)
	assert.Equal(t, jwt.ClaimStrings{"audience1"}, value)

	claims := jwt.MapClaims{}
	claims[Aud] = []string{"a", "b"}
	value, err = GetClaimStringsValue(&jwt.Token{Claims: claims}, Aud)
	assert.Nil(t, err)
	assert.Equal(t, jwt.ClaimStrings{"a", "b"}, value)

	claims = jwt.MapClaims{}
	claims[Aud] = []any{"a", 1.5}
	value, err = GetClaimStringsValue(&jwt.Token{Claims: claims}, Aud)
	assert.ErrorIs(t, err, jwt.ErrInvalidType)
	assert.ErrorContains(t, err, "invalid type for claim: aud is invalid, expected string, but got float64")
}
func Test_GetNumericDateValue(t *testing.T) {
	value, err := GetNumericDateValue(nil, Exp)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetNumericDateValue(&jwt.Token{}, Exp)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetNumericDateValue(&jwt.Token{Claims: KubernetesClaims{}}, Exp)
	assert.ErrorIs(t, err, ErrTokenClaimsUnsupported)
	assert.ErrorContains(t, err, "token has unsupported claims implementation: expected jwt.MapClaims, but got token.KubernetesClaims")

	token := test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetNumericDateValue(token, Exp)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: exp is missed")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetNumericDateValue(token, Aud)
	assert.ErrorIs(t, err, jwt.ErrInvalidType)
	assert.ErrorContains(t, err, "invalid type for claim: aud is invalid, expected float64 or json.Number, but got []interface {}")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetNumericDateValue(token, Exp)
	assert.Nil(t, err)
	assert.Equal(t, jwt.NewNumericDate(time.Unix(1757656985, 0)), value)
}
func Test_GetMapValue(t *testing.T) {
	value, err := GetMapValue(nil, KubernetesIo)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetMapValue(&jwt.Token{}, KubernetesIo)
	assert.ErrorContains(t, err, "token is nil")

	value, err = GetMapValue(&jwt.Token{Claims: KubernetesClaims{}}, KubernetesIo)
	assert.ErrorIs(t, err, ErrTokenClaimsUnsupported)
	assert.ErrorContains(t, err, "token has unsupported claims implementation: expected jwt.MapClaims, but got token.KubernetesClaims")

	token := test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetMapValue(token, KubernetesIo)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: kubernetes.io is missed")

	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetMapValue(token, Aud)
	assert.ErrorIs(t, err, jwt.ErrInvalidType)
	assert.ErrorContains(t, err, "invalid type for claim: aud is invalid, expected map[string]any, but got []interface {}")

	var claims = jwt.MapClaims{
		Namespace: "namespace",
		Node: map[string]interface{}{
			Name: "node",
			Uid:  "225d44ac-4729-4277-bd20-450859a10d0f",
		},
		Pod: map[string]interface{}{
			Name: "pod",
			Uid:  "6b52c6a5-614f-484d-a329-80de170a45e6",
		},
		ServiceAccount: map[string]interface{}{
			Name: "service",
			Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
		},
	}
	token = test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err = GetMapValue(token, KubernetesIo)
	assert.Nil(t, err)
	assert.Equal(t, claims, value)
}
func Test_GetIssuer(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err := GetIssuer(token)
	assert.Nil(t, err)
	assert.Equal(t, "https://kubernetes.default.svc.cluster.local", value)
}
func Test_GetSubject(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err := GetSubject(token)
	assert.Nil(t, err)
	assert.Equal(t, "system:serviceaccount:namespace:service", value)
}
func Test_GetAudience(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err := GetAudience(token)
	assert.Nil(t, err)
	assert.Equal(t, jwt.ClaimStrings{"audience1", "audience2"}, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value, err = GetAudience(token)
	assert.Nil(t, err)
	assert.Equal(t, jwt.ClaimStrings{"audience1"}, value)
}
func Test_GetExpirationTime(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err := GetExpirationTime(token)
	assert.Nil(t, err)
	assert.Equal(t, jwt.NewNumericDate(time.Unix(1757656985, 0)), value)
}
func Test_GetIssuedAt(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err := GetIssuedAt(token)
	assert.Nil(t, err)
	assert.Equal(t, jwt.NewNumericDate(time.Unix(1757656385, 0)), value)
}
func Test_GetNotBefore(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err := GetNotBefore(token)
	assert.Nil(t, err)
	assert.Equal(t, jwt.NewNumericDate(time.Unix(1757656385, 0)), value)
}
func Test_GetId(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sMultiAudPayload)
	value, err := GetId(token)
	assert.Nil(t, err)
	assert.Equal(t, "cca3c408-f65c-4daa-a45e-5e390ffe0540", value)
}
func Test_GetFamilyName(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value, err := GetFamilyName(token)
	assert.Nil(t, err)
	assert.Equal(t, "family_name", value)
}
func Test_GetGivenName(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value, err := GetGivenName(token)
	assert.Nil(t, err)
	assert.Equal(t, "given_name", value)
}
func Test_GetEmail(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value, err := GetEmail(token)
	assert.Nil(t, err)
	assert.Equal(t, "email@gmail.com", value)
}
func Test_GetPhoneNumber(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value, err := GetPhoneNumber(token)
	assert.Nil(t, err)
	assert.Equal(t, "77777777", value)
}
func Test_GetPreferredUsername(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value, err := GetPreferredUsername(token)
	assert.Nil(t, err)
	assert.Equal(t, "preferred_username", value)
}
func Test_GetRealmAccess(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err := GetRealmAccess(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: realm_access is missed")

	token = test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value, err = GetRealmAccess(token)
	assert.Nil(t, err)
	expectedValue := RealmAccessClaim{
		Roles: []string{"ROLE_ROLE1", "ROLE_ROLE2"},
	}
	assert.Equal(t, expectedValue, value)
}
func Test_GetRoles(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err := GetRoles(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: realm_access is missed")

	token = test.CreateUnsignedTokenFromPayload(t, keycloakNoRolesPayload)
	value, err = GetRoles(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: roles is missed")

	token = test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value, err = GetRoles(token)
	assert.Nil(t, err)
	assert.Equal(t, jwt.ClaimStrings{"ROLE_ROLE1", "ROLE_ROLE2"}, value)
}
func Test_GetKubernetesSubject(t *testing.T) {
	assert.Equal(t, "system:serviceaccount:namespace:serviceAccount", GetKubernetesSubject("namespace", "serviceAccount"))
}
func Test_IsKubernetesToken(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, keycloakPayload)
	value := IsKubernetesToken(token)
	assert.False(t, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value = IsKubernetesToken(token)
	assert.True(t, value)
}
func Test_GetKubernetesIo(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value, err := GetKubernetesIo(token)
	assert.Nil(t, err)
	expectedValue := KubernetesIoClaim{
		Namespace: "namespace",
		ServiceAccount: ServiceAccountClaim{
			Name: "service",
			Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
		},
		Pod: PodClaim{
			Name: "pod",
			Uid:  "6b52c6a5-614f-484d-a329-80de170a45e6",
		},
		Node: NodeClaim{
			Name: "node",
			Uid:  "225d44ac-4729-4277-bd20-450859a10d0f",
		},
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoPodPayload)
	value, err = GetKubernetesIo(token)
	assert.Nil(t, err)
	expectedValue = KubernetesIoClaim{
		Namespace: "namespace",
		ServiceAccount: ServiceAccountClaim{
			Name: "service",
			Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
		},
		Node: NodeClaim{
			Name: "node",
			Uid:  "225d44ac-4729-4277-bd20-450859a10d0f",
		},
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoNodePayload)
	value, err = GetKubernetesIo(token)
	assert.Nil(t, err)
	expectedValue = KubernetesIoClaim{
		Namespace: "namespace",
		ServiceAccount: ServiceAccountClaim{
			Name: "service",
			Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
		},
		Pod: PodClaim{
			Name: "pod",
			Uid:  "6b52c6a5-614f-484d-a329-80de170a45e6",
		},
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoServiceAccountPayload)
	value, err = GetKubernetesIo(token)
	assert.Nil(t, err)
	expectedValue = KubernetesIoClaim{
		Namespace: "namespace",
		Pod: PodClaim{
			Name: "pod",
			Uid:  "6b52c6a5-614f-484d-a329-80de170a45e6",
		},
		Node: NodeClaim{
			Name: "node",
			Uid:  "225d44ac-4729-4277-bd20-450859a10d0f",
		},
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoNamespacePayload)
	value, err = GetKubernetesIo(token)
	assert.Nil(t, err)
	expectedValue = KubernetesIoClaim{
		ServiceAccount: ServiceAccountClaim{
			Name: "service",
			Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
		},
		Pod: PodClaim{
			Name: "pod",
			Uid:  "6b52c6a5-614f-484d-a329-80de170a45e6",
		},
		Node: NodeClaim{
			Name: "node",
			Uid:  "225d44ac-4729-4277-bd20-450859a10d0f",
		},
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetKubernetesIo(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: kubernetes.io is missed")
}
func Test_GetServiceAccount(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value, err := GetServiceAccount(token)
	assert.Nil(t, err)
	expectedValue := ServiceAccountClaim{
		Name: "service",
		Uid:  "530f2aa0-ed7b-4923-886b-2223a0dadae4",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoServiceAccountIdPayload)
	value, err = GetServiceAccount(token)
	assert.Nil(t, err)
	expectedValue = ServiceAccountClaim{
		Name: "service",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoServiceAccountNamePayload)
	value, err = GetServiceAccount(token)
	assert.Nil(t, err)
	expectedValue = ServiceAccountClaim{
		Uid: "530f2aa0-ed7b-4923-886b-2223a0dadae4",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetServiceAccount(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: kubernetes.io is missed")
}
func Test_GetNode(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value, err := GetNode(token)
	assert.Nil(t, err)
	expectedValue := NodeClaim{
		Name: "node",
		Uid:  "225d44ac-4729-4277-bd20-450859a10d0f",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoNodeIdPayload)
	value, err = GetNode(token)
	assert.Nil(t, err)
	expectedValue = NodeClaim{
		Name: "node",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoNodeNamePayload)
	value, err = GetNode(token)
	assert.Nil(t, err)
	expectedValue = NodeClaim{
		Uid: "225d44ac-4729-4277-bd20-450859a10d0f",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetNode(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: kubernetes.io is missed")
}
func Test_GetPod(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value, err := GetPod(token)
	assert.Nil(t, err)
	expectedValue := PodClaim{
		Name: "pod",
		Uid:  "6b52c6a5-614f-484d-a329-80de170a45e6",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoPodIdPayload)
	value, err = GetPod(token)
	assert.Nil(t, err)
	expectedValue = PodClaim{
		Name: "pod",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, k8sNoPodNamePayload)
	value, err = GetPod(token)
	assert.Nil(t, err)
	expectedValue = PodClaim{
		Uid: "6b52c6a5-614f-484d-a329-80de170a45e6",
	}
	assert.Equal(t, expectedValue, value)

	token = test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetPod(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: kubernetes.io is missed")
}
func Test_GetNamespace(t *testing.T) {
	token := test.CreateUnsignedTokenFromPayload(t, k8sPayload)
	value, err := GetNamespace(token)
	assert.Nil(t, err)
	assert.Equal(t, "namespace", value)

	token = test.CreateUnsignedTokenFromPayload(t, noClaimsPayload)
	value, err = GetNamespace(token)
	assert.ErrorIs(t, err, ErrTokenClaimMissing)
	assert.ErrorContains(t, err, "token is missing claim: kubernetes.io is missed")
}
