package token

import "github.com/golang-jwt/jwt/v5"

// see https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
// see https://www.keycloak.org/docs/latest/server_admin/index.html#_oidc_token_role_mappings
const (
	GivenName         = "given_name"
	FamilyName        = "family_name"
	Email             = "email"
	PhoneNumber       = "phone_number"
	PreferredUsername = "preferred_username"
	RealmAccess       = "realm_access"
	Roles             = "roles"
)

type KeycloakClaims struct {
	jwt.RegisteredClaims
	RealmAccess RealmAccessClaim `json:"realm_access"`
}

type RealmAccessClaim struct {
	Roles []string `json:"roles"`
}

func GetGivenName(token *jwt.Token) (string, error) {
	return GetStringValue(token, GivenName)
}
func GetFamilyName(token *jwt.Token) (string, error) {
	return GetStringValue(token, FamilyName)
}
func GetEmail(token *jwt.Token) (string, error) {
	return GetStringValue(token, Email)
}
func GetPhoneNumber(token *jwt.Token) (string, error) {
	return GetStringValue(token, PhoneNumber)
}
func GetPreferredUsername(token *jwt.Token) (string, error) {
	return GetStringValue(token, PreferredUsername)
}
func GetRealmAccess(token *jwt.Token) (RealmAccessClaim, error) {
	empty := RealmAccessClaim{}
	realmAccessMap, err := GetMapValue(token, RealmAccess)
	if err != nil {
		return empty, err
	}
	roles, _ := getClaimStringsValue(realmAccessMap, Roles)
	return RealmAccessClaim{
		Roles: roles,
	}, nil
}
func GetRoles(token *jwt.Token) (jwt.ClaimStrings, error) {
	realmAccessMap, err := GetMapValue(token, RealmAccess)
	if err != nil {
		return nil, err
	}
	roles, err := getClaimStringsValue(realmAccessMap, Roles)
	if err != nil {
		return nil, err
	}
	return roles, nil
}
