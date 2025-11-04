package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"
)

// Standard JWT claim names used in OpenID Connect and JSON Web Tokens (JWT).
// These constants represent the registered claim names defined in:
//   - OpenID Connect Core 1.0, Section 2 “ID Token”:
//     https://openid.net/specs/openid-connect-core-1_0.html#IDToken
//   - RFC 7519 “JSON Web Token (JWT)”:
//     https://datatracker.ietf.org/doc/html/rfc7519
//
// The claims are commonly included in ID Tokens issued by OpenID Providers and
// are used for subject identification, audience restriction, and token lifetime validation.
const (
	Iss = "iss"
	Sub = "sub"
	Aud = "aud"
	Exp = "exp"
	Nbf = "nbf"
	Iat = "iat"
	Jti = "jti"
)

const (
	claimIsInvalid = "%s is invalid, expected %s, but got %T"
	claimIsMissed  = "%s is missed"
)

var (
	ErrTokenClaimMissing      = errors.New("token is missing claim")
	ErrTokenClaimsUnsupported = errors.New("token has unsupported claims implementation")
)

func GetValue(token *jwt.Token, claim string) (any, error) {
	claims, err := getMapClaims(token)
	if err != nil {
		return nil, err
	}
	return Value(claims, claim)
}
func GetStringValue(token *jwt.Token, claim string) (string, error) {
	claims, err := getMapClaims(token)
	if err != nil {
		return "", err
	}
	return StringValue(claims, claim)
}
func GetClaimStringsValue(token *jwt.Token, claim string) (jwt.ClaimStrings, error) {
	claims, err := getMapClaims(token)
	if err != nil {
		return nil, err
	}
	return ClaimStringsValue(claims, claim)
}
func GetNumericDateValue(token *jwt.Token, claim string) (*jwt.NumericDate, error) {
	claims, err := getMapClaims(token)
	if err != nil {
		return nil, err
	}
	return NumericDateValue(claims, claim)
}
func GetMapValue(token *jwt.Token, claim string) (jwt.MapClaims, error) {
	claims, err := getMapClaims(token)
	if err != nil {
		return nil, err
	}
	return MapValue(claims, claim)
}
func GetIssuer(token *jwt.Token) (string, error) {
	return GetStringValue(token, Iss)
}
func GetSubject(token *jwt.Token) (string, error) {
	return GetStringValue(token, Sub)
}
func GetAudience(token *jwt.Token) (jwt.ClaimStrings, error) {
	return GetClaimStringsValue(token, Aud)
}
func GetExpirationTime(token *jwt.Token) (*jwt.NumericDate, error) {
	return GetNumericDateValue(token, Exp)
}
func GetNotBefore(token *jwt.Token) (*jwt.NumericDate, error) {
	return GetNumericDateValue(token, Nbf)
}
func GetIssuedAt(token *jwt.Token) (*jwt.NumericDate, error) {
	return GetNumericDateValue(token, Iat)
}
func GetId(token *jwt.Token) (string, error) {
	return GetStringValue(token, Jti)
}
func getMapClaims(token *jwt.Token) (jwt.MapClaims, error) {
	if token == nil || token.Claims == nil {
		return nil, fmt.Errorf("token is nil")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, utils.NewError(fmt.Sprintf("expected jwt.MapClaims, but got %T", token.Claims), ErrTokenClaimsUnsupported)
}
func Value(claims jwt.MapClaims, claim string) (any, error) {
	if value, found := claims[claim]; found {
		return value, nil
	}
	return nil, utils.NewError(fmt.Sprintf(claimIsMissed, claim), ErrTokenClaimMissing)
}
func StringValue(claims jwt.MapClaims, claim string) (string, error) {
	value, err := Value(claims, claim)
	if err != nil {
		return "", err
	}
	if stringValue, ok := value.(string); ok {
		return stringValue, nil
	}
	return "", utils.NewError(fmt.Sprintf(claimIsInvalid, claim, "string", value), jwt.ErrInvalidType)
}
func ClaimStringsValue(claims jwt.MapClaims, claim string) (jwt.ClaimStrings, error) {
	value, err := Value(claims, claim)
	if err != nil {
		return nil, err
	}
	var array []string
	switch v := value.(type) {
	case string:
		array = append(array, v)
	case []string:
		array = v
	case []any:
		for _, vv := range v {
			if vs, ok := vv.(string); ok {
				array = append(array, vs)
			} else {
				return nil, utils.NewError(fmt.Sprintf(claimIsInvalid, claim, "string", vv), jwt.ErrInvalidType)
			}
		}
	default:
		return nil, utils.NewError(fmt.Sprintf(claimIsInvalid, claim, "string or []string", value), jwt.ErrInvalidType)
	}
	return array, nil
}
func NumericDateValue(claims jwt.MapClaims, claim string) (*jwt.NumericDate, error) {
	value, err := Value(claims, claim)
	if err != nil {
		return nil, err
	}
	switch date := value.(type) {
	case float64:
		if date == 0 {
			return nil, nil
		}
		return newNumericDateFromSeconds(date), nil
	case json.Number:
		v, _ := date.Float64()
		return newNumericDateFromSeconds(v), nil
	}
	return nil, utils.NewError(fmt.Sprintf(claimIsInvalid, claim, "float64 or json.Number", value), jwt.ErrInvalidType)
}
func newNumericDateFromSeconds(f float64) *jwt.NumericDate {
	round, frac := math.Modf(f)
	return jwt.NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}
func MapValue(claims jwt.MapClaims, claim string) (jwt.MapClaims, error) {
	value, err := Value(claims, claim)
	if err != nil {
		return nil, err
	}
	if mapValue, ok := value.(map[string]any); ok {
		return mapValue, nil
	}
	return nil, utils.NewError(fmt.Sprintf(claimIsInvalid, claim, "map[string]any", value), jwt.ErrInvalidType)
}
