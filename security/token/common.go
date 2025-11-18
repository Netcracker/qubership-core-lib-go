package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Kid header. The key ID is a hint indicating which key was used to secure the JWS.
//   - OpenID Connect Core 1.0, Section 10.1 “Signing”:
//     https://openid.net/specs/openid-connect-core-1_0.html#Signing
const (
	Kid = "kid"
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
	claimIsInvalid = "%w: %s is invalid, expected %s, but got %T"
	claimIsMissed  = "%w: %s is missed"
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
func Value(claims jwt.MapClaims, claim string) (any, error) {
	if value, found := claims[claim]; found {
		return value, nil
	}
	return nil, fmt.Errorf(claimIsMissed, ErrTokenClaimMissing, claim)
}
func StringValue(claims jwt.MapClaims, claim string) (string, error) {
	value, err := Value(claims, claim)
	if err != nil {
		return "", err
	}
	if stringValue, ok := value.(string); ok {
		return stringValue, nil
	}
	return "", fmt.Errorf(claimIsInvalid, jwt.ErrInvalidType, claim, "string", value)
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
				return nil, fmt.Errorf(claimIsInvalid, jwt.ErrInvalidType, claim, "string", vv)
			}
		}
	default:
		return nil, fmt.Errorf(claimIsInvalid, jwt.ErrInvalidType, claim, "string or []string", value)
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
	return nil, fmt.Errorf(claimIsInvalid, jwt.ErrInvalidType, claim, "float64 or json.Number", value)
}
func MapValue(claims jwt.MapClaims, claim string) (jwt.MapClaims, error) {
	value, err := Value(claims, claim)
	if err != nil {
		return nil, err
	}
	if mapValue, ok := value.(map[string]any); ok {
		return mapValue, nil
	}
	return nil, fmt.Errorf(claimIsInvalid, jwt.ErrInvalidType, claim, "map[string]any", value)
}
func GetRegisteredClaims(token *jwt.Token) (jwt.RegisteredClaims, error) {
	claims, err := getMapClaims(token)
	if err != nil {
		return jwt.RegisteredClaims{}, err
	}
	issuer, _ := StringValue(claims, Iss)
	subject, _ := StringValue(claims, Sub)
	audience, _ := ClaimStringsValue(claims, Aud)
	expiredAt, _ := NumericDateValue(claims, Exp)
	notBefore, _ := NumericDateValue(claims, Nbf)
	issuedAt, _ := NumericDateValue(claims, Iat)
	id, _ := StringValue(claims, Jti)
	return jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		ExpiresAt: expiredAt,
		NotBefore: notBefore,
		IssuedAt:  issuedAt,
		ID:        id,
	}, nil
}
func getMapClaims(token *jwt.Token) (jwt.MapClaims, error) {
	if token == nil || token.Claims == nil {
		return nil, fmt.Errorf("token is nil")
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, fmt.Errorf("%w: expected jwt.MapClaims, but got %T", ErrTokenClaimsUnsupported, token.Claims)
}
func newNumericDateFromSeconds(f float64) *jwt.NumericDate {
	round, frac := math.Modf(f)
	return jwt.NewNumericDate(time.Unix(int64(round), int64(frac*1e9)))
}
