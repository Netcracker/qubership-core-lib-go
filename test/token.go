package test

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func CreateSignedTokenString(t *testing.T, kid string, key crypto.PrivateKey, claims jwt.Claims) string {
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	unsignedToken.Header["kid"] = kid
	signedToken, err := unsignedToken.SignedString(key)
	assert.Nil(t, err)
	return signedToken
}

func CreateUnsignedTokenFromPayload(t *testing.T, filePath string) *jwt.Token {
	payload := LoadFileContent(t, filePath)
	var claims jwt.MapClaims
	err := json.Unmarshal(payload, &claims)
	assert.Nil(t, err)
	return &jwt.Token{
		Claims: claims,
	}
}
