package test

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/stretchr/testify/assert"
)

const (
	DefaultKid         = "kid-1"
	JwksSubPath        = "/openid/v1/jwks"
	ServiceAccount     = "test-service-account"
	Namespace          = "test-namespace"
	Uuid               = "test-uuid"
	KubernetesAudience = "https://kubernetes.default.svc.cluster.local"
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
func CreateServiceAccountToken(t *testing.T, issuer, kid string, key crypto.PrivateKey) string {
	return CreateSignedTokenString(t, kid, key, token.KubernetesClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   token.GetKubernetesSubject(Namespace, ServiceAccount),
			Audience:  jwt.ClaimStrings{KubernetesAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		KubernetesIo: token.KubernetesIoClaim{
			Namespace: Namespace,
			ServiceAccount: token.ServiceAccountClaim{
				Name: ServiceAccount,
				Uid:  Uuid,
			},
		},
	})
}
func ToHexBase64(a *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(a.Bytes())
}
func AddDefaultKubernetesProviderHandler(serviceAccountToken, issuer string) {
	response := oidc.ProviderResponse{
		Issuer:  issuer,
		JwksUri: issuer + JwksSubPath,
	}
	responseBody, _ := json.Marshal(response)
	AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, responseBody)
}
func AddKubernetesProviderHandler(serviceAccountToken string, statusCode int, responseBody []byte) {
	AddKubernetesHandler(oidc.ProviderSubPath, serviceAccountToken, statusCode, responseBody)
}
func AddDefaultKubernetesJwksHandler(serviceAccountToken string, privateKeys map[string]*rsa.PrivateKey) {
	var keySet []jwkset.JWKMarshal
	for kid, privateKey := range privateKeys {
		keySet = append(keySet, jwkset.JWKMarshal{
			KTY: "RSA",
			KID: kid,
			ALG: jwkset.ALG(jwt.SigningMethodRS256.Alg()),
			USE: "sig",
			N:   ToHexBase64(privateKey.N),
			E:   ToHexBase64(big.NewInt(int64(privateKey.E))),
		})
	}
	jwks := &jwkset.JWKSMarshal{
		Keys: keySet,
	}
	responseBody, _ := json.Marshal(jwks)
	AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, responseBody)
}
func AddKubernetesJwksHandler(serviceAccountToken string, statusCode int, responseBody []byte) {
	AddKubernetesHandler(JwksSubPath, serviceAccountToken, statusCode, responseBody)
}
func AddKubernetesHandler(path, serviceAccountToken string, statusCode int, responseBody []byte) {
	AddHandler(Contains(path),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+serviceAccountToken {
				responseWriter.WriteHeader(http.StatusUnauthorized)
				logger.Infof("request to %s, response %v", path, http.StatusUnauthorized)
				return
			}
			if responseBody != nil {
				responseWriter.WriteHeader(statusCode)
				_, _ = responseWriter.Write(responseBody)
				logger.Infof("request to %s, response %v:%s", path, http.StatusOK, string(responseBody))
			}
		})
}
