package test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
)

const (
	DefaultKid         = "kid-1"
	JwksSubPath        = "/openid/v1/jwks"
	ServiceAccount     = "test-service-account"
	Namespace          = "test-namespace"
	Uuid               = "test-uuid"
	KubernetesAudience = "https://kubernetes.default.svc.cluster.local"
)

var (
	DefaultKey  *rsa.PrivateKey
	DefaultKeys map[string]*rsa.PrivateKey
)

func init() {
	DefaultKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	DefaultKeys = make(map[string]*rsa.PrivateKey)
	DefaultKeys[DefaultKid] = DefaultKey
}
func LoadFileContent(filePath string) []byte {
	absPath, _ := filepath.Abs(filePath)
	content, _ := os.ReadFile(absPath)
	return content
}
func CreateSignedToken(kid string, key crypto.PrivateKey, claims jwt.Claims) string {
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	unsignedToken.Header["kid"] = kid
	signedToken, _ := unsignedToken.SignedString(key)
	return signedToken
}
func CreateDefaultSignedToken(claims jwt.Claims) string {
	return CreateSignedToken(DefaultKid, DefaultKey, claims)
}
func CreateUnsignedTokenFromFile(filePath string) *jwt.Token {
	payload := LoadFileContent(filePath)
	var claims jwt.MapClaims
	_ = json.Unmarshal(payload, &claims)
	return &jwt.Token{
		Claims: claims,
	}
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
type MockTokenSource struct {
	AudienceToken string
	AudienceTokenError error
	ServiceAccountToken string
	ServiceAccountTokenError error
}
func (t MockTokenSource) GetAudienceToken(_ context.Context, _ tokensource.TokenAudience) (string, error) {
	if t.AudienceTokenError != nil {
		return "", t.AudienceTokenError
	}
	return t.AudienceToken, nil
}
func (t MockTokenSource) GetServiceAccountToken(_ context.Context) (string, error) {
	if t.ServiceAccountTokenError != nil {
		return "", t.ServiceAccountTokenError
	}
	return t.ServiceAccountToken, nil
}
