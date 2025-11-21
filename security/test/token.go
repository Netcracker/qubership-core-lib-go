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

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
	"github.com/netcracker/qubership-core-lib-go/v3/security/tokensource"
	mockServer "github.com/netcracker/qubership-core-lib-go/v3/test"
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
	logger            = logging.GetLogger("security-test")
	DefaultPrivateKey *rsa.PrivateKey
	DefaultPublicKeys map[string]rsa.PublicKey
)

func MustInitDefaultTestKeys() {
	var err error
	DefaultPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	DefaultPublicKeys = make(map[string]rsa.PublicKey)
	DefaultPublicKeys[DefaultKid] = DefaultPrivateKey.PublicKey
}
func MustCreateSignedToken(kid string, key crypto.PrivateKey, claims jwt.Claims) string {
	unsignedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	unsignedToken.Header["kid"] = kid
	signedToken, err := unsignedToken.SignedString(key)
	if err != nil {
		panic(err)
	}
	return signedToken
}
func MustCreateDefaultSignedToken(claims jwt.Claims) string {
	return MustCreateSignedToken(DefaultKid, DefaultPrivateKey, claims)
}
func MustCreateUnsignedToken(payload []byte) *jwt.Token {
	var claims jwt.MapClaims
	err := json.Unmarshal(payload, &claims)
	if err != nil {
		panic(err)
	}
	return &jwt.Token{
		Claims: claims,
	}
}
func ToHexBase64(a *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(a.Bytes())
}
func MustAddDefaultKubernetesProviderHandler(serviceAccountToken, issuer string) {
	response := oidc.ProviderResponse{
		Issuer:  issuer,
		JwksUri: issuer + JwksSubPath,
	}
	responseBody, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}
	AddKubernetesProviderHandler(serviceAccountToken, http.StatusOK, responseBody)
}
func AddKubernetesProviderHandler(serviceAccountToken string, statusCode int, responseBody []byte) {
	AddKubernetesHandler(oidc.ProviderSubPath, serviceAccountToken, statusCode, responseBody)
}
func MustAddDefaultKubernetesJwksHandler(serviceAccountToken string, publicKeys map[string]rsa.PublicKey) {
	var keySet []jwkset.JWKMarshal
	for kid, publicKey := range publicKeys {
		keySet = append(keySet, jwkset.JWKMarshal{
			KTY: "RSA",
			KID: kid,
			ALG: jwkset.ALG(jwt.SigningMethodRS256.Alg()),
			USE: "sig",
			N:   ToHexBase64(publicKey.N),
			E:   ToHexBase64(big.NewInt(int64(publicKey.E))),
		})
	}
	jwks := &jwkset.JWKSMarshal{
		Keys: keySet,
	}
	responseBody, err := json.Marshal(jwks)
	if err != nil {
		panic(err)
	}
	AddKubernetesJwksHandler(serviceAccountToken, http.StatusOK, responseBody)
}
func AddKubernetesJwksHandler(serviceAccountToken string, statusCode int, responseBody []byte) {
	AddKubernetesHandler(JwksSubPath, serviceAccountToken, statusCode, responseBody)
}
func AddKubernetesHandler(path, serviceAccountToken string, statusCode int, responseBody []byte) {
	mockServer.AddHandler(mockServer.Contains(path),
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+serviceAccountToken {
				responseWriter.WriteHeader(http.StatusUnauthorized)
				logger.Infof("request to %s, response %v", path, http.StatusUnauthorized)
				return
			}
			if responseBody != nil {
				responseWriter.WriteHeader(statusCode)
				_, err := responseWriter.Write(responseBody)
				if err != nil {
					panic(err)
				}
				logger.Infof("request to %s, response %v:%s", path, http.StatusOK, string(responseBody))
			}
		})
}

type MockTokenSource struct {
	AudienceToken            string
	AudienceTokenError       error
	ServiceAccountToken      string
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
