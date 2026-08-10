package internal

import "time"

const (
	applicationJSON           = "application/json"
	applicationFormURLEncoded = "application/x-www-form-urlencoded"
	authorizationHeader       = "Authorization"
	contentTypeHeader         = "Content-Type"
	acceptHeader              = "Accept"
	bearerPrefix              = "Bearer "

	defaultKubernetesIssuer = "https://kubernetes.default.svc"
	jwksPath                = "/openid/v1/jwks"

	tokenRequestExpirationSeconds = 28800 // 8 hours
	maxErrorBodyLength            = 500
	jwtBase64PadLength            = 4

	httpRequestTimeout        = 30 * time.Second
	httpMaxIdleConns          = 100
	httpIdleConnTimeout       = 90 * time.Second
	httpTLSHandshakeTimeout   = 10 * time.Second
	httpExpectContinueTimeout = 1 * time.Second
	kubeConfigExecTimeout     = 30 * time.Second
	oidcExpirySkew            = 60 * time.Second
	tokenCacheExpirySkew      = 5 * time.Minute

	tokenRequestAPIVersion            = "authentication.k8s.io/v1"
	tokenRequestKind                  = "TokenRequest"
	tokenRequestSpecAudiences         = "audiences"
	tokenRequestSpecExpirationSeconds = "expirationSeconds"

	oidcGrantRefreshToken = "refresh_token"
	oidcFormClientID      = "client_id"
	oidcFormClientSecret  = "client_secret"
	oidcFormGrantType     = "grant_type"

	oidcAuthProviderName = "oidc"
)

// Kubeconfig YAML / map field names.
const (
	kubeConfigCluster                  = "cluster"
	kubeConfigUser                     = "user"
	kubeConfigName                     = "name"
	kubeConfigServer                   = "server"
	kubeConfigToken                    = "token"
	kubeConfigCertificateAuthorityData = "certificate-authority-data"
	kubeConfigInsecureSkipTLSVerify    = "insecure-skip-tls-verify"
	kubeConfigAuthProvider             = "auth-provider"
	kubeConfigExec                     = "exec"
	kubeConfigCommand                  = "command"
	kubeConfigArgs                     = "args"
	kubeConfigEnv                      = "env"
	kubeConfigValue                    = "value"
	kubeConfigConfig                   = "config"
	kubeConfigIDToken                  = "id-token"
	kubeConfigAccessToken              = "access-token"
	kubeConfigRefreshToken             = "refresh-token"
	kubeConfigIDPIssuerURL             = "idp-issuer-url"
	kubeConfigClientID                 = "client-id"
	kubeConfigClientSecret             = "client-secret"
)
