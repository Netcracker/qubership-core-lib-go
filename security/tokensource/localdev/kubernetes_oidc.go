package localdev

import (
	"net/url"
	"strings"
	"sync"
)

var (
	credentialsLock   sync.Mutex
	cachedCredentials *KubeConfigCredentials
)

// APIServerURL returns the kube API server URL from kubeconfig (cached).
func APIServerURL() (string, error) {
	creds, err := cachedKubeConfig()
	if err != nil {
		return "", err
	}
	return creds.ServerURL, nil
}

// UserToken returns the kubeconfig user token for Kubernetes API calls.
func UserToken() (string, error) {
	creds, err := cachedKubeConfig()
	if err != nil {
		return "", err
	}
	return creds.UserToken, nil
}

// JwksURL returns the reachable JWKS URL on the kube API server.
func JwksURL() (string, error) {
	server, err := APIServerURL()
	if err != nil {
		return "", err
	}
	return server + JwksPath, nil
}

// IsPublicOidcEndpoint reports whether the URL is served without authentication on the kube API.
func IsPublicOidcEndpoint(rawURL string) bool {
	if strings.TrimSpace(rawURL) == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return strings.Contains(rawURL, wellKnownOpenIDConfigPath) || strings.Contains(rawURL, JwksPath)
	}
	path := parsed.Path
	if path == "" {
		return false
	}
	return strings.HasSuffix(path, wellKnownOpenIDConfigPath) ||
		strings.HasSuffix(path, JwksPath) ||
		strings.Contains(path, JwksPath)
}

func cachedKubeConfig() (*KubeConfigCredentials, error) {
	credentialsLock.Lock()
	defer credentialsLock.Unlock()
	if cachedCredentials != nil {
		return cachedCredentials, nil
	}
	creds, err := LoadKubeConfig()
	if err != nil {
		return nil, err
	}
	cachedCredentials = creds
	kubeLogger.Infof("Local-dev kubeconfig: API server %s", creds.ServerURL)
	return cachedCredentials, nil
}

// ResetCache clears cached kubeconfig credentials (tests).
func ResetCache() {
	credentialsLock.Lock()
	defer credentialsLock.Unlock()
	cachedCredentials = nil
	ResetHTTPClient()
}
