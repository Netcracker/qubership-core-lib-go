package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
)

var kubeLogger = logging.GetLogger("kubeconfig-loader")

var (
	credentialsLock   sync.Mutex
	cachedCredentials *KubeConfigCredentials

	httpClientLock   sync.Mutex
	cachedHTTPClient *http.Client
)

func APIServerURL() (string, error) {
	creds, err := cachedKubeConfig()
	if err != nil {
		return "", err
	}
	return creds.ServerURL, nil
}

func UserToken() (string, error) {
	creds, err := cachedKubeConfig()
	if err != nil {
		return "", err
	}
	return creds.UserToken, nil
}

func JwksURL() (string, error) {
	server, err := APIServerURL()
	if err != nil {
		return "", err
	}
	return server + jwksPath, nil
}

func IsPublicOidcEndpoint(rawURL string) bool {
	if strings.TrimSpace(rawURL) == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return strings.Contains(rawURL, oidc.ProviderSubPath) || strings.Contains(rawURL, jwksPath)
	}
	path := parsed.Path
	if path == "" {
		return false
	}
	return strings.HasSuffix(path, oidc.ProviderSubPath) ||
		strings.HasSuffix(path, jwksPath) ||
		strings.Contains(path, jwksPath)
}

func HTTPClient() (*http.Client, error) {
	httpClientLock.Lock()
	defer httpClientLock.Unlock()
	if cachedHTTPClient != nil {
		return cachedHTTPClient, nil
	}
	creds, err := cachedKubeConfig()
	if err != nil {
		return nil, err
	}
	cachedHTTPClient = newHTTPClient(creds)
	return cachedHTTPClient, nil
}

func resetHTTPClient() {
	httpClientLock.Lock()
	defer httpClientLock.Unlock()
	cachedHTTPClient = nil
}

func DiscoveryURL() (string, error) {
	server, err := APIServerURL()
	if err != nil {
		return "", err
	}
	return oidc.GetProviderUrl(server)
}

func IsKubernetesIssuer(issuerOrURL string) bool {
	if strings.TrimSpace(issuerOrURL) == "" {
		return false
	}
	normalized := strings.ToLower(issuerOrURL)
	return strings.Contains(normalized, "kubernetes.default.svc") ||
		strings.Contains(normalized, "kubernetes.default")
}

func ResolveIssuerClaimFromDiscovery() (string, error) {
	discoveryURL, err := DiscoveryURL()
	if err != nil {
		return defaultKubernetesIssuer, err
	}
	body, err := getPublicJSON(discoveryURL)
	if err != nil {
		kubeLogger.Warnf("failed to resolve Kubernetes issuer from discovery at %s in local-dev, using default %s: %v",
			discoveryURL, defaultKubernetesIssuer, err)
		return defaultKubernetesIssuer, nil
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err = json.Unmarshal(body, &discovery); err != nil {
		kubeLogger.Warnf("failed to parse OIDC discovery at %s in local-dev, using default %s: %v",
			discoveryURL, defaultKubernetesIssuer, err)
		return defaultKubernetesIssuer, nil
	}
	if strings.TrimSpace(discovery.Issuer) != "" {
		return discovery.Issuer, nil
	}
	kubeLogger.Warnf("oidc discovery at %s has no issuer in local-dev, using default %s", discoveryURL, defaultKubernetesIssuer)
	return defaultKubernetesIssuer, nil
}

func ResetCache() {
	credentialsLock.Lock()
	defer credentialsLock.Unlock()
	cachedCredentials = nil
	resetHTTPClient()
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
	kubeLogger.Infof("local-dev kubeconfig: API server %s", creds.ServerURL)
	return cachedCredentials, nil
}

func getPublicJSON(url string) ([]byte, error) {
	client, err := HTTPClient()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(acceptHeader, applicationJSON)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if isFailed(resp.StatusCode) {
		return nil, fmt.Errorf("HTTP %d for %s: %s", resp.StatusCode, url, truncateResponseBody(body))
	}
	return body, nil
}
