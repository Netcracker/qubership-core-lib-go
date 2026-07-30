package localdev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
)

var (
	httpClientLock   sync.Mutex
	cachedHTTPClient *http.Client
)

// HTTPClient returns an HTTP client configured with kubeconfig TLS (cached).
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

// ResetHTTPClient clears cached HTTP client (tests).
func ResetHTTPClient() {
	httpClientLock.Lock()
	defer httpClientLock.Unlock()
	cachedHTTPClient = nil
}

// DiscoveryURL returns the OIDC discovery URL on the reachable kube API server.
func DiscoveryURL() (string, error) {
	server, err := APIServerURL()
	if err != nil {
		return "", err
	}
	return oidc.GetProviderUrl(server)
}

// IsKubernetesIssuer reports whether the value looks like a Kubernetes cluster issuer.
func IsKubernetesIssuer(issuerOrURL string) bool {
	if strings.TrimSpace(issuerOrURL) == "" {
		return false
	}
	normalized := strings.ToLower(issuerOrURL)
	return strings.Contains(normalized, "kubernetes.default.svc") ||
		strings.Contains(normalized, "kubernetes.default")
}

// ResolveIssuerClaimFromDiscovery reads issuer from kube API OIDC discovery (no projected SA token required).
func ResolveIssuerClaimFromDiscovery() (string, error) {
	discoveryURL, err := DiscoveryURL()
	if err != nil {
		return DefaultKubernetesIssuer, err
	}
	body, err := getPublicJSON(discoveryURL)
	if err != nil {
		kubeLogger.Warnf("failed to resolve Kubernetes issuer from discovery at %s in local-dev, using default %s: %v",
			discoveryURL, DefaultKubernetesIssuer, err)
		return DefaultKubernetesIssuer, nil
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &discovery); err != nil {
		kubeLogger.Warnf("failed to parse OIDC discovery at %s in local-dev, using default %s: %v",
			discoveryURL, DefaultKubernetesIssuer, err)
		return DefaultKubernetesIssuer, nil
	}
	if strings.TrimSpace(discovery.Issuer) != "" {
		return discovery.Issuer, nil
	}
	kubeLogger.Warnf("oidc discovery at %s has no issuer in local-dev, using default %s", discoveryURL, DefaultKubernetesIssuer)
	return DefaultKubernetesIssuer, nil
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
