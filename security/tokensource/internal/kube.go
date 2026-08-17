package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
)

var kubeLogger = logging.GetLogger("kubeconfig-loader")

// KubeLocalDevConfig is kubeconfig-backed Kubernetes OIDC helpers for local-dev
// (JWKS URL rewrite, issuer discovery). Instance-scoped, like Java KubeLocalDevConfig.
type KubeLocalDevConfig struct {
	credentials *KubeConfigCredentials
	httpClient  *http.Client
}

func NewKubeLocalDevConfig() *KubeLocalDevConfig {
	return &KubeLocalDevConfig{}
}

func (c *KubeLocalDevConfig) APIServerURL() (string, error) {
	creds, err := c.loadCredentials()
	if err != nil {
		return "", err
	}
	return creds.ServerURL, nil
}

func (c *KubeLocalDevConfig) UserToken() (string, error) {
	creds, err := c.loadCredentials()
	if err != nil {
		return "", err
	}
	return creds.UserToken, nil
}

func (c *KubeLocalDevConfig) JwksURL() (string, error) {
	server, err := c.APIServerURL()
	if err != nil {
		return "", err
	}
	return server + jwksPath, nil
}

func (c *KubeLocalDevConfig) FetchJwks() (string, error) {
	jwksURL, err := c.JwksURL()
	if err != nil {
		return "", err
	}
	body, err := c.getPublicJSON(jwksURL)
	if err != nil {
		return "", fmt.Errorf("local-dev JWKS fetch failed for %s: %w", jwksURL, err)
	}
	return string(body), nil
}

func (c *KubeLocalDevConfig) IsPublicOidcEndpoint(rawURL string) bool {
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

func (c *KubeLocalDevConfig) HTTPClient() (*http.Client, error) {
	if c.httpClient != nil {
		return c.httpClient, nil
	}
	creds, err := c.loadCredentials()
	if err != nil {
		return nil, err
	}
	c.httpClient = newHTTPClient(creds)
	return c.httpClient, nil
}

func (c *KubeLocalDevConfig) DiscoveryURL() (string, error) {
	server, err := c.APIServerURL()
	if err != nil {
		return "", err
	}
	return oidc.GetProviderUrl(server)
}

func (c *KubeLocalDevConfig) ResolveIssuerClaimFromDiscovery() (string, error) {
	discoveryURL, err := c.DiscoveryURL()
	if err != nil {
		return DefaultKubernetesIssuer, err
	}
	body, err := c.getPublicJSON(discoveryURL)
	if err != nil {
		kubeLogger.Warnf("failed to resolve Kubernetes issuer from discovery at %s in local-dev, using default %s: %v",
			discoveryURL, DefaultKubernetesIssuer, err)
		return DefaultKubernetesIssuer, nil
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err = json.Unmarshal(body, &discovery); err != nil {
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

func (c *KubeLocalDevConfig) loadCredentials() (*KubeConfigCredentials, error) {
	if c.credentials != nil {
		return c.credentials, nil
	}
	creds, err := LoadKubeConfig()
	if err != nil {
		return nil, err
	}
	c.credentials = creds
	kubeLogger.Infof("local-dev kubeconfig: API server %s", creds.ServerURL)
	return c.credentials, nil
}

func acceptHeaderFor(rawURL string) string {
	if strings.Contains(rawURL, jwksPath) {
		return applicationJWKSetJSON
	}
	return applicationJSON
}

func (c *KubeLocalDevConfig) getPublicJSON(rawURL string) ([]byte, error) {
	body, retryable, err := c.sendGet(rawURL)
	if err != nil && retryable {
		kubeLogger.Debugf("retrying Kubernetes OIDC request after I/O failure for %s: %v", rawURL, err)
		c.httpClient = nil
		body, _, err = c.sendGet(rawURL)
	}
	return body, err
}

func (c *KubeLocalDevConfig) sendGet(rawURL string) ([]byte, bool, error) {
	client, err := c.HTTPClient()
	if err != nil {
		return nil, true, err
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set(acceptHeader, acceptHeaderFor(rawURL))
	if !c.IsPublicOidcEndpoint(rawURL) {
		token, tokenErr := c.UserToken()
		if tokenErr != nil {
			return nil, true, tokenErr
		}
		req.Header.Set(authorizationHeader, bearerPrefix+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, err
	}
	if isFailed(resp.StatusCode) {
		return nil, false, fmt.Errorf("HTTP %d for %s: %s", resp.StatusCode, rawURL, truncateResponseBody(body))
	}
	return body, false, nil
}
