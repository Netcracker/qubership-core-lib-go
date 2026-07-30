package localdev

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/security/oidc"
)

var oidcLogger = logging.GetLogger("oidc-auth-provider")

func resolveOidcAuthProviderToken(config map[string]any) (string, error) {
	client := idpHTTPClient()
	cached := firstNonBlank(
		getKubeConfigStringField(config, kubeConfigIDToken),
		getKubeConfigStringField(config, kubeConfigAccessToken),
	)
	if cached != "" && !isJwtExpired(cached) {
		oidcLogger.Debug("using non-expired oidc id-token from kubeconfig auth-provider")
		return cached, nil
	}
	issuerURL := getKubeConfigStringField(config, kubeConfigIDPIssuerURL)
	refreshToken := getKubeConfigStringField(config, kubeConfigRefreshToken)
	clientID := getKubeConfigStringField(config, kubeConfigClientID)
	clientSecret := getKubeConfigStringField(config, kubeConfigClientSecret)
	if issuerURL == "" || refreshToken == "" || clientID == "" {
		if cached != "" {
			oidcLogger.Warn("oidc auth-provider id-token is expired or missing refresh fields; falling back to cached token")
			return cached, nil
		}
		return "", nil
	}
	oidcLogger.Infof("refreshing oidc kubeconfig token via idp-issuer-url=%s", issuerURL)
	tokenEndpoint, err := discoverTokenEndpoint(client, issuerURL)
	if err != nil {
		if cached != "" {
			oidcLogger.Warnf("oidc token refresh failed; falling back to cached id-token: %v", err)
			return cached, nil
		}
		return "", err
	}
	token, err := refreshIdToken(client, tokenEndpoint, clientID, clientSecret, refreshToken)
	if err != nil {
		if cached != "" {
			oidcLogger.Warnf("oidc token refresh failed; falling back to cached id-token: %v", err)
			return cached, nil
		}
		return "", err
	}
	return token, nil
}

func idpHTTPClient() *http.Client {
	if IsEnabled() && isInsecureIdpTlsEnabled() {
		return newInsecureIdpHTTPClient()
	}
	return &http.Client{Timeout: httpRequestTimeout}
}

func discoverTokenEndpoint(client *http.Client, issuerURL string) (string, error) {
	discoveryURL, err := oidc.GetProviderUrl(issuerURL)
	if err != nil {
		return "", fmt.Errorf("oidc discovery URL invalid for %s: %w", issuerURL, err)
	}
	req, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(acceptHeader, applicationJSON)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc discovery failed for %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if isFailed(resp.StatusCode) {
		return "", fmt.Errorf("oidc discovery failed (HTTP %d) for %s: %s",
			resp.StatusCode, discoveryURL, truncateResponseBody(body))
	}
	var doc struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("oidc discovery failed for %s: %w", discoveryURL, err)
	}
	if doc.TokenEndpoint == "" {
		return "", fmt.Errorf("oidc discovery response has no token_endpoint: %s", discoveryURL)
	}
	return doc.TokenEndpoint, nil
}

func refreshIdToken(client *http.Client, tokenEndpoint, clientID, clientSecret, refreshToken string) (string, error) {
	form := url.Values{}
	form.Set(oidcFormGrantType, oidcGrantRefreshToken)
	form.Set(oidcGrantRefreshToken, refreshToken)
	form.Set(oidcFormClientID, clientID)
	if clientSecret != "" {
		form.Set(oidcFormClientSecret, clientSecret)
	}
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set(contentTypeHeader, applicationFormURLEncoded)
	req.Header.Set(acceptHeader, applicationJSON)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc refresh_token grant failed for %s: %w", tokenEndpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if isFailed(resp.StatusCode) {
		return "", fmt.Errorf("oidc refresh_token grant failed (HTTP %d) for %s: %s",
			resp.StatusCode, tokenEndpoint, truncateResponseBody(body))
	}
	var tokenResponse struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", err
	}
	token := firstNonBlank(tokenResponse.IDToken, tokenResponse.AccessToken)
	if token == "" {
		return "", fmt.Errorf("oidc token response has neither id_token nor access_token: %s", tokenEndpoint)
	}
	return token, nil
}

func isJwtExpired(jwt string) bool {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(padBase64Url(parts[1]))
	if err != nil {
		return true
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return true
	}
	return time.Now().Add(oidcExpirySkew).After(time.Unix(claims.Exp, 0))
}
