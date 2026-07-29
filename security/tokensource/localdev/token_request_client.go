package localdev

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var tokenRequestLogger = logging.GetLogger("token-request")

type TokenRequestClient struct {
	httpClient *http.Client
	serverURL  string
	userToken  string
}

type TokenRequestResult struct {
	Token     string
	ExpiresAt time.Time
}

func NewTokenRequestClient(credentials *KubeConfigCredentials) *TokenRequestClient {
	return &TokenRequestClient{
		httpClient: newHTTPClient(credentials),
		serverURL:  credentials.ServerURL,
		userToken:  credentials.UserToken,
	}
}

func (c *TokenRequestClient) RequestToken(namespace, serviceAccountName, audience string) (*TokenRequestResult, error) {
	return c.requestToken(namespace, serviceAccountName, audience, tokenRequestExpirationSeconds)
}

func (c *TokenRequestClient) requestToken(
	namespace, serviceAccountName, audience string,
	expirationSeconds int64,
) (*TokenRequestResult, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/serviceaccounts/%s/token",
		c.serverURL, namespace, serviceAccountName)
	body, err := buildTokenRequestBody(audience, expirationSeconds)
	if err != nil {
		return nil, err
	}
	tokenRequestLogger.Infof(
		"Requesting local-dev SA token: namespace=%s, sa=%s, audience=%s, ttl=%ds",
		namespace, serviceAccountName, audience, expirationSeconds,
	)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set(authorizationHeader, bearerPrefix+c.userToken)
	req.Header.Set(contentTypeHeader, applicationJSON)
	req.Header.Set(acceptHeader, applicationJSON)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("local-dev TokenRequest failed for SA %q in namespace %q: %w",
			serviceAccountName, namespace, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if isUnauthorized(resp.StatusCode) {
		return nil, fmt.Errorf(
			"local-dev TokenRequest unauthorized (HTTP %d) for SA %q in namespace %q. Check RBAC for serviceaccounts/token. Response: %s",
			resp.StatusCode, serviceAccountName, namespace, truncateResponseBody(respBody),
		)
	}
	if isFailed(resp.StatusCode) {
		return nil, fmt.Errorf(
			"local-dev TokenRequest failed (HTTP %d) for SA %q in namespace %q. Response: %s",
			resp.StatusCode, serviceAccountName, namespace, truncateResponseBody(respBody),
		)
	}
	var parsed struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("invalid TokenRequest response: %w", err)
	}
	if strings.TrimSpace(parsed.Status.Token) == "" {
		return nil, fmt.Errorf("TokenRequest response has no status.token")
	}
	expiresAt := parseExpiration(parsed.Status.ExpirationTimestamp, expirationSeconds)
	return &TokenRequestResult{
		Token:     parsed.Status.Token,
		ExpiresAt: expiresAt,
	}, nil
}

func buildTokenRequestBody(audience string, expirationSeconds int64) ([]byte, error) {
	payload := map[string]interface{}{
		"apiVersion": tokenRequestAPIVersion,
		"kind":       tokenRequestKind,
		"spec": map[string]interface{}{
			tokenRequestSpecAudiences:         []string{audience},
			tokenRequestSpecExpirationSeconds: expirationSeconds,
		},
	}
	return json.Marshal(payload)
}

func parseExpiration(expirationTimestamp string, expirationSeconds int64) time.Time {
	if strings.TrimSpace(expirationTimestamp) != "" {
		if t, err := time.Parse(time.RFC3339, expirationTimestamp); err == nil {
			return t
		}
	}
	return time.Now().Add(time.Duration(expirationSeconds) * time.Second)
}
