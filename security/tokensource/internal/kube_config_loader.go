package internal

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// KubeConfigCredentials holds kube API server URL, user credentials, and TLS settings from kubeconfig.
type KubeConfigCredentials struct {
	ServerURL                string
	UserToken                string
	CertificateAuthorityData []byte
	InsecureSkipTLSVerify    bool
}

type kubeConfig struct {
	CurrentContext string       `yaml:"current-context"`
	Clusters       []namedEntry `yaml:"clusters"`
	Contexts       []namedEntry `yaml:"contexts"`
	Users          []namedEntry `yaml:"users"`
}

type namedEntry struct {
	Name    string         `yaml:"name"`
	Cluster map[string]any `yaml:"cluster"`
	Context map[string]any `yaml:"context"`
	User    map[string]any `yaml:"user"`
}

// LoadKubeConfig reads the current kubeconfig context and resolves API credentials.
// Supported user auth: static token, OIDC auth-provider (with refresh), id-token / access-token.
// Exec auth is not supported.
func LoadKubeConfig() (*KubeConfigCredentials, error) {
	path, err := resolveKubeConfigPath()
	if err != nil {
		return nil, err
	}

	root, err := readAndParseKubeConfig(path)
	if err != nil {
		return nil, err
	}

	clusterEntry, userEntry, err := resolveActiveKubeConfigEntries(root, path)
	if err != nil {
		return nil, err
	}

	return credentialsFromKubeConfigEntries(clusterEntry, userEntry)
}

func readAndParseKubeConfig(path string) (kubeConfig, error) {
	var root kubeConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return root, fmt.Errorf("kubeconfig not found at %s: %w", path, err)
	}

	if err = yaml.Unmarshal(data, &root); err != nil {
		return root, fmt.Errorf("failed to parse kubeconfig %s: %w", path, err)
	}
	if strings.TrimSpace(root.CurrentContext) == "" {
		return root, fmt.Errorf("kubeconfig has no current-context: %s", path)
	}
	return root, nil
}

func resolveActiveKubeConfigEntries(root kubeConfig, path string) (namedEntry, namedEntry, error) {
	var clusterEntry, userEntry namedEntry
	contextEntry, err := findKubeConfigEntryByName(root.Contexts, root.CurrentContext)
	if err != nil {
		return clusterEntry, userEntry, err
	}

	clusterName := getStringField(contextEntry.Context, kubeConfigCluster)
	userName := getStringField(contextEntry.Context, kubeConfigUser)
	if clusterName == "" || userName == "" {
		return clusterEntry, userEntry, fmt.Errorf(
			"context %q must define cluster and user in %s",
			root.CurrentContext,
			path,
		)
	}

	clusterEntry, err = findKubeConfigEntryByName(root.Clusters, clusterName)
	if err != nil {
		return clusterEntry, userEntry, err
	}

	userEntry, err = findKubeConfigEntryByName(root.Users, userName)
	if err != nil {
		return clusterEntry, userEntry, err
	}

	return clusterEntry, userEntry, nil
}

func credentialsFromKubeConfigEntries(clusterEntry, userEntry namedEntry) (*KubeConfigCredentials, error) {
	clusterName := clusterEntry.Name
	server := getStringField(clusterEntry.Cluster, kubeConfigServer)
	if server == "" {
		return nil, fmt.Errorf("cluster %q has no server URL", clusterName)
	}

	caData, err := decodeOptionalBase64(getStringField(clusterEntry.Cluster, kubeConfigCertificateAuthorityData))
	if err != nil {
		return nil, err
	}

	userToken, err := resolveUserToken(userEntry.User)
	if err != nil {
		return nil, err
	}

	insecure, _ := getBoolField(clusterEntry.Cluster, kubeConfigInsecureSkipTLSVerify)
	return &KubeConfigCredentials{
		ServerURL:                strings.TrimRight(server, "/"),
		UserToken:                userToken,
		CertificateAuthorityData: caData,
		InsecureSkipTLSVerify:    insecure,
	}, nil
}

func resolveKubeConfigPath() (string, error) {
	if kubeConfig, isPresent := os.LookupEnv("KUBECONFIG"); isPresent {
		parts := strings.Split(kubeConfig, string(os.PathListSeparator))
		first := strings.TrimSpace(parts[0])
		if first != "" {
			if len(parts) > 1 {
				kubeLogger.Warnf("local-dev takes only the first kubeconfig: %s", first)
			}
			return first, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve home directory for kubeconfig: %w", err)
	}
	return filepath.Join(home, ".kube", "config"), nil
}

func resolveUserToken(user map[string]any) (string, error) {
	if token := getStringField(user, kubeConfigToken); token != "" {
		return token, nil
	}
	if authProvider, ok := user[kubeConfigAuthProvider].(map[string]any); ok {
		token, err := resolveAuthProviderToken(authProvider)
		if err != nil {
			return "", err
		}
		if token != "" {
			return token, nil
		}
	}
	if idToken := getStringField(user, kubeConfigIDToken); idToken != "" {
		return idToken, nil
	}
	if accessToken := getStringField(user, kubeConfigAccessToken); accessToken != "" {
		return accessToken, nil
	}
	if _, ok := user[kubeConfigExec]; ok {
		return "", fmt.Errorf(
			"kubeconfig exec authentication is not supported for local-dev; use a static user token or OIDC auth-provider (id-token / refresh-token)",
		)
	}
	return "", fmt.Errorf(
		"kubeconfig user has neither token nor OIDC auth-provider; local-dev TokenRequest needs kube API credentials",
	)
}

func resolveAuthProviderToken(authProvider map[string]any) (string, error) {
	config, ok := authProvider[kubeConfigConfig].(map[string]any)
	if !ok || config == nil {
		return "", nil
	}
	name := getStringField(authProvider, kubeConfigName)
	if strings.EqualFold(name, oidcAuthProviderName) {
		return resolveOidcAuthProviderToken(config)
	}
	if token := getStringField(config, kubeConfigIDToken); token != "" {
		return token, nil
	}
	return getStringField(config, kubeConfigAccessToken), nil
}

func findKubeConfigEntryByName(entries []namedEntry, name string) (namedEntry, error) {
	var found namedEntry
	for _, entry := range entries {
		if entry.Name == name {
			return entry, nil
		}
	}
	return found, fmt.Errorf("kubeconfig entry not found: %s", name)
}

func decodeOptionalBase64(value string) ([]byte, error) {
	value = strings.Join(strings.Fields(value), "")
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate-authority-data in kubeconfig: %w", err)
	}
	return decoded, nil
}
