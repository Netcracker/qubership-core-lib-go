package localdev

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"gopkg.in/yaml.v3"
)

var kubeLogger = logging.GetLogger("kubeconfig-loader")

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
	Name    string                 `yaml:"name"`
	Cluster map[string]interface{} `yaml:"cluster"`
	Context map[string]interface{} `yaml:"context"`
	User    map[string]interface{} `yaml:"user"`
}

// LoadKubeConfig reads the current kubeconfig context and resolves API credentials.
// Supported user auth: static token, OIDC auth-provider (with refresh), id-token / access-token, exec.
func LoadKubeConfig() (*KubeConfigCredentials, error) {
	path, err := resolveKubeConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig not found at %s: %w", path, err)
	}

	var root kubeConfig
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig %s: %w", path, err)
	}
	if strings.TrimSpace(root.CurrentContext) == "" {
		return nil, fmt.Errorf("kubeconfig has no current-context: %s", path)
	}

	contextEntry, err := findKubeConfigEntryByName(root.Contexts, root.CurrentContext)
	if err != nil {
		return nil, err
	}
	clusterName := getKubeConfigStringField(contextEntry.Context, kubeConfigCluster)
	userName := getKubeConfigStringField(contextEntry.Context, kubeConfigUser)
	if clusterName == "" || userName == "" {
		return nil, fmt.Errorf("context %q must define cluster and user in %s", root.CurrentContext, path)
	}
	clusterEntry, err := findKubeConfigEntryByName(root.Clusters, clusterName)
	if err != nil {
		return nil, err
	}
	userEntry, err := findKubeConfigEntryByName(root.Users, userName)
	if err != nil {
		return nil, err
	}
	server := getKubeConfigStringField(clusterEntry.Cluster, kubeConfigServer)
	if server == "" {
		return nil, fmt.Errorf("cluster %q has no server URL", clusterName)
	}
	caData, err := decodeOptionalBase64(getKubeConfigStringField(clusterEntry.Cluster, kubeConfigCertificateAuthorityData))
	if err != nil {
		return nil, err
	}
	userToken, err := resolveUserToken(userEntry.User)
	if err != nil {
		return nil, err
	}
	insecure, _ := getKubeConfigBoolField(clusterEntry.Cluster, kubeConfigInsecureSkipTLSVerify)
	return &KubeConfigCredentials{
		ServerURL:                strings.TrimRight(server, "/"),
		UserToken:                userToken,
		CertificateAuthorityData: caData,
		InsecureSkipTLSVerify:    insecure,
	}, nil
}

func resolveKubeConfigPath() (string, error) {
	if kubeConfig := os.Getenv("KUBECONFIG"); kubeConfig != "" {
		parts := strings.Split(kubeConfig, string(os.PathListSeparator))
		first := strings.TrimSpace(parts[0])
		if first != "" {
			return first, nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve home directory for kubeconfig: %w", err)
	}
	return filepath.Join(home, ".kube", "config"), nil
}

func resolveUserToken(user map[string]interface{}) (string, error) {
	if token := getKubeConfigStringField(user, kubeConfigToken); token != "" {
		return token, nil
	}
	if authProvider, ok := user[kubeConfigAuthProvider].(map[string]interface{}); ok {
		token, err := resolveAuthProviderToken(authProvider)
		if err != nil {
			return "", err
		}
		if token != "" {
			return token, nil
		}
	}
	if idToken := getKubeConfigStringField(user, kubeConfigIDToken); idToken != "" {
		return idToken, nil
	}
	if accessToken := getKubeConfigStringField(user, kubeConfigAccessToken); accessToken != "" {
		return accessToken, nil
	}
	if execCfg, ok := user[kubeConfigExec].(map[string]interface{}); ok {
		return runExecCredential(execCfg)
	}
	return "", fmt.Errorf(
		"kubeconfig user has neither token, OIDC auth-provider, nor exec; local-dev TokenRequest needs kube API credentials",
	)
}

func resolveAuthProviderToken(authProvider map[string]interface{}) (string, error) {
	config, ok := authProvider[kubeConfigConfig].(map[string]interface{})
	if !ok || config == nil {
		return "", nil
	}
	name := getKubeConfigStringField(authProvider, kubeConfigName)
	if strings.EqualFold(name, oidcAuthProviderName) {
		return resolveOidcAuthProviderToken(config)
	}
	if token := getKubeConfigStringField(config, kubeConfigIDToken); token != "" {
		return token, nil
	}
	return getKubeConfigStringField(config, kubeConfigAccessToken), nil
}

func runExecCredential(execCfg map[string]interface{}) (string, error) {
	command := getKubeConfigStringField(execCfg, kubeConfigCommand)
	if command == "" {
		return "", fmt.Errorf("kubeconfig exec.command is empty")
	}
	args := []string{command}
	if rawArgs, ok := execCfg[kubeConfigArgs].([]interface{}); ok {
		for _, arg := range rawArgs {
			if s, ok := arg.(string); ok {
				args = append(args, s)
			}
		}
	}
	kubeLogger.Debugf("Resolving kubeconfig credentials via exec: %v", args)
	ctx, cancel := context.WithTimeout(context.Background(), kubeConfigExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if envVars, ok := execCfg[kubeConfigEnv].([]interface{}); ok {
		for _, item := range envVars {
			envMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			name := getKubeConfigStringField(envMap, kubeConfigName)
			if name == "" {
				continue
			}
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", name, getKubeConfigStringField(envMap, kubeConfigValue)))
		}
	}
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("kubeconfig exec timed out after %s: %s", kubeConfigExecTimeout, command)
	}
	if err != nil {
		return "", fmt.Errorf("kubeconfig exec failed: %s: %w", string(output), err)
	}
	var credential struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if err := json.Unmarshal(output, &credential); err != nil {
		return "", fmt.Errorf("kubeconfig exec returned invalid JSON: %w", err)
	}
	if credential.Status.Token == "" {
		return "", fmt.Errorf("kubeconfig exec did not return status.token")
	}
	return credential.Status.Token, nil
}

func findKubeConfigEntryByName(entries []namedEntry, name string) (namedEntry, error) {
	for _, entry := range entries {
		if entry.Name == name {
			return entry, nil
		}
	}
	return namedEntry{}, fmt.Errorf("kubeconfig entry not found: %s", name)
}

func decodeOptionalBase64(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	clean := strings.ReplaceAll(strings.ReplaceAll(value, "\n", ""), "\r", "")
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate-authority-data in kubeconfig: %w", err)
	}
	return decoded, nil
}
