package tokensource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"
)

// TokenAudience represents an audience of a Kubernetes projected volume token. For common predefined audiences see below
type TokenAudience string

const (
	// AudienceNetcracker is used for m2m communication between microservices in the same namespace
	AudienceNetcracker = "netcracker"
	// AudienceDBaaS is used for sending requests to DBaaS infra service
	AudienceDBaaS = "dbaas"
	// AudienceMaaS is used for sending requests to MaaS infra service
	AudienceMaaS = "maas"
)

var (
	// DefaultAudienceTokensDir is the default directory where kubernetes projected volume tokens with custom audience will be located. Set this value to override the location for test purposes
	DefaultAudienceTokensDir = "/var/run/secrets/tokens"
	// DefaultServiceAccountDir is the default kubernetes service account directory. GetServiceAccountToken returns the token located at this dir. Set this value to override the location for test purposes
	DefaultServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

	logger = logging.GetLogger("token-file-storage")

	// we can't define lazy initializer in var section definition, because initialization
	// function have global variables that can be redefined by consumer level code and thus
	// values can't be captured early
	audienceTokensWatcher      atomic.Pointer[utils.Lazy[*tokenWatcher]]
	serviceAccountTokenWatcher atomic.Pointer[utils.Lazy[*tokenWatcher]]

	audienceTokensCache      sync.Map
	serviceAccountTokenCache atomic.Value
)

// GetAudienceToken gets token by audience. Do not store the token. Always call GetAudienceToken again to get a fresh token. Default tokens directory can be overridden using global variable DefaultAudienceTokensDir
func GetAudienceToken(ctx context.Context, audience TokenAudience) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("GetToken: empty audience")
	}
	audienceTokensWatcher.CompareAndSwap(nil, utils.NewLazy(func() (*tokenWatcher, error) {
		return newTokenWatcher(ctx, DefaultAudienceTokensDir, refreshAudienceTokensCache)
	}))
	_, err := audienceTokensWatcher.Load().Get()
	if err != nil {
		return "", fmt.Errorf("failed to create token watcher: %w", err)
	}
	cachedToken, ok := audienceTokensCache.Load(audience)
	if !ok {
		return "", fmt.Errorf("token with audience %s was not found", audience)
	}
	result := cachedToken.(tokenUpdateResult)
	if result.err != nil {
		return "", fmt.Errorf("failed to get token by audience: %s: %w", audience, err)
	}
	return result.value, nil
}

// GetServiceAccountToken gets the default service account token located at /var/run/secrets/kubernetes.io/serviceaccount. Do not store the token. Always call GetServiceAccountToken again to get a fresh token. Default service account token directory can be overridden using global variable DefaultServiceAccountDir
func GetServiceAccountToken(ctx context.Context) (string, error) {
	serviceAccountTokenWatcher.CompareAndSwap(nil, utils.NewLazy(func() (*tokenWatcher, error) {
		return newTokenWatcher(ctx, DefaultServiceAccountDir, refreshServiceAccountTokenCache)
	}))
	_, err := serviceAccountTokenWatcher.Load().Get()
	if err != nil {
		return "", fmt.Errorf("failed to create token watcher: %w", err)
	}
	cachedToken := serviceAccountTokenCache.Load()
	result := cachedToken.(tokenUpdateResult)
	if result.err != nil {
		return "", fmt.Errorf("failed to get token default kubernetes service account token: %w", err)
	}
	return result.value, nil
}

type tokenUpdateResult struct {
	value string
	err   error
}

func refreshAudienceTokensCache(tokensDir string) error {
	entries, err := os.ReadDir(tokensDir)
	if err != nil {
		return fmt.Errorf("failed to get dir entries from tokenDir %s: %w", tokensDir, err)
	}
	for _, tokenDir := range entries {
		audience := tokenDir.Name()
		token, err := readToken(filepath.Join(tokensDir, audience, "token"))
		audienceTokensCache.Store(TokenAudience(audience), tokenUpdateResult{
			value: token,
			err:   err,
		})
	}
	return nil
}

func refreshServiceAccountTokenCache(serviceAccountDir string) error {
	token, err := readToken(filepath.Join(serviceAccountDir, "token"))
	serviceAccountTokenCache.Store(tokenUpdateResult{
		value: token,
		err:   err,
	})
	return nil
}

func readToken(tokenPath string) (string, error) {
	freshToken, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read token at path %s: %w", tokenPath, err)
	}
	return string(freshToken), nil
}

type tokenWatcher struct {
	watcher     *fsnotify.Watcher
	tokensDir   string
	updateCache func(string) error
	cancel      context.CancelFunc
}

func newTokenWatcher(ctx context.Context, tokensDir string, updateCache func(tokensDir string) error) (*tokenWatcher, error) {
	ctx, cancel := context.WithCancel(ctx)
	tw := &tokenWatcher{
		tokensDir:   tokensDir,
		updateCache: updateCache,
		cancel:      cancel,
	}
	err := tw.updateCache(tokensDir)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens cache: %w", err)
	}
	tw.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize file watcher: %w", err)
	}
	err = tw.watcher.Add(tokensDir)
	if err != nil {
		_ = tw.watcher.Close()
		return nil, fmt.Errorf("failed to add path %s to file watcher: %w", tw.tokensDir, err)
	}
	go tw.listenFs(ctx, tw.watcher.Events, tw.watcher.Errors)
	return tw, nil
}

func (tw *tokenWatcher) listenFs(ctx context.Context, events <-chan fsnotify.Event, errs <-chan error) {
	for {
		select {
		case ev := <-events:
			// we look for event "..data file created". kubernetes updates the token by updating the "..data" in tokensDir.
			if ev.Op.Has(fsnotify.Create) && strings.Contains(ev.Name, "..data") {
				logger.Debugf("k8s tokens updated: started refreshing k8s tokensCache")
				err := tw.updateCache(tw.tokensDir)
				if err != nil {
					logger.Errorf("%v", fmt.Errorf("failed to update cache: %w", err))
					break
				}
				logger.Debugf("k8s tokensCache refreshed")
			}
		case err := <-errs:
			logger.Error("%v", fmt.Errorf("error at k8s volume mounted token watcher: %w", err))
		case <-ctx.Done():
			_ = tw.watcher.Close()
			logger.Infof("k8s token watcher shutdown")
			return
		}
	}
}
