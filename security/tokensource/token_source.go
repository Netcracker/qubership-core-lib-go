package tokensource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/utils"
)

var (
	DefaultTokensDir         = "/var/run/secrets/tokens"
	DefaultServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	DefaultTokenAud          = "oidc-token"

	logger = logging.GetLogger("token-file-storage")

	// we can't define lazy initializer in var section definition, because initialization
	// function have global variables that can be redefined by consumer level code and thus
	// values can't be captured early
	tokensSource atomic.Pointer[utils.Lazy[*fileTokenSource]]
)

// GetToken gets token by audience. Token is always up to date. Default tokens directory can be overridden using config property kubernetes.tokens.dir. ctx should be app ctx that will be used for gracefull shutdown.
func GetToken(ctx context.Context, audience string) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("GetToken: empty audience")
	}

	tokensSource.CompareAndSwap(nil, utils.NewLazy(func() (*fileTokenSource, error) {
		return newFileTokenSource(ctx, DefaultTokensDir, DefaultServiceAccountDir)
	}))
	ts, err := tokensSource.Load().Get()
	if err != nil {
		return "", fmt.Errorf("failed to create token source: %w", err)
	}

	token, err := ts.getToken(audience)
	if err != nil {
		return "", fmt.Errorf("failed to get token by audience: %s: %w", audience, err)
	}
	return token, nil
}

// GetTokenDefault gets the default token used to make OIDC discovery to Kubernetes located at serviceaccount directory. Default dir for this token can be overrided using config property kubernetes.serviceaccount.dir
func GetTokenDefault(ctx context.Context) (string, error) {
	return GetToken(ctx, DefaultTokenAud)
}

type tokenCache struct {
	token string
	err   error
}

func (t *tokenCache) Token() (string, error) {
	return t.token, t.err
}

type fileTokenSource struct {
	mu                sync.RWMutex
	watcher           *fsnotify.Watcher
	tokensDir         string
	serviceAccountDir string
	tokensCache       map[string]*tokenCache
	cancel            context.CancelFunc
}

func createFileTokenSource(ctx context.Context, tokensDir, serviceAccountDir string) (*fileTokenSource, error) {
	ctx, cancel := context.WithCancel(ctx)
	ts := &fileTokenSource{
		tokensDir:         tokensDir,
		serviceAccountDir: serviceAccountDir,
		tokensCache:       make(map[string]*tokenCache),
		cancel:            cancel,
	}
	err := ts.refreshTokensCache()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens cache: %w", err)
	}
	ts.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize file watcher: %w", err)
	}
	for _, dir := range []string{ts.tokensDir, ts.serviceAccountDir} {
		err = ts.watcher.Add(dir)
		if err != nil {
			_ = ts.watcher.Close()
			return nil, fmt.Errorf("failed to add path %s to file watcher: %w", ts.tokensDir, err)
		}
	}
	go ts.listenFs(ctx, ts.watcher.Events, ts.watcher.Errors)
	return ts, nil
}

var newFileTokenSource = createFileTokenSource

func (f *fileTokenSource) Close() {
	f.cancel()
}

func (f *fileTokenSource) listenFs(ctx context.Context, events <-chan fsnotify.Event, errs <-chan error) {
	for {
		select {
		case ev := <-events:
			// we look for event "..data file created". kubernetes updates the token by updating the "..data" symlink token file points to.
			if filepath.Base(ev.Name) == "..data" && ev.Op.Has(fsnotify.Create) {
				logger.Debugf("k8s tokens updated: started refreshing k8s tokensCache")
				err := f.refreshTokensCache()
				if err != nil {
					logger.Errorf("%v", fmt.Errorf("failed to update cache: %w", err))
					break
				}
				logger.Debugf("k8s tokensCache refreshed")
			}
		case err := <-errs:
			logger.Error("%v", fmt.Errorf("error at k8s volume mounted token watcher: %w", err))
		case <-ctx.Done():
			_ = f.watcher.Close()
			logger.Infof("k8s token watcher shutdown")
			return
		}
	}
}

func (f *fileTokenSource) refreshTokensCache() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries, err := os.ReadDir(f.tokensDir)
	if err != nil {
		return fmt.Errorf("failed to get dir entries from tokenDir %s: %w", f.tokensDir, err)
	}
	for _, tokenDir := range entries {
		audience := tokenDir.Name()
		tokenPath := filepath.Join(f.tokensDir, audience, "token")
		tokenExists, err := fileExists(tokenPath)
		if err != nil {
			return err
		}
		if tokenExists {
			f.tokensCache[audience] = f.updatedToken(tokenPath)
		}
	}
	f.tokensCache[DefaultTokenAud] = f.updatedToken(filepath.Join(f.serviceAccountDir, "token"))
	return nil
}

func (f *fileTokenSource) updatedToken(tokenPath string) *tokenCache {
	freshToken, err := os.ReadFile(tokenPath)
	if err != nil {
		err = fmt.Errorf("failed to refresh token at path %s: %w", tokenPath, err)
	}
	return &tokenCache{token: string(freshToken), err: err}
}

func (f *fileTokenSource) getToken(audience string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	tokenCache, ok := f.tokensCache[audience]
	if !ok {
		return "", fmt.Errorf("token by audience %s not found or properyly configured in k8s deployments", audience)
	}
	return tokenCache.token, tokenCache.err
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if file %s exists: %w", filePath, err)
	}
	return true, nil
}
