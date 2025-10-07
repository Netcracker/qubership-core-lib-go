package tokensource

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

const (
	defaultTokensDir         = "/var/run/secrets/tokens"
	defaultServiceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	oidcTokenAud             = "oidc-token"
)

var (
	logger       = logging.GetLogger("token-file-storage")
	mu           sync.Mutex
	tokensSource *fileTokenSource
)

// GetToken gets token by audience. Token is always up to date. Default tokens directory can be overrided using config property kubernetes.tokens.dir. ctx should be app ctx that will be used for gracefull shutdown.
func GetToken(ctx context.Context, audience string) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("GetToken: empty audience")
	}
	mu.Lock()
	defer mu.Unlock()
	if tokensSource == nil {
		tokensDir := configloader.GetOrDefaultString("kubernetes.tokens.dir", defaultTokensDir)
		saDir := configloader.GetOrDefaultString("kubernetes.serviceaccount.dir", defaultServiceAccountDir)
		fts, err := newFileTokenSource(ctx, tokensDir, saDir)
		if err != nil {
			return "", fmt.Errorf("failed to initialize token source: %w", err)
		}
		tokensSource = fts
	}
	token, err := tokensSource.getToken(audience)
	if err != nil {
		return "", fmt.Errorf("token by audience %s not found or properyly configured in k8s deployments", audience)
	}
	return token, nil
}

// GetOidcToken gets the default token used to make OIDC discovery to Kubernetes. Default dir for this token can be overrided using config property kubernetes.serviceaccount.dir
func GetOidcToken(ctx context.Context) (string, error) {
	return GetToken(ctx, oidcTokenAud)
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

func newFileTokenSource(ctx context.Context, tokensDir, serviceAccountDir string) (*fileTokenSource, error) {
	ctx, cancel := context.WithCancel(ctx)
	ts := &fileTokenSource{
		tokensDir:         tokensDir,
		serviceAccountDir: serviceAccountDir,
		tokensCache:       make(map[string]*tokenCache),
		cancel:            cancel,
	}
	err := ts.refreshTokensCache()
	if err != nil {
		return nil, err
	}
	ts.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize file watcher: %w", err)
	}
	for _, dir := range []string{ts.tokensDir, ts.serviceAccountDir} {
		err = ts.watcher.Add(dir)
		if err != nil {
			ts.watcher.Close()
			return nil, fmt.Errorf("failed to add path %s to file watcher: %w", ts.tokensDir, err)
		}
	}
	go ts.listenFs(ctx, ts.watcher.Events, ts.watcher.Errors)
	return ts, nil
}

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
			logger.Error("%v", fmt.Errorf("error at volume mounted token watcher at path %s: %v", err))
		case <-ctx.Done():
			f.watcher.Close()
			logger.Infof("k8s token watcher shutdown")
			return
		}
	}
}

func (f *fileTokenSource) refreshTokensCache() error {
	entries, err := os.ReadDir(f.tokensDir)
	if err != nil {
		return fmt.Errorf("failed to get dir entries from tokenDir %s: %w", f.tokensDir, err)
	}
	for _, tokenDir := range entries {
		if !tokenDir.IsDir() {
			continue
		}
		audience := tokenDir.Name()
		f.tokensCache[audience] = f.updatedToken(filepath.Join(f.tokensDir, audience))
	}
	f.tokensCache[oidcTokenAud] = f.updatedToken(f.serviceAccountDir)
	return nil
}

func (f *fileTokenSource) updatedToken(tokenDir string) *tokenCache {
	f.mu.Lock()
	defer f.mu.Unlock()
	tokenFilePath := filepath.Join(tokenDir, "token")
	freshToken, err := os.ReadFile(tokenFilePath)
	if err != nil {
		err = fmt.Errorf("failed to refresh token at path %s: %w", tokenFilePath, err)
	}
	return &tokenCache{token: string(freshToken), err: err}
}

func (f *fileTokenSource) getToken(audience string) (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	tokenCache := f.tokensCache[audience]
	return tokenCache.token, tokenCache.err
}
