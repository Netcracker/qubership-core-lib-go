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
	defaultTokensDir = "/var/run/secrets/tokens"
	tokenFileName   = "token"
)

var (
	logger       = logging.GetLogger("token-file-storage")
	mu           sync.RWMutex
	tokenSources = make(map[string]*fileTokenSource)
)

// GetToken gets token by audience. Token is always up to date. Default tokens directory can be overrided using config property kubernetes.tokens.dir
func GetToken(ctx context.Context, audience string) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("GetToken: empty audience")
	}
	tokensDir := configloader.GetOrDefaultString("kubernetes.tokens.dir", defaultTokensDir)
	return getToken(ctx, audience, tokensDir)
}

func getToken(ctx context.Context, audience string, tokensDir string) (string, error) {
	mu.RLock()
	tokenSource, ok := tokenSources[audience]
	mu.RUnlock()
	if ok {
		return tokenSource.Token()
	}

	mu.Lock()
	defer mu.Unlock()
	tokenSource, ok = tokenSources[audience]
	if ok {
		return tokenSource.Token()
	}

	tokenSource, err := newFileTokenSource(ctx, filepath.Join(tokensDir, audience))
	if err != nil {
		return "", fmt.Errorf("failed to create a tokensource for token with audience %s: %w", audience, err)
	}
	tokenSources[audience] = tokenSource
	return tokenSource.Token()
}

type fileTokenSource struct {
	mu       sync.RWMutex
	watcher  *fsnotify.Watcher
	err      error
	token    string
	tokenDir string
	cancel   context.CancelFunc
}

func newFileTokenSource(ctx context.Context, tokenDir string) (*fileTokenSource, error) {
	if tokenDir == "" {
		return nil, fmt.Errorf("tokenDir is an empty string, use NewDefault if default service account dir needed or specify tokenDir")
	}

	ts := &fileTokenSource{
		tokenDir: tokenDir,
	}
	err := ts.refreshToken()
	if err != nil {
		return nil, err
	}

	ts.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize file watcher: %w", err)
	}

	err = ts.watcher.Add(ts.tokenDir)
	if err != nil {
		ts.watcher.Close()
		return nil, fmt.Errorf("failed to add path %s to file watcher: %w", ts.tokenDir, err)
	}

	ctx, ts.cancel = context.WithCancel(ctx)
	go ts.listenFs(ctx, ts.watcher.Events, ts.watcher.Errors)

	return ts, nil
}

func (f *fileTokenSource) Token() (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.token, f.err
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
				err := f.refreshToken()
				if err != nil {
					msg := "watching volume token at dir %s: %v"
					f.setError(fmt.Errorf(msg, f.tokenDir, err))
					logger.Errorf(msg, f.tokenDir, err)
					break
				}
				f.setError(nil)
			}
		case err := <-errs:
			if err != nil {
				msg := "error at volume mounted token watcher at path %s: %v"
				f.setError(fmt.Errorf(msg, f.tokenDir, err))
				logger.Errorf(msg, f.tokenDir, err)
			}
		case <-ctx.Done():
			f.watcher.Close()
			logger.Infof("token watcher at %s shutdown", f.tokenDir)
			return
		}
	}
}

func (f *fileTokenSource) refreshToken() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	tokenFilePath := filepath.Join(f.tokenDir, tokenFileName)
	freshToken, err := os.ReadFile(tokenFilePath)
	if err != nil {
		return fmt.Errorf("failed to refresh token at path %s: %w", tokenFilePath, err)
	}
	f.token = string(freshToken)
	return nil
}

func (f *fileTokenSource) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}
