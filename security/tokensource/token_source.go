package tokensource

import (
	"context"
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	secretsDir        = "/var/run/secrets"
)

var (
	logger   = logging.GetLogger("token-file-storage")
	mu       sync.RWMutex
	launched = make(map[string]*fileTokenSource)
)

func GetToken(ctx context.Context, audience string) (string, error) {
	mu.RLock()
	tokenSource, ok := launched[audience]
	mu.RUnlock()
	if ok {
		return tokenSource.Token()
	}

	mu.Lock()
	defer mu.Unlock()
	tokenSource, ok = launched[audience]
	if ok {
		return tokenSource.Token()
	}

	entries, err := os.ReadDir(secretsDir)
	if err != nil {
		return "", fmt.Errorf("failed to get entries of dir %s: %w", secretsDir, err)
	}
	for _, entry := range entries {
		if entry.Name() != audience {
			continue
		}
		ts, err := newFileTokenSource(ctx, fmt.Sprintf("%s/%s/token", secretsDir, audience))
		if err != nil {
			return "", fmt.Errorf("failed to create a tokensource for token with audience %s: %w", audience, err)
		}
		launched[audience] = ts
		return ts.Token()
	}
	return "", fmt.Errorf("token with audience %s not found in %s", audience, secretsDir)
}

type fileTokenSource struct {
	mu       sync.RWMutex
	watcher  *fsnotify.Watcher
	err      error
	token    string
	tokenDir string
}

func NewDefault(ctx context.Context) (*fileTokenSource, error) {
	return New(ctx, serviceAccountDir)
}

func New(ctx context.Context, tokenDir string) (*fileTokenSource, error) {
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

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize file watcher: %w", err)
	}
	ts.watcher = watcher

	err = watcher.Add(ts.tokenDir + "/")
	if err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to add path %s to file watcher: %w", ts.tokenDir, err)
	}

	go ts.listenFs(ctx, watcher.Events, watcher.Errors)

	return ts, nil
}

var newFileTokenSource = New

func (f *fileTokenSource) Token() (string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.token, f.err
}

func (f *fileTokenSource) listenFs(ctx context.Context, events chan fsnotify.Event, errs chan error) {
	for {
		select {
		case ev := <-events:
			// we look for event "..data file created". kubernetes updates the token by updating the "..data" symlink token file points to.
			if path.Base(ev.Name) == "..data" && ev.Op.Has(fsnotify.Create) {
				logger.Infof("volume mounted token updated, refreshing token at dir %s", f.tokenDir)
				err := f.refreshToken()
				if err != nil {
					msg := "watching volume token at dir %s: %w"
					f.setError(fmt.Errorf(msg, f.tokenDir, err))
					logger.Errorf(msg, f.tokenDir, err)
				}
				f.setError(nil)
			}
		case err := <-errs:
			f.watcher.Close()
			msg := "error at volume mounted token watcher at path %s: %w"
			f.setError(fmt.Errorf(msg, f.tokenDir, err))
			logger.Errorf(msg, f.tokenDir, err)
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

	freshToken, err := os.ReadFile(f.tokenDir + "/token")
	if err != nil {
		return fmt.Errorf("failed to refresh token at path %s: %w", f.tokenDir+"/token", err)
	}
	f.token = string(freshToken)
	return nil
}

func (f *fileTokenSource) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}
