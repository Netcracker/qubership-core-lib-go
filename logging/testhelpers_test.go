package logging

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	lock "github.com/viney-shih/go-lock"
)

// Every knob this package exposes is process-global: DefaultFormat, globalLogFormat, the
// registeredLoggers registry, the configloader subscription and os.Stdout itself. Tests here have
// historically leaked that state into each other -- TestSetLogFormat leaves globalLogFormat
// pointing at a custom formatter for the remainder of the run, and TestSetMessageFormat_CustomFormat
// carries a "// have to clear message logFormat or other test won't pass" comment admitting the
// same. The helpers below make that leakage impossible so failures stay attributable to the test
// that caused them.
//
// Rules for this package:
//   - never call t.Parallel(); the shared globals make it unsound
//   - use t.Setenv, never os.Setenv/os.Clearenv (os.Clearenv defeats t.Setenv's restore)
//   - wrap any test that touches formatting or output in withCleanLoggingState

// withCleanLoggingState snapshots every mutable global the logging package owns and restores it
// when the test finishes, whether it passes, fails or panics.
func withCleanLoggingState(t *testing.T) {
	t.Helper()

	savedMessageFormat := DefaultFormat.messageFormat
	savedCustomFields := globalCustomFields.Load()
	savedGlobalLogFormat := globalLogFormat.Load()
	savedActiveFormat := activeFormat.Load()
	savedFormatExplicit := globalFormatExplicit.Load()
	savedGlobalOut := globalOut.Load()
	savedStdout := os.Stdout

	t.Cleanup(func() {
		DefaultFormat.messageFormat = savedMessageFormat
		globalCustomFields.Store(savedCustomFields)
		globalLogFormat.Store(savedGlobalLogFormat)
		activeFormat.Store(savedActiveFormat)
		globalFormatExplicit.Store(savedFormatExplicit)
		globalOut.Store(savedGlobalOut)
		os.Stdout = savedStdout
	})
}

// requireBootstrapConfigPath skips a test that can only exercise the pre-configloader bootstrap
// path in readLvlFromConfig.
//
// TestGetLogger_InitedConfigLoader initialises configloader process-wide and there is no way to
// undo that, so once it has run the os.LookupEnv branch is unreachable for the rest of the run.
// The env variables involved also cannot be reached through configloader instead: its
// EnvPropertySource maps LOG_LEVEL_PACKAGE_TEST_ENV_PACKAGE to log.level.package.test.env.package,
// while definePackageLvl looks up log.level.package.test_env_package -- underscores in a package
// name are not recoverable from the env key.
//
// Skipping keeps the package deterministic under -shuffle instead of failing depending on order.
// In declaration order these tests run before the configloader is initialised, so they do execute.
func requireBootstrapConfigPath(t *testing.T) {
	t.Helper()
	if configloader.IsConfigLoaderInited() {
		t.Skip("configloader is already initialised process-wide; the env bootstrap path is unreachable")
	}
}

// newTestLogger builds an unregistered logger. Unlike createTestLogger it returns a pointer --
// logger embeds a sync.RWMutex, so returning it by value trips go vet's copylocks check -- and it
// never touches registeredLoggers, so it cannot perturb GetLogLevels or the configloader watcher.
func newTestLogger(t *testing.T, lvl Lvl, name string) *logger {
	t.Helper()
	l := new(logger)
	l.maxLvl = lvl
	l.name = name
	l.mu = lock.NewChanMutex()
	return l
}

// registerTestLogger is for the few tests that genuinely need GetLogger to find the logger (the
// HTTP level/format controllers look it up by name). It removes the entry afterwards so the
// registry does not grow across the run.
func registerTestLogger(t *testing.T, name string) *logger {
	t.Helper()
	l := GetLogger(name).(*logger)
	t.Cleanup(func() { registeredLoggers.Delete(name) })
	return l
}

// captureStdout redirects os.Stdout through a pipe and returns a func yielding everything written.
// It exists for the legacy log methods, which write to os.Stdout unconditionally. Prefer asserting
// on a formatter's return value directly where possible; this is inherently serialising.
func captureStdout(t *testing.T) func() string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w

	copied := make(chan string, 1)
	go func() {
		var sb strings.Builder
		_, _ = io.Copy(&sb, r)
		_ = r.Close()
		copied <- sb.String()
	}()

	var out string
	var read bool
	restore := func() string {
		if read {
			return out
		}
		read = true
		os.Stdout = saved
		_ = w.Close()
		out = <-copied
		return out
	}
	// Guarantee the goroutine is unblocked and os.Stdout restored even if the test never calls
	// the returned func (early t.Fatal, panic).
	t.Cleanup(func() { restore() })
	return restore
}

// sprintf mirrors what the printf-style log methods do to their arguments, for test doubles that
// need to reproduce the same message text.
func sprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

// syncBuffer is a bytes.Buffer safe for concurrent writers, for tests that log from several
// goroutines at once.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}
