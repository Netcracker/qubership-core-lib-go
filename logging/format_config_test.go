package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/configloader"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormat_String(t *testing.T) {
	assert.Equal(t, "text", FormatText.String())
	assert.Equal(t, "json", FormatJSON.String())
	assert.Equal(t, "text", Format(99).String(), "unknown values must not panic")
}

func TestParseFormat_Table(t *testing.T) {
	tests := []struct {
		in    string
		want  Format
		valid bool
	}{
		{"json", FormatJSON, true},
		{"JSON", FormatJSON, true},
		{"  Json  ", FormatJSON, true},
		{"text", FormatText, true},
		{"TEXT", FormatText, true},
		{"", FormatText, false},
		{"yaml", FormatText, false},
		{"jsonl", FormatText, false},
	}

	for _, tt := range tests {
		t.Run("input="+tt.in, func(t *testing.T) {
			got, ok := parseFormat(tt.in)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.valid, ok)
		})
	}
}

func TestResolveFormat_DefaultIsText(t *testing.T) {
	withCleanLoggingState(t)
	globalFormatExplicit.Store(false)

	applyResolvedFormat()

	assert.Equal(t, FormatText, GetOutputFormat(),
		"upgrading the library must not change a service's output on its own")
}

func TestResolveFormat_UnknownValueFallsBackToTextSilently(t *testing.T) {
	withCleanLoggingState(t)
	globalFormatExplicit.Store(false)
	setFormatConfig(t, "yaml")

	applyResolvedFormat()

	assert.Equal(t, FormatText, GetOutputFormat())
}

func TestResolveFormat_Json(t *testing.T) {
	withCleanLoggingState(t)
	globalFormatExplicit.Store(false)
	setFormatConfig(t, "json")

	applyResolvedFormat()

	assert.Equal(t, FormatJSON, GetOutputFormat())
}

func TestResolveFormat_CaseInsensitiveAndTrimmed(t *testing.T) {
	withCleanLoggingState(t)
	globalFormatExplicit.Store(false)
	setFormatConfig(t, "  JSON ")

	applyResolvedFormat()

	assert.Equal(t, FormatJSON, GetOutputFormat())
}

func TestSetOutputFormat_MarksExplicit(t *testing.T) {
	withCleanLoggingState(t)
	globalFormatExplicit.Store(false)
	assert.False(t, IsOutputFormatExplicit())

	SetOutputFormat(FormatJSON)

	assert.Equal(t, FormatJSON, GetOutputFormat())
	assert.True(t, IsOutputFormatExplicit())
}

// TestFormat_ExplicitChoiceSurvivesRefresh pins the guard that keeps an operator's deliberate
// switch from being silently undone by the next configuration reload.
func TestFormat_ExplicitChoiceSurvivesRefresh(t *testing.T) {
	withCleanLoggingState(t)
	setFormatConfig(t, "text")

	SetOutputFormat(FormatJSON)
	applyResolvedFormat() // simulates an Inited/Refreshed event

	assert.Equal(t, FormatJSON, GetOutputFormat())
}

func TestSetLogFormat_MarksExplicitAndWins(t *testing.T) {
	withCleanLoggingState(t)
	setFormatConfig(t, "json")

	SetLogFormat(customLogFormat)
	applyResolvedFormat()

	assert.True(t, IsOutputFormatExplicit())

	l := newTestLogger(t, LvlInfo, "orders")
	buf := &bytes.Buffer{}
	l.SetOutput(buf)
	l.Info("hello")

	assert.Contains(t, buf.String(), "[packageName=testPackageName]",
		"an installed custom formatter must beat the configured format")
}

func TestFormat_PerLoggerOverrideBeatsGlobal(t *testing.T) {
	withCleanLoggingState(t)
	SetOutputFormat(FormatJSON)

	l := newTestLogger(t, LvlInfo, "orders")
	buf := &bytes.Buffer{}
	l.SetOutput(buf)
	l.SetLogFormat(customLogFormat)

	l.Info("hello")

	assert.Contains(t, buf.String(), "[packageName=testPackageName]")
	assert.NotContains(t, buf.String(), `"level"`)
}

func TestFormat_SwitchTakesEffectOnNextRecord(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	l := newTestLogger(t, LvlInfo, "orders")
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	SetOutputFormat(FormatText)
	l.Info("first")
	SetOutputFormat(FormatJSON)
	l.Info("second")

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	assert.True(t, strings.HasPrefix(lines[0], "["), "first line stays text")
	assert.True(t, strings.HasPrefix(lines[1], "{"), "second line is JSON")

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &doc))
	assert.Equal(t, "second", doc["message"])
}

// TestFormat_ConcurrentSwapAndLog_NoRace runs writers alongside a goroutine flipping the format.
// Every emitted line must be complete and parse as either text or JSON -- never a torn mixture.
func TestFormat_ConcurrentSwapAndLog_NoRace(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	l := newTestLogger(t, LvlInfo, "orders")
	buf := &syncBuffer{}
	l.SetOutput(buf)

	// The swapper is tracked separately from the writers: it runs until told to stop, so waiting
	// on it in the same group as the writers would deadlock.
	var writers, swapper sync.WaitGroup
	stop := make(chan struct{})

	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				SetOutputFormat(FormatJSON)
			} else {
				SetOutputFormat(FormatText)
			}
		}
	}()

	for w := 0; w < 8; w++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 0; i < 100; i++ {
				l.InfoW("concurrent", "n", i)
			}
		}()
	}

	for w := 0; w < 8; w++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 0; i < 100; i++ {
				l.Info("legacy %d", i)
			}
		}()
	}

	writers.Wait()
	close(stop)
	swapper.Wait()

	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "{") {
			var doc map[string]any
			assert.NoError(t, json.Unmarshal([]byte(line), &doc), "torn JSON line: %q", line)
			continue
		}
		assert.True(t, strings.HasPrefix(line, "[") && strings.Contains(line, "[class=orders]"),
			"torn text line: %q", line)
	}
}

// ---------------------------------------------------------------------------
// Output destination
// ---------------------------------------------------------------------------

func TestSetOutput_Global(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	buf := &bytes.Buffer{}
	SetOutput(buf)

	newTestLogger(t, LvlInfo, "orders").Info("hello")

	assert.Contains(t, buf.String(), "hello")
}

func TestSetOutput_PerLoggerOverridesGlobal(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	global := &bytes.Buffer{}
	perLogger := &bytes.Buffer{}
	SetOutput(global)

	l := newTestLogger(t, LvlInfo, "orders")
	l.SetOutput(perLogger)
	l.Info("hello")

	assert.Contains(t, perLogger.String(), "hello")
	assert.Empty(t, global.String())
}

func TestSetOutput_NilRestoresDefault(t *testing.T) {
	withCleanLoggingState(t)

	buf := &bytes.Buffer{}
	SetOutput(buf)
	SetOutput(nil)

	assert.Same(t, os.Stdout, resolveGlobalWriter())
}

func TestSetOutput_ChildInheritsParent(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	buf := &bytes.Buffer{}
	l := newTestLogger(t, LvlInfo, "orders")
	l.SetOutput(buf)

	l.With("env", "prod").InfoW("hello")

	assert.Contains(t, buf.String(), "hello env=prod")
}

// TestOutput_DefaultsToStdout_ResolvedLazily guards the contract the deadlock-guard test depends
// on: os.Stdout must be read at write time, not captured when the logger is built.
func TestOutput_DefaultsToStdout_ResolvedLazily(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	l := newTestLogger(t, LvlInfo, "orders")

	// Reassign os.Stdout AFTER the logger exists.
	read := captureStdout(t)
	l.Info("captured after reassignment")
	out := read()

	assert.Contains(t, out, "captured after reassignment")
}

// ---------------------------------------------------------------------------
// Phase-1 migration gate: legacy methods must emit valid JSON with no code changes
// ---------------------------------------------------------------------------

func TestJSONFormat_LegacyMethods_NoCodeChange(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")
	SetOutputFormat(FormatJSON)

	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIdContextName, "req-1")
	ctx = context.WithValue(ctx, TenantContextName, "ten-1")

	tests := []struct {
		name      string
		call      func(l *logger)
		wantLevel string
		wantMsg   string
		wantCtx   bool
		panics    bool
	}{
		{"Debug", func(l *logger) { l.Debug("d %d", 1) }, "DEBUG", "d 1", false, false},
		{"Debugf", func(l *logger) { l.Debugf("d %d", 2) }, "DEBUG", "d 2", false, false},
		{"DebugC", func(l *logger) { l.DebugC(ctx, "d %d", 3) }, "DEBUG", "d 3", true, false},
		{"Info", func(l *logger) { l.Info("i %d", 1) }, "INFO", "i 1", false, false},
		{"Infof", func(l *logger) { l.Infof("i %d", 2) }, "INFO", "i 2", false, false},
		{"InfoC", func(l *logger) { l.InfoC(ctx, "i %d", 3) }, "INFO", "i 3", true, false},
		{"Warn", func(l *logger) { l.Warn("w %d", 1) }, "WARN", "w 1", false, false},
		{"Warnf", func(l *logger) { l.Warnf("w %d", 2) }, "WARN", "w 2", false, false},
		{"WarnC", func(l *logger) { l.WarnC(ctx, "w %d", 3) }, "WARN", "w 3", true, false},
		{"Error", func(l *logger) { l.Error("e %d", 1) }, "ERROR", "e 1", false, false},
		{"Errorf", func(l *logger) { l.Errorf("e %d", 2) }, "ERROR", "e 2", false, false},
		{"ErrorC", func(l *logger) { l.ErrorC(ctx, "e %d", 3) }, "ERROR", "e 3", true, false},
		{"Panic", func(l *logger) { l.Panic("p %d", 1) }, "FATAL", "p 1", false, true},
		{"Panicf", func(l *logger) { l.Panicf("p %d", 2) }, "FATAL", "p 2", false, true},
		{"PanicC", func(l *logger) { l.PanicC(ctx, "p %d", 3) }, "FATAL", "p 3", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newTestLogger(t, LvlDebug, "orders")
			buf := &bytes.Buffer{}
			l.SetOutput(buf)

			if tt.panics {
				assert.Panics(t, func() { tt.call(l) })
			} else {
				tt.call(l)
			}

			doc := decodeJSONLine(t, buf.Bytes())
			assert.Equal(t, tt.wantLevel, doc["level"])
			assert.Equal(t, tt.wantMsg, doc["message"], "printf formatting still applies to msg")
			assert.Equal(t, "orders", doc["class"])
			assert.Equal(t, "-", doc["thread"])

			if tt.wantCtx {
				assert.Equal(t, "req-1", doc["request_id"], "context fields become keys for free")
				assert.Equal(t, "ten-1", doc["tenant_id"])
			} else {
				assert.Equal(t, "-", doc["request_id"])
			}
		})
	}
}

func TestJSONFormat_MessageWithPrintfVerbsAndSpecialChars_RoundTrips(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")
	SetOutputFormat(FormatJSON)

	l := newTestLogger(t, LvlInfo, "orders")
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	l.Info("path=%s err=%q newline=%s", `c:\tmp`, "boom\"quote", "a\nb")

	doc := decodeJSONLine(t, buf.Bytes())
	assert.Equal(t, `path=c:\tmp err="boom\"quote" newline=a`+"\nb", doc["message"])
}

func TestJSONFormat_MixedPhase1AndPhase2CallSites_SameDocumentShape(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")
	SetOutputFormat(FormatJSON)

	l := newTestLogger(t, LvlInfo, "orders")
	buf := &bytes.Buffer{}
	l.SetOutput(buf)

	l.InfoC(context.Background(), "order %d placed", 42)
	l.InfoWC(context.Background(), "order placed", "order_id", 42)

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2)

	legacy := decodeJSONLine(t, []byte(lines[0]+"\n"))
	structured := decodeJSONLine(t, []byte(lines[1]+"\n"))

	fixed := []string{"time", "level", "message", "request_id", "tenant_id", "thread", "class", "x_channel_request_id"}
	for _, key := range fixed {
		assert.Contains(t, legacy, key)
		assert.Contains(t, structured, key)
	}

	assert.Equal(t, "order 42 placed", legacy["message"], "phase 1 keeps the value inside the message")
	assert.Len(t, legacy, len(fixed))

	assert.Equal(t, "order placed", structured["message"], "phase 2 lifts the value out")
	assert.Equal(t, float64(42), structured["order_id"])
	assert.Len(t, structured, len(fixed)+1)
}

// TestJSONFormat_DeadlockFallbackStillEmits is the JSON analogue of TestLogger_TestMutex: a
// formatter that logs from inside itself must still produce output rather than hanging.
func TestJSONFormat_DeadlockFallbackStillEmits(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")
	SetOutputFormat(FormatJSON)

	buf := &syncBuffer{}
	l := newTestLogger(t, LvlInfo, "reentrant")
	l.SetOutput(buf)
	l.SetLogFormat(func(r *Record) []byte {
		l.Info("re-entrant call")
		return []byte("unreachable\n")
	})

	l.Info("outer")

	assert.Contains(t, buf.String(), "Possibility of deadlock or circular dependency")
}

func TestGetOutputFormat_ReflectsActive(t *testing.T) {
	withCleanLoggingState(t)

	SetOutputFormat(FormatJSON)
	assert.Equal(t, FormatJSON, GetOutputFormat())

	SetOutputFormat(FormatText)
	assert.Equal(t, FormatText, GetOutputFormat())
}

// setFormatConfig points the format setting at value, through whichever source
// resolveFormatFromConfig will actually consult.
//
// Setting the environment variable covers both paths: before configloader is initialised it is
// read directly by the bootstrap fallback, and afterwards EnvPropertySource maps LOGGING_FORMAT to
// the logging.format property -- but only once the configuration is re-read, hence the Refresh.
// An earlier test in this package initialises configloader process-wide and cannot undo it, so
// which path is live depends on test ordering; this helper makes that irrelevant.
func setFormatConfig(t *testing.T, value string) {
	t.Helper()

	inited := configloader.IsConfigLoaderInited()
	if inited {
		// Registered BEFORE t.Setenv on purpose. Cleanups run last-in-first-out, so t.Setenv's
		// own restore (registered after this one) runs first and this re-read then observes the
		// original environment. Registering it the other way round leaves configloader holding
		// the test's value for the remainder of the run, which silently reformats every later
		// test's output.
		t.Cleanup(func() {
			_ = configloader.Refresh()
			applyResolvedFormat()
		})
	}

	t.Setenv(FormatEnvName, value)

	if inited {
		require.NoError(t, configloader.Refresh())
	}
}
