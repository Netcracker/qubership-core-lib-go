package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCapturingLogger returns an unregistered logger writing into the returned buffer.
func newCapturingLogger(t *testing.T, lvl Lvl, name string) (*logger, *bytes.Buffer) {
	t.Helper()
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	l := newTestLogger(t, lvl, name)
	buf := &bytes.Buffer{}
	l.SetOutput(buf)
	return l, buf
}

func TestFieldLogger_Embeds_Logger(t *testing.T) {
	var fl FieldLogger = newTestLogger(t, LvlInfo, "test")
	var asLogger Logger = fl
	assert.NotNil(t, asLogger)
}

func TestGetFieldLogger_ReturnsSameInstanceAsGetLogger(t *testing.T) {
	plain := registerTestLogger(t, "same_instance")
	structured := GetFieldLogger("same_instance")
	assert.Same(t, plain, structured)
}

// TestW_MessageIsLiteral_NotPrintf is the defining difference between the W methods and the
// printf-style ones: msg must never be run through fmt.Sprintf.
func TestW_MessageIsLiteral_NotPrintf(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	l.InfoW("100% done, %s and %d untouched", "k", 1)

	out := buf.String()
	assert.Contains(t, out, "100% done, %s and %d untouched")
	assert.NotContains(t, out, "%!", "no printf error verbs may appear")
}

func TestW_TextRendering_FieldsFollowMessage(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	l.InfoW("order placed", "order_id", 42, "amount", 19.99, "note", "two words")

	assert.Equal(t,
		"[order placed order_id=42 amount=19.99 note=\"two words\"]",
		"["+strings.SplitN(strings.TrimSuffix(buf.String(), "\n"), "] ", 8)[7]+"]")
}

func TestW_NoFields_ProducesLegacyLine(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	l.InfoW("order placed")

	// Byte-identical to what InfoC("order placed") produces: the fields segment must vanish
	// entirely, not render as an empty trailing space.
	line := buf.String()
	assert.True(t, strings.HasSuffix(line, "[x_channel_request_id=-] order placed\n"), line)
}

func TestW_Methods_RespectLevelFilter(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlWarn, "orders")

	l.DebugW("debug", "k", 1)
	l.InfoW("info", "k", 1)
	assert.Empty(t, buf.String(), "records below the level must not be written")

	l.WarnW("warn", "k", 1)
	l.ErrorW("error", "k", 1)
	assert.Contains(t, buf.String(), "warn k=1")
	assert.Contains(t, buf.String(), "error k=1")
}

func TestW_ContextVariantsResolveContextFields(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlDebug, "orders")

	ctx := context.WithValue(context.Background(), RequestIdContextName, "req-9")

	l.DebugWC(ctx, "d", "k", 1)
	l.InfoWC(ctx, "i", "k", 2)
	l.WarnWC(ctx, "w", "k", 3)
	l.ErrorWC(ctx, "e", "k", 4)

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 4)
	for _, line := range lines {
		assert.Contains(t, line, "[request_id=req-9]")
	}
	assert.Contains(t, lines[0], "[DEBUG]")
	assert.Contains(t, lines[1], "[INFO]")
	assert.Contains(t, lines[2], "[WARN]")
	assert.Contains(t, lines[3], "[ERROR]")
}

func TestPanicW_PanicsOnceWithLiteralMessage(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	assert.PanicsWithValue(t, "100% broken", func() {
		l.PanicW("100% broken", "k", 1)
	})
	assert.Contains(t, buf.String(), "[FATAL]")
	assert.Contains(t, buf.String(), "100% broken k=1")
}

func TestPanicWC_PanicsOnceWithLiteralMessage(t *testing.T) {
	l, _ := newCapturingLogger(t, LvlInfo, "orders")

	assert.PanicsWithValue(t, "boom", func() {
		l.PanicWC(context.Background(), "boom", "k", 1)
	})
}

func TestWith_ParentUnaffected(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	child := l.With("env", "prod")
	child.InfoW("from child")
	l.InfoW("from parent")

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "from child env=prod")
	assert.Contains(t, lines[1], "from parent")
	assert.NotContains(t, lines[1], "env=prod", "the parent must not inherit the child's fields")
}

func TestWith_ChainOrderPreserved(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	l.With("a", 1).With("b", 2).InfoW("msg", "c", 3)

	assert.Contains(t, buf.String(), "msg a=1 b=2 c=3")
}

// TestWith_SiblingsDoNotShareBackingArray is the end-to-end counterpart of
// TestConcatFields_NoBackingArrayAliasing: two children of one parent must never see each other's
// fields.
func TestWith_SiblingsDoNotShareBackingArray(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	parent := l.With("shared", "yes")
	first := parent.With("only", "first")
	second := parent.With("only", "second")

	first.InfoW("one")
	second.InfoW("two")

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "one shared=yes only=first")
	assert.NotContains(t, lines[0], "second")
	assert.Contains(t, lines[1], "two shared=yes only=second")
	assert.NotContains(t, lines[1], "first")
}

func TestWith_NoArgsReturnsReceiver(t *testing.T) {
	l := newTestLogger(t, LvlInfo, "orders")
	assert.Same(t, l, l.With())
}

func TestWith_MalformedArgsUseBadKey(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")

	l.With("dangling").InfoW("msg", 7)

	assert.Contains(t, buf.String(), "!BADKEY=dangling")
	assert.Contains(t, buf.String(), "!BADKEY=7")
}

func TestWith_DelegatesLevelToParent(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")
	child := l.With("env", "prod")

	child.InfoW("visible")
	assert.Contains(t, buf.String(), "visible")

	// Raising the level on the parent must silence the already-derived child.
	buf.Reset()
	l.SetLevel(LvlError)
	child.InfoW("hidden")
	assert.Empty(t, buf.String())

	// ...and the child's own SetLevel must reach the parent, since a child is a view.
	child.SetLevel(LvlDebug)
	assert.Equal(t, LvlDebug, l.GetLevel())
	assert.Equal(t, LvlDebug, child.GetLevel())
}

func TestWith_ChildNotInRegistry(t *testing.T) {
	l := registerTestLogger(t, "registry_parent")
	l.SetLevel(LvlInfo)

	fl := GetFieldLogger("registry_parent").With("env", "prod")
	fl.InfoW("noop")

	levels := GetLogLevels()
	assert.Contains(t, levels, "registry_parent")
	for name := range levels {
		assert.NotContains(t, name, "env", "derived loggers must not appear in the registry")
	}
}

func TestWith_ChildInheritsOutputAndFormat(t *testing.T) {
	l, buf := newCapturingLogger(t, LvlInfo, "orders")
	SetOutputFormat(FormatJSON)

	l.With("env", "prod").InfoW("order placed", "order_id", 42)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	assert.Equal(t, "prod", doc["env"])
	assert.Equal(t, float64(42), doc["order_id"])
	assert.Equal(t, "orders", doc["class"], "the child keeps the parent's logger name")
}

func TestWith_ConcurrentChildren_NoRace(t *testing.T) {
	l, _ := newCapturingLogger(t, LvlInfo, "orders")
	parent := l.With("shared", "yes")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			parent.With("i", i).InfoW("concurrent", "j", i)
		}(i)
	}
	wg.Wait()
}

// foreignLogger implements only Logger, mimicking a downstream mock. Fields() must adapt it
// instead of panicking.
type foreignLogger struct {
	lines []string
}

func (f *foreignLogger) GetLevel() Lvl                       { return LvlDebug }
func (f *foreignLogger) SetLevel(Lvl)                        {}
func (f *foreignLogger) SetLogFormat(func(r *Record) []byte) {}
func (f *foreignLogger) SetMessageFormat(messageFmt)         {}
func (f *foreignLogger) record(format string, args ...interface{}) {
	f.lines = append(f.lines, sprintf(format, args...))
}

func (f *foreignLogger) Debug(format string, args ...interface{})  { f.record(format, args...) }
func (f *foreignLogger) Debugf(format string, args ...interface{}) { f.record(format, args...) }
func (f *foreignLogger) DebugC(_ context.Context, format string, args ...interface{}) {
	f.record(format, args...)
}
func (f *foreignLogger) Info(format string, args ...interface{})  { f.record(format, args...) }
func (f *foreignLogger) Infof(format string, args ...interface{}) { f.record(format, args...) }
func (f *foreignLogger) InfoC(_ context.Context, format string, args ...interface{}) {
	f.record(format, args...)
}
func (f *foreignLogger) Warn(format string, args ...interface{})  { f.record(format, args...) }
func (f *foreignLogger) Warnf(format string, args ...interface{}) { f.record(format, args...) }
func (f *foreignLogger) WarnC(_ context.Context, format string, args ...interface{}) {
	f.record(format, args...)
}
func (f *foreignLogger) Error(format string, args ...interface{})  { f.record(format, args...) }
func (f *foreignLogger) Errorf(format string, args ...interface{}) { f.record(format, args...) }
func (f *foreignLogger) ErrorC(_ context.Context, format string, args ...interface{}) {
	f.record(format, args...)
}
func (f *foreignLogger) Panic(format string, args ...interface{}) {
	f.record(format, args...)
	panic(sprintf(format, args...))
}
func (f *foreignLogger) Panicf(format string, args ...interface{}) { f.Panic(format, args...) }
func (f *foreignLogger) PanicC(_ context.Context, format string, args ...interface{}) {
	f.Panic(format, args...)
}

func TestFields_ForeignLoggerImpl_DoesNotPanic(t *testing.T) {
	foreign := &foreignLogger{}

	adapted := Fields(foreign)
	require.NotNil(t, adapted)

	adapted.InfoW("order placed", "order_id", 42)
	adapted.With("env", "prod").WarnW("careful", "attempt", 2)
	adapted.ErrorWC(context.Background(), "failed", "err", "boom")

	assert.Equal(t, []string{
		"order placed order_id=42",
		"careful env=prod attempt=2",
		"failed err=boom",
	}, foreign.lines)
}

// TestFields_ForeignLoggerImpl_MessageWithPercentIsNotReinterpreted guards the adapter's use of a
// "%s" format: the foreign Logger is printf-style, so a literal '%' must not become a verb.
func TestFields_ForeignLoggerImpl_MessageWithPercentIsNotReinterpreted(t *testing.T) {
	foreign := &foreignLogger{}

	Fields(foreign).InfoW("100% done", "k", 1)

	assert.Equal(t, []string{"100% done k=1"}, foreign.lines)
}

func TestFields_OnPackageLogger_IsPlainAssertion(t *testing.T) {
	l := newTestLogger(t, LvlInfo, "orders")
	assert.Same(t, l, Fields(l))
}

func TestFields_ForeignLoggerPanicW(t *testing.T) {
	foreign := &foreignLogger{}
	assert.PanicsWithValue(t, "boom", func() {
		Fields(foreign).PanicW("boom", "k", 1)
	})
	assert.Equal(t, []string{"boom k=1"}, foreign.lines)
}
