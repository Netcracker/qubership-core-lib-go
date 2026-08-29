package logging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	lock "github.com/viney-shih/go-lock"
)

// Baseline benchmarks captured against the text-only implementation. They exist to make the
// performance impact of the JSON format and the structured-field API falsifiable: capture
//
//	go test -bench=. -benchmem -count=10 ./logging > baseline.txt
//
// before any production change, and compare with benchstat afterwards. The text path must not
// regress in ns/op or allocs/op; BenchmarkDefaultFormat_CustomFields3 must improve once the
// per-record regexp.Compile is hoisted.

var benchTime = time.Date(2026, 7, 30, 10, 0, 0, 123000000, time.UTC)

// benchSink keeps the compiler from eliminating the formatter calls.
var benchSink []byte

type benchLogValueObject struct {
	value string
}

func (o *benchLogValueObject) GetLogValue() string { return o.value }

// benchCtxWithValues builds the context shape a real request carries: the three well-known
// propagated ids, all as ContextObjectLogValueGetter implementations (that is what
// context-propagation actually stores).
func benchCtxWithValues() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIdContextName, &benchLogValueObject{"3f2a9c1e-req"})
	ctx = context.WithValue(ctx, TenantContextName, &benchLogValueObject{"tenant-42"})
	ctx = context.WithValue(ctx, ChannelRequestIdContextName, &benchLogValueObject{"chan-77"})
	return ctx
}

// benchCtxWithCustomFields adds the three keys referenced by the %{...} template used in the
// CustomFields3 benchmarks.
func benchCtxWithCustomFields() context.Context {
	ctx := benchCtxWithValues()
	ctx = context.WithValue(ctx, "business_process_id", "bp-1")
	ctx = context.WithValue(ctx, "originating_bi_id", "bi-2")
	ctx = context.WithValue(ctx, "x_version", "v3")
	return ctx
}

const benchCustomFieldsTemplate = "[business_process_id=%{business_process_id}] " +
	"[originating_bi_id=%{originating_bi_id}] [x_version=%{x_version}]"

func benchRecord(ctx context.Context) *Record {
	return &Record{
		PackageName: "orders",
		Time:        benchTime,
		Lvl:         LvlInfo,
		Message:     "order placed for customer acme with id 42",
		Ctx:         ctx,
	}
}

// setBenchCustomFields installs a custom-fields template and restores the previous value.
// The template is package-global state shared with every other test in this package.
func setBenchCustomFields(b *testing.B, template string) {
	b.Helper()
	previous := globalCustomFields.Load()
	DefaultFormat.SetCustomLogFields(template)
	b.Cleanup(func() { globalCustomFields.Store(previous) })
}

func benchLogger(lvl Lvl, name string) *logger {
	l := new(logger)
	l.maxLvl = lvl
	l.name = name
	l.mu = lock.NewChanMutex()
	return l
}

// ---------------------------------------------------------------------------
// Formatter-level: no I/O, no locking. Isolates the cost of building the line.
// ---------------------------------------------------------------------------

// BenchmarkDefaultFormat_NilCtx is the floor: the Fprintf pattern with every context lookup
// missing.
func BenchmarkDefaultFormat_NilCtx(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = DefaultFormat.format(r)
	}
}

// BenchmarkDefaultFormat_Ctx3Values adds three context.Value walks plus
// ContextObjectLogValueGetter dispatch on each.
func BenchmarkDefaultFormat_Ctx3Values(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(benchCtxWithValues())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = DefaultFormat.format(r)
	}
}

// BenchmarkDefaultFormat_CustomFields0 measures the custom-fields path when no template is
// configured. On the current implementation this still compiles the regexp on every record.
func BenchmarkDefaultFormat_CustomFields0(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(benchCtxWithValues())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = DefaultFormat.format(r)
	}
}

// BenchmarkDefaultFormat_CustomFields3 is the headline baseline: a three-field template, so the
// per-record regexp.Compile plus three ReplaceAll passes over the template are all exercised.
func BenchmarkDefaultFormat_CustomFields3(b *testing.B) {
	setBenchCustomFields(b, benchCustomFieldsTemplate)
	r := benchRecord(benchCtxWithCustomFields())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = DefaultFormat.format(r)
	}
}

// BenchmarkAssembleCustomLogFields isolates the regexp+replace work from the surrounding Fprintf.
func BenchmarkAssembleCustomLogFields(b *testing.B) {
	ctx := benchCtxWithCustomFields()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = assembleCustomLogFields(benchCustomFieldsTemplate, ctx)
	}
	_ = s
}

// ---------------------------------------------------------------------------
// Context lookup
// ---------------------------------------------------------------------------

func BenchmarkGetValueOrPlaceholder_Hit(b *testing.B) {
	ctx := benchCtxWithValues()
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = GetValueOrPlaceholder(ctx, RequestIdContextName)
	}
	_ = s
}

// BenchmarkGetValueOrPlaceholder_Miss walks a deliberately deep chain to the root without
// finding the key -- the worst case, and the common one for services that do not propagate a
// given id.
func BenchmarkGetValueOrPlaceholder_Miss(b *testing.B) {
	ctx := context.Background()
	for i := 0; i < 16; i++ {
		ctx = context.WithValue(ctx, "filler", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	var s string
	for i := 0; i < b.N; i++ {
		s = GetValueOrPlaceholder(ctx, RequestIdContextName)
	}
	_ = s
}

// ---------------------------------------------------------------------------
// Logger-level: end to end through log(), including Sprintf and the ChanMutex.
// Writes go to io.Discard so the measurement excludes syscall cost.
// ---------------------------------------------------------------------------

func BenchmarkLogger_InfoC_Discard(b *testing.B) {
	setBenchCustomFields(b, "")
	l := benchLogger(LvlInfo, "orders")
	ctx := benchCtxWithValues()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.log(ctx, LvlInfo, io.Discard, "order %d placed for %s", 42, "acme")
	}
}

// BenchmarkLogger_Disabled measures the early return when the record is filtered out by level.
// In production this is the most frequently executed path by a wide margin, so it must stay
// allocation free.
func BenchmarkLogger_Disabled(b *testing.B) {
	l := benchLogger(LvlInfo, "orders")
	ctx := benchCtxWithValues()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.log(ctx, LvlDebug, io.Discard, "order %d placed for %s", 42, "acme")
	}
}

// BenchmarkLogger_Parallel measures contention on the single per-logger ChanMutex that
// serialises every write.
func BenchmarkLogger_Parallel(b *testing.B) {
	setBenchCustomFields(b, "")
	l := benchLogger(LvlInfo, "orders")
	ctx := benchCtxWithValues()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.log(ctx, LvlInfo, io.Discard, "order %d placed for %s", 42, "acme")
		}
	})
}

// ---------------------------------------------------------------------------
// JSON format, A/B against the text counterparts above
// ---------------------------------------------------------------------------

func BenchmarkJSONFormat_NilCtx(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = JSONFormat.format(r)
	}
}

func BenchmarkJSONFormat_Ctx3Values(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(benchCtxWithValues())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = JSONFormat.format(r)
	}
}

func BenchmarkJSONFormat_CustomFields3(b *testing.B) {
	setBenchCustomFields(b, benchCustomFieldsTemplate)
	r := benchRecord(benchCtxWithCustomFields())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = JSONFormat.format(r)
	}
}

var benchFields = []Field{
	{"order_id", 42},
	{"customer", "acme"},
	{"amount", 19.99},
	{"express", true},
}

func BenchmarkJSONFormat_With4Fields(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(benchCtxWithValues())
	r.Fields = benchFields
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = JSONFormat.format(r)
	}
}

func BenchmarkTextFormat_With4Fields(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(benchCtxWithValues())
	r.Fields = benchFields
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = DefaultFormat.format(r)
	}
}

// BenchmarkJSONFormat_Parallel checks that the buffer pool actually helps under contention:
// allocs/op should stay close to the serial figure rather than growing.
func BenchmarkJSONFormat_Parallel(b *testing.B) {
	setBenchCustomFields(b, "")
	r := benchRecord(benchCtxWithValues())
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			benchSink = JSONFormat.format(r)
		}
	})
}

// ---------------------------------------------------------------------------
// JSON encoding primitives
// ---------------------------------------------------------------------------

func benchWriteJSONString(b *testing.B, s string) {
	b.Helper()
	buf := &bytes.Buffer{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		writeJSONString(buf, s)
	}
}

func BenchmarkWriteJSONString_Clean(b *testing.B) {
	benchWriteJSONString(b, "order placed for customer acme with id 42")
}

func BenchmarkWriteJSONString_NeedsEscaping(b *testing.B) {
	benchWriteJSONString(b, "order \"placed\"\nfor\tcustomer c:\\acme")
}

func BenchmarkWriteJSONString_Unicode(b *testing.B) {
	benchWriteJSONString(b, "заказ размещён 🎉 для клиента")
}

// BenchmarkWriteJSONValue_ByType has one sub-benchmark per arm of the type switch. A regression
// here -- especially an arm silently falling through to the fmt.Sprint default -- shows up as a
// large jump in that one sub-benchmark.
func BenchmarkWriteJSONValue_ByType(b *testing.B) {
	values := []struct {
		name string
		v    any
	}{
		{"string", "acme"},
		{"bool", true},
		{"int", 42},
		{"int64", int64(42)},
		{"uint64", uint64(42)},
		{"float64", 19.99},
		{"nil", nil},
		{"bytes", []byte("raw")},
		{"error", errBench},
		{"stringer", benchStringer{"str"}},
		{"logvalue", &benchLogValueObject{"lv"}},
		{"struct", struct{ A int }{1}},
	}

	for _, tt := range values {
		b.Run(tt.name, func(b *testing.B) {
			buf := &bytes.Buffer{}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf.Reset()
				writeJSONValue(buf, tt.v)
			}
		})
	}
}

var errBench = errors.New("boom")

type benchStringer struct{ v string }

func (s benchStringer) String() string { return s.v }

// ---------------------------------------------------------------------------
// Structured field plumbing
// ---------------------------------------------------------------------------

func BenchmarkArgsToFields_4Pairs(b *testing.B) {
	args := []any{"order_id", 42, "customer", "acme", "amount", 19.99, "express", true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argsToFields(args)
	}
}

func BenchmarkArgsToFields_Odd(b *testing.B) {
	args := []any{"order_id", 42, "dangling"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argsToFields(args)
	}
}

// BenchmarkArgsToFields_Empty must stay at zero allocations: it is on the path of every W call
// made without inline fields.
func BenchmarkArgsToFields_Empty(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = argsToFields(nil)
	}
}

func BenchmarkWith_Depth1(b *testing.B) {
	l := benchLogger(LvlInfo, "orders")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.With("env", "prod")
	}
}

func BenchmarkWith_Depth3(b *testing.B) {
	l := benchLogger(LvlInfo, "orders")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = l.With("env", "prod").With("component", "checkout").With("shard", 3)
	}
}

// BenchmarkWith_ThenLog_Discard is the realistic per-request shape: derive a scoped logger once,
// then log through it.
func BenchmarkWith_ThenLog_Discard(b *testing.B) {
	setBenchCustomFields(b, "")
	l := benchLogger(LvlInfo, "orders")
	l.SetOutput(io.Discard)
	ctx := benchCtxWithValues()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.With("env", "prod").InfoWC(ctx, "order placed", "order_id", 42)
	}
}

func BenchmarkLogger_InfoWC_Discard(b *testing.B) {
	setBenchCustomFields(b, "")
	l := benchLogger(LvlInfo, "orders")
	l.SetOutput(io.Discard)
	ctx := benchCtxWithValues()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.InfoWC(ctx, "order placed", "order_id", 42, "customer", "acme")
	}
}

// BenchmarkFormatResolution measures the atomic-load chain that picks a formatter on every record.
// It should be a handful of nanoseconds; anything more means a lock or an allocation crept in.
func BenchmarkFormatResolution(b *testing.B) {
	l := benchLogger(LvlInfo, "orders")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if f := l.root().logFormat.Load(); f != nil {
			benchSink = (*f)(nil)
			continue
		}
		if f := globalLogFormat.Load(); f != nil {
			benchSink = (*f)(nil)
			continue
		}
		benchFormatFuncSink = formatFuncFor(GetOutputFormat())
	}
}

var benchFormatFuncSink LogFormatFunc
