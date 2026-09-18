package logging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func jsonRecord(ctx context.Context) *Record {
	return &Record{
		PackageName: "orders",
		Time:        compatTime,
		Lvl:         LvlInfo,
		Message:     "order placed",
		Ctx:         ctx,
	}
}

// decodeJSONLine asserts the formatter produced exactly one newline-terminated JSON document and
// returns it decoded.
func decodeJSONLine(t *testing.T, line []byte) map[string]any {
	t.Helper()
	require.True(t, strings.HasSuffix(string(line), "\n"), "line must be newline terminated")
	require.Equal(t, 1, strings.Count(string(line), "\n"), "line must contain exactly one newline")

	var doc map[string]any
	require.NoError(t, json.Unmarshal(line, &doc), "output must be valid JSON: %s", line)
	return doc
}

func TestJSONFormat_BaseSchema_AllPlaceholders(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	doc := decodeJSONLine(t, JSONFormat.format(jsonRecord(nil)))

	assert.Equal(t, map[string]any{
		"time":                 "2026-07-30T10:15:03.123",
		"level":                "INFO",
		"message":              "order placed",
		"request_id":           "-",
		"tenant_id":            "-",
		"thread":               "-",
		"class":                "orders",
		"x_channel_request_id": "-",
	}, doc)
}

// TestJSONFormat_KeyOrderIsStable asserts on raw bytes rather than the decoded map: the readability
// rationale for the JSON format is that time, level and message come first.
func TestJSONFormat_KeyOrderIsStable(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	line := string(JSONFormat.format(jsonRecord(nil)))

	assert.Equal(t,
		`{"time":"2026-07-30T10:15:03.123","level":"INFO","message":"order placed",`+
			`"request_id":"-","tenant_id":"-","thread":"-","class":"orders","x_channel_request_id":"-"}`+"\n",
		line)
}

func TestJSONFormat_CtxValues(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIdContextName, &compatLogValueObject{"req-id"})
	ctx = context.WithValue(ctx, TenantContextName, "plain-tenant")
	ctx = context.WithValue(ctx, ChannelRequestIdContextName, &compatPlainObject{"ignored"})
	ctx = context.WithValue(ctx, CallerPropertyName, "CreateOrder")

	doc := decodeJSONLine(t, JSONFormat.format(jsonRecord(ctx)))

	assert.Equal(t, "req-id", doc["request_id"], "ContextObjectLogValueGetter must be unwrapped")
	assert.Equal(t, "plain-tenant", doc["tenant_id"], "plain strings pass through")
	assert.Equal(t, "-", doc["x_channel_request_id"], "unsupported types fall back to the placeholder")
	assert.Equal(t, "orders.CreateOrder", doc["class"], "caller is appended to class as in text mode")
}

func TestJSONFormat_CustomTemplateFieldsBecomeTopLevelKeys(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("[bp=%{business_process_id}] [ob=%{originating_bi_id}]")

	ctx := context.WithValue(context.Background(), "business_process_id", "bp-1")

	doc := decodeJSONLine(t, JSONFormat.format(jsonRecord(ctx)))

	// The template's literal text is dropped entirely; only the names survive, as real keys.
	assert.Equal(t, "bp-1", doc["business_process_id"])
	assert.Equal(t, "-", doc["originating_bi_id"])
	assert.Equal(t, "order placed", doc["message"], "the template must not be folded into the message")
	assert.NotContains(t, string(JSONFormat.format(jsonRecord(ctx))), "[bp=")
}

func TestJSONFormat_WithFieldsAppendedLast(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	r := jsonRecord(nil)
	r.Fields = []Field{{"order_id", 42}, {"amount", 19.99}, {"express", true}}

	line := string(JSONFormat.format(r))
	assert.True(t, strings.HasSuffix(line, `"order_id":42,"amount":19.99,"express":true}`+"\n"), line)

	doc := decodeJSONLine(t, []byte(line))
	assert.Equal(t, float64(42), doc["order_id"])
	assert.Equal(t, 19.99, doc["amount"])
	assert.Equal(t, true, doc["express"])
}

func TestJSONFormat_DuplicateKeyIsEmittedAsIs(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	r := jsonRecord(nil)
	r.Fields = []Field{{"message", "shadow"}}

	// Still a parseable document; last value wins per encoding/json. Documented as "avoid reserved
	// keys" rather than paying for per-record de-duplication.
	doc := decodeJSONLine(t, JSONFormat.format(r))
	assert.Equal(t, "shadow", doc["message"])
}

func TestJSONFormat_Escaping_Table(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	tests := []struct {
		name    string
		message string
	}{
		{"double quote", `he said "hi"`},
		{"backslash", `c:\tmp\file`},
		{"newline", "line1\nline2"},
		{"carriage return", "line1\rline2"},
		{"tab", "col1\tcol2"},
		{"backspace and formfeed", "a\bb\fc"},
		{"null byte", "a\x00b"},
		{"all control chars", "\x01\x02\x03\x04\x05\x06\x07\x0b\x0e\x0f\x1e\x1f"},
		{"del", "a\x7fb"},
		{"line separator U+2028", "a\u2028b"},
		{"paragraph separator U+2029", "a\u2029b"},
		{"emoji", "order 🎉 placed"},
		{"cyrillic", "заказ размещён"},
		{"invalid utf8", "bad\xffbyte"},
		{"lone surrogate bytes", "x\xed\xa0\x80y"},
		{"very long", strings.Repeat("a", 64*1024)},
		{"empty", ""},
		{"json injection attempt", `","level":"FATAL","injected":"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := jsonRecord(nil)
			r.Message = tt.message

			doc := decodeJSONLine(t, JSONFormat.format(r))

			// Level must survive: proves the message could not break out of its string and inject
			// sibling keys.
			assert.Equal(t, "INFO", doc["level"])

			if utf8Valid(tt.message) {
				assert.Equal(t, tt.message, doc["message"], "valid UTF-8 must round-trip exactly")
			} else {
				assert.Contains(t, doc["message"].(string), "\uFFFD", "invalid UTF-8 becomes U+FFFD")
			}
		})
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

func TestJSONFormat_EscapedControlCharsAreNotRawBytes(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	r := jsonRecord(nil)
	r.Message = "a\x01b\u2028c"

	line := string(JSONFormat.format(r))

	assert.Contains(t, line, `\u0001`)
	assert.Contains(t, line, `\u2028`)
	assert.NotContains(t, line, "\x01", "raw control byte must not reach the output")
}

type jsonStringerValue struct{ v string }

func (s jsonStringerValue) String() string { return s.v }

type jsonErrorStringer struct{}

func (jsonErrorStringer) Error() string  { return "from Error" }
func (jsonErrorStringer) String() string { return "from String" }

func TestJSONFormat_ValueTypes_Table(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	tests := []struct {
		name string
		in   any
		want any
	}{
		{"string", "v", "v"},
		{"bool true", true, true},
		{"bool false", false, false},
		{"int", 42, float64(42)},
		{"negative int", -7, float64(-7)},
		{"int8", int8(8), float64(8)},
		{"int16", int16(16), float64(16)},
		{"int32", int32(32), float64(32)},
		{"int64", int64(64), float64(64)},
		{"uint", uint(1), float64(1)},
		{"uint8", uint8(2), float64(2)},
		{"uint16", uint16(3), float64(3)},
		{"uint32", uint32(4), float64(4)},
		{"uint64", uint64(5), float64(5)},
		{"float64", 19.99, 19.99},
		{"float32", float32(1.5), 1.5},
		{"nil", nil, nil},
		{"byte slice", []byte("raw"), "raw"},
		{"error", errors.New("boom"), "boom"},
		{"error preferred over stringer", jsonErrorStringer{}, "from Error"},
		{"stringer", jsonStringerValue{"str"}, "str"},
		{"log value getter", fieldsLogValue{"lv"}, "lv"},
		{"unknown struct", struct{ A int }{1}, "{1}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := jsonRecord(nil)
			r.Fields = []Field{{"v", tt.in}}

			doc := decodeJSONLine(t, JSONFormat.format(r))
			assert.Equal(t, tt.want, doc["v"])
		})
	}
}

// TestJSONFormat_NonFiniteFloats covers the values JSON cannot represent. Emitting a bare NaN would
// make the whole document unparseable.
func TestJSONFormat_NonFiniteFloats(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	for _, tt := range []struct {
		name string
		in   float64
		want string
	}{
		{"NaN", math.NaN(), "NaN"},
		{"positive infinity", math.Inf(1), "+Inf"},
		{"negative infinity", math.Inf(-1), "-Inf"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := jsonRecord(nil)
			r.Fields = []Field{{"v", tt.in}}

			doc := decodeJSONLine(t, JSONFormat.format(r))
			assert.Equal(t, tt.want, doc["v"])
		})
	}
}

func TestJSONFormat_AllLevels(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	for lvl, want := range map[Lvl]string{
		LvlCrit:  "FATAL",
		LvlError: "ERROR",
		LvlWarn:  "WARN",
		LvlInfo:  "INFO",
		LvlDebug: "DEBUG",
	} {
		r := jsonRecord(nil)
		r.Lvl = lvl
		doc := decodeJSONLine(t, JSONFormat.format(r))
		assert.Equal(t, want, doc["level"])
	}
}

func TestJSONFormat_ZeroValueRecord(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	doc := decodeJSONLine(t, JSONFormat.format(&Record{}))

	assert.Equal(t, "0001-01-01T00:00:00.000", doc["time"])
	assert.Equal(t, "FATAL", doc["level"])
	assert.Equal(t, "", doc["message"])
	assert.Equal(t, "Default", doc["class"])
}

// TestJSONFormat_ReturnedSliceNotAliasedAfterReuse catches the classic pooled-buffer bug: returning
// b.Bytes() instead of a copy, so the next format() call overwrites a slice a caller still holds.
func TestJSONFormat_ReturnedSliceNotAliasedAfterReuse(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	first := jsonRecord(nil)
	first.Message = "first message"
	firstLine := JSONFormat.format(first)
	firstCopy := string(firstLine)

	second := jsonRecord(nil)
	second.Message = "second message wow much longer than the first one"
	_ = JSONFormat.format(second)

	assert.Equal(t, firstCopy, string(firstLine), "a previously returned line must not be mutated")
	assert.Contains(t, string(firstLine), "first message")
}

// TestJSONFormat_PoolNoCrossContamination hammers the shared pool from many goroutines. Each line
// must be a complete, valid document containing only its own message.
func TestJSONFormat_PoolNoCrossContamination(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	const goroutines = 200

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			want := fmt.Sprintf("message-%03d-%s", i, strings.Repeat("x", i))
			r := jsonRecord(nil)
			r.Message = want
			r.Fields = []Field{{"i", i}}

			line := JSONFormat.format(r)

			var doc map[string]any
			if err := json.Unmarshal(line, &doc); err != nil {
				errCh <- fmt.Errorf("goroutine %d: invalid JSON %q: %w", i, line, err)
				return
			}
			if doc["message"] != want {
				errCh <- fmt.Errorf("goroutine %d: got message %q, want %q", i, doc["message"], want)
			}
			if doc["i"] != float64(i) {
				errCh <- fmt.Errorf("goroutine %d: got i %v", i, doc["i"])
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

func TestJSONFormat_LargeMessageIsNotPooled(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	r := jsonRecord(nil)
	r.Message = strings.Repeat("a", maxPooledBuffer*2)

	doc := decodeJSONLine(t, JSONFormat.format(r))
	assert.Len(t, doc["message"], maxPooledBuffer*2)

	// A normal record after the oversized one must still format correctly.
	doc = decodeJSONLine(t, JSONFormat.format(jsonRecord(nil)))
	assert.Equal(t, "order placed", doc["message"])
}
