package logging

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// JSON keys emitted by the JSON format. The key set mirrors the text format exactly so queries
// translate mechanically between the two; only the emission order differs.
const (
	JSONKeyTime      = "time"
	JSONKeyLevel     = "level"
	JSONKeyMessage   = "message"
	JSONKeyRequestId = "request_id"
	JSONKeyTenantId  = "tenant_id"
	JSONKeyThread    = "thread"
	JSONKeyClass     = "class"
	JSONKeyChannelId = "x_channel_request_id"
)

// jsonFormat renders a Record as a single-line JSON document.
//
// Key order is fixed and deliberately not the text field order: time, level and message lead so a
// raw line stays scannable in a terminal without jq, and everything else follows as additional
// fields. JSON consumers are order-insensitive, so this costs nothing downstream.
//
//	{"time":"2026-07-30T10:15:03.123","level":"INFO","message":"order placed",
//	 "request_id":"-","tenant_id":"-","thread":"-","class":"orders",
//	 "x_channel_request_id":"-","order_id":42}
//
// Absent context values render as the "-" placeholder string rather than null, matching the text
// format's long-standing contract.
type jsonFormat struct{}

// JSONFormat is the JSON formatter instance used when the log format is set to json.
var JSONFormat = &jsonFormat{}

// jsonBufPool recycles the scratch buffers used to build log lines. format() always returns a copy
// of the assembled bytes, never the pooled buffer's own storage, so a recycled buffer can never
// corrupt a line that has already been handed to a writer.
var jsonBufPool = sync.Pool{
	New: func() any {
		b := new(bytes.Buffer)
		b.Grow(512)
		return b
	},
}

// maxPooledBuffer caps what goes back into the pool. A single very large message must not pin
// megabytes of scratch space for the lifetime of the process.
const maxPooledBuffer = 64 << 10

func (f *jsonFormat) format(r *Record) []byte {
	b := jsonBufPool.Get().(*bytes.Buffer)
	b.Reset()
	defer func() {
		if b.Cap() <= maxPooledBuffer {
			jsonBufPool.Put(b)
		}
	}()

	b.WriteByte('{')

	writeJSONKV(b, JSONKeyTime, r.Time.Format(TimeFormat))
	b.WriteByte(',')
	writeJSONKV(b, JSONKeyLevel, strings.ToUpper(r.Lvl.String()))
	b.WriteByte(',')
	writeJSONKV(b, JSONKeyMessage, r.Message)
	b.WriteByte(',')
	writeJSONKV(b, JSONKeyRequestId, GetValueOrPlaceholder(r.Ctx, RequestIdContextName))
	b.WriteByte(',')
	writeJSONKV(b, JSONKeyTenantId, GetValueOrPlaceholder(r.Ctx, TenantContextName))
	b.WriteByte(',')
	// Hardcoded to match the text format's literal [thread=-]; Go has no thread identity to report.
	writeJSONKV(b, JSONKeyThread, valuePlaceholder)
	b.WriteByte(',')
	writeJSONKV(b, JSONKeyClass, ConstructCallerValueByRecord(r))
	b.WriteByte(',')
	writeJSONKV(b, JSONKeyChannelId, GetValueOrPlaceholder(r.Ctx, ChannelRequestIdContextName))

	// Custom-template fields become discrete keys here rather than being substituted into the
	// message as they are in text format -- that promotion is the whole point of the JSON format.
	for _, name := range customFieldNames() {
		b.WriteByte(',')
		writeJSONKV(b, name, GetValueOrPlaceholder(r.Ctx, name))
	}

	// Structured fields last. Duplicate keys (a field literally named "message") are emitted as-is;
	// de-duplicating would need a per-record map and defeat the pooled-buffer design.
	for _, field := range r.Fields {
		b.WriteByte(',')
		writeJSONString(b, field.Key)
		b.WriteByte(':')
		writeJSONValue(b, field.Value)
	}

	b.WriteString("}\n")

	// Copy: the buffer goes back to the pool the moment this function returns.
	out := make([]byte, b.Len())
	copy(out, b.Bytes())
	return out
}

func writeJSONKV(b *bytes.Buffer, key, value string) {
	writeJSONString(b, key)
	b.WriteByte(':')
	writeJSONString(b, value)
}

// writeJSONValue encodes a structured-field value. The type switch covers everything that shows up
// in practice so the hot path never reaches encoding/json's reflection. Anything unrecognised is
// rendered with fmt.Sprint and written as a JSON string -- never as raw bytes, so an exotic value
// can never break the document.
func writeJSONValue(b *bytes.Buffer, v any) {
	switch value := v.(type) {
	case nil:
		b.WriteString("null")
	case string:
		writeJSONString(b, value)
	case bool:
		if value {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.Itoa(value))
	case int8:
		b.WriteString(strconv.FormatInt(int64(value), 10))
	case int16:
		b.WriteString(strconv.FormatInt(int64(value), 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(value), 10))
	case int64:
		b.WriteString(strconv.FormatInt(value, 10))
	case uint:
		b.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint8:
		b.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint16:
		b.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(value, 10))
	case float32:
		writeJSONFloat(b, float64(value), 32)
	case float64:
		writeJSONFloat(b, value, 64)
	case []byte:
		writeJSONString(b, string(value))
	case error:
		// Before Stringer: an error that also implements Stringer must still log its Error() text.
		writeJSONString(b, value.Error())
	case ContextObjectLogValueGetter:
		writeJSONString(b, value.GetLogValue())
	case fmt.Stringer:
		writeJSONString(b, value.String())
	default:
		writeJSONString(b, fmt.Sprint(value))
	}
}

// writeJSONFloat emits a JSON number, falling back to a string for NaN and infinities, which JSON
// cannot represent. Dropping them or writing a bare NaN would produce an unparseable document.
func writeJSONFloat(b *bytes.Buffer, f float64, bitSize int) {
	if math.IsNaN(f) {
		b.WriteString(`"NaN"`)
		return
	}
	if math.IsInf(f, 1) {
		b.WriteString(`"+Inf"`)
		return
	}
	if math.IsInf(f, -1) {
		b.WriteString(`"-Inf"`)
		return
	}
	b.WriteString(strconv.FormatFloat(f, 'g', -1, bitSize))
}

const hexDigits = "0123456789abcdef"

// writeJSONString writes s as a quoted, escaped JSON string per RFC 8259.
//
// Beyond the mandatory escapes it also escapes U+2028 and U+2029, which are legal in JSON but
// terminate a line in JavaScript and break log viewers that eval documents, and it replaces
// invalid UTF-8 with U+FFFD so a log line can never be rejected by a strict parser because some
// caller logged a raw byte slice.
func writeJSONString(b *bytes.Buffer, s string) {
	b.WriteByte('"')

	start := 0
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			if start < i {
				b.WriteString(s[start:i])
			}
			switch c {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			default:
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if start < i {
				b.WriteString(s[start:i])
			}
			b.WriteString(`�`)
			i += size
			start = i
			continue
		}
		if r == ' ' || r == ' ' {
			if start < i {
				b.WriteString(s[start:i])
			}
			b.WriteString(`\u202`)
			b.WriteByte(hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}

	if start < len(s) {
		b.WriteString(s[start:])
	}
	b.WriteByte('"')
}
