package logging

import (
	"bytes"
	"fmt"
	"strconv"
)

// BadKeyPlaceholder is used as the key when a structured-field argument list is malformed -- an odd
// trailing argument, or a non-string in a key position. Matching log/slog, a malformed argument
// list never panics and never silently drops data: the offending value is still logged, under this
// key, so the mistake is visible in the output instead of invisible in the code.
const BadKeyPlaceholder = "!BADKEY"

// Field is a single structured key/value pair attached to a log record.
type Field struct {
	Key   string
	Value any
}

// argsToFields converts a flat slog-style argument list into fields.
//
//	argsToFields([]any{"user_id", 42, "tenant", "acme"})
//	    -> [{user_id 42} {tenant acme}]
//
// Malformed input degrades rather than failing:
//
//	"key" as the final argument  -> {!BADKEY "key"}
//	non-string in a key position -> {!BADKEY <value>}
//
// Returns nil (not an empty slice) for empty input so callers keep the zero-allocation path.
func argsToFields(args []any) []Field {
	if len(args) == 0 {
		return nil
	}

	fields := make([]Field, 0, (len(args)+1)/2)
	for i := 0; i < len(args); {
		key, ok := args[i].(string)
		switch {
		case !ok:
			// Not a string where a key was expected: consume just this element, so the rest of
			// the list still has a chance to parse as well-formed pairs.
			fields = append(fields, Field{Key: BadKeyPlaceholder, Value: args[i]})
			i++
		case i+1 >= len(args):
			// Dangling key with no value.
			fields = append(fields, Field{Key: BadKeyPlaceholder, Value: key})
			i++
		default:
			fields = append(fields, Field{Key: key, Value: args[i+1]})
			i += 2
		}
	}
	return fields
}

// concatFields returns the concatenation of parent and extra in a freshly allocated slice.
//
// The fresh allocation is not an optimisation detail, it is the correctness requirement. Using
// append(parent, extra...) would let two child loggers derived from the same parent share a
// backing array and overwrite each other's fields:
//
//	p  := log.With("a", 1)   // len 1, cap 2
//	c1 := p.With("b", 2)     // would write into p's spare capacity
//	c2 := p.With("c", 3)     // would overwrite c1's "b"
func concatFields(parent, extra []Field) []Field {
	if len(extra) == 0 {
		return parent
	}
	if len(parent) == 0 {
		return extra
	}
	out := make([]Field, len(parent)+len(extra))
	copy(out, parent)
	copy(out[len(parent):], extra)
	return out
}

// renderFieldsAsText renders fields in logfmt style ("k=v k2=\"v with space\"") for the text
// format. Returns "" for no fields so the caller's JoinStringsWithSpace drops the segment entirely
// and the emitted line stays byte-identical to the pre-structured-fields output.
func renderFieldsAsText(fields []Field) string {
	if len(fields) == 0 {
		return ""
	}
	b := &bytes.Buffer{}
	appendLogfmt(b, fields)
	return b.String()
}

// appendLogfmt writes fields to b as space-separated key=value pairs.
func appendLogfmt(b *bytes.Buffer, fields []Field) {
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(' ')
		}
		writeLogfmtToken(b, f.Key)
		b.WriteByte('=')
		writeLogfmtToken(b, fieldValueToString(f.Value))
	}
}

// writeLogfmtToken writes s bare when it is unambiguous, and quoted otherwise. An empty value is
// written as `""` so that `k=` never appears, which would be indistinguishable from a truncated
// line.
func writeLogfmtToken(b *bytes.Buffer, s string) {
	if s == "" {
		b.WriteString(`""`)
		return
	}
	if !logfmtNeedsQuoting(s) {
		b.WriteString(s)
		return
	}

	b.WriteByte('"')
	for _, r := range s {
		switch r {
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
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func logfmtNeedsQuoting(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == '"' || c == '=' || c == '\\' || c == 0x7f {
			return true
		}
	}
	return false
}

// fieldValueToString renders a field value for the text format. It mirrors the type switch used by
// the JSON encoder so the same value never renders differently between the two formats, beyond
// JSON's own quoting rules.
func fieldValueToString(v any) string {
	switch value := v.(type) {
	case nil:
		return "<nil>"
	case string:
		return value
	case bool:
		return strconv.FormatBool(value)
	case int:
		return strconv.Itoa(value)
	case int8:
		return strconv.FormatInt(int64(value), 10)
	case int16:
		return strconv.FormatInt(int64(value), 10)
	case int32:
		return strconv.FormatInt(int64(value), 10)
	case int64:
		return strconv.FormatInt(value, 10)
	case uint:
		return strconv.FormatUint(uint64(value), 10)
	case uint8:
		return strconv.FormatUint(uint64(value), 10)
	case uint16:
		return strconv.FormatUint(uint64(value), 10)
	case uint32:
		return strconv.FormatUint(uint64(value), 10)
	case uint64:
		return strconv.FormatUint(value, 10)
	case float32:
		return strconv.FormatFloat(float64(value), 'g', -1, 32)
	case float64:
		return strconv.FormatFloat(value, 'g', -1, 64)
	case []byte:
		return string(value)
	case error:
		// Checked before Stringer: an error that also implements Stringer should still log its
		// Error() text.
		return value.Error()
	case ContextObjectLogValueGetter:
		return value.GetLogValue()
	case fmt.Stringer:
		return value.String()
	default:
		return fmt.Sprint(value)
	}
}

// fieldsToMessageSuffix renders fields for the noFieldLogger adapter, which has no access to a
// Record and must fold them into the message text instead.
func fieldsToMessageSuffix(fields []Field) string {
	rendered := renderFieldsAsText(fields)
	if rendered == "" {
		return ""
	}
	return " " + rendered
}
