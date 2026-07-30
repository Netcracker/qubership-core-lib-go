package logging

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

const (
	TimeFormat                  = "2006-01-02T15:04:05.000"
	CallerPropertyName          = "caller"
	valuePlaceholder            = "-"
	RequestIdContextName        = "X-Request-Id"         // see implementation in github.com/netcracker/qubership-core-lib-go/v3/context-propagation/xrequestid
	ChannelRequestIdContextName = "X-Channel-Request-Id" // see implementation in github.com/netcracker/qubership-core-lib-go/v3/context-propagation/xchannelrequestid
	TenantContextName           = "Tenant-Context"
)

var (
	DefaultFormat = defaultFormat{}

	// customFieldsPattern matches one %{name} placeholder. Compiled once at package init: it used
	// to be compiled inside assembleCustomLogFields, i.e. on every single log record, which
	// accounted for roughly 30 of the ~33 allocations of a log line even when no template was
	// configured at all.
	customFieldsPattern = regexp.MustCompile(`%\{.[^}]+}`)

	// globalCustomFields holds the parsed template installed via DefaultFormat.SetCustomLogFields.
	// It is package-global rather than per-instance because the formatter has always resolved
	// custom fields from DefaultFormat regardless of which defaultFormat instance was rendering;
	// keeping it global preserves that behaviour for per-logger message formats.
	globalCustomFields atomic.Pointer[customFieldsSpec]
)

type (
	messageFmt func(r *Record, b *bytes.Buffer, color int, lvl string) (int, error)
)

// customFieldsSpec is a %{...} template parsed ahead of time. raw drives text rendering, which
// substitutes values back into the template; names drives JSON rendering, which emits each field
// as a top-level key. Parsing once at Set time keeps both paths off the regexp on the hot path.
type customFieldsSpec struct {
	raw   string
	names []string
}

type defaultFormat struct {
	messageFormat messageFmt
}

type ContextObjectLogValueGetter interface {
	GetLogValue() string
}

// SetCustomLogFields installs a template of %{context-key} placeholders that is rendered with
// every log record.
//
// In text format the template is substituted and prefixed to the message, e.g.
//
//	SetCustomLogFields("[bp=%{business_process_id}]")
//	    -> "... [x_channel_request_id=-] [bp=bp-1] the message"
//
// In JSON format the placeholder names become top-level keys instead, e.g.
//
//	{"time":..., "message":"the message", ..., "business_process_id":"bp-1"}
//
// Values are resolved from the record's context.Context by key, exactly as the built-in fields are;
// a key that is absent renders as the "-" placeholder.
//
// The template is stored globally, not on the receiver. It always was in effect -- the formatter
// read it from DefaultFormat no matter which defaultFormat instance was rendering -- so a
// per-logger message format installed via SetMessageFormat still sees the configured custom
// fields.
func (format *defaultFormat) SetCustomLogFields(lineWithCustomFields string) {
	globalCustomFields.Store(parseCustomFieldsSpec(lineWithCustomFields))
}

func (format *defaultFormat) SetMessageFormat(fn messageFmt) {
	format.messageFormat = fn
}

func parseCustomFieldsSpec(template string) *customFieldsSpec {
	spec := &customFieldsSpec{raw: template}
	if template == "" {
		return spec
	}
	for _, placeholder := range customFieldsPattern.FindAllString(template, -1) {
		spec.names = append(spec.names, customFieldName(placeholder))
	}
	return spec
}

// customFieldName extracts "foo" from "%{foo}".
//
// This used to be strings.TrimRight(strings.TrimLeft(placeholder, "%{"), "}"), which treats its
// argument as a cutset rather than a prefix: a field named "%weird" or "{weird" had its leading
// characters eaten. TrimPrefix/TrimSuffix strip exactly the delimiters.
func customFieldName(placeholder string) string {
	return strings.TrimSuffix(strings.TrimPrefix(placeholder, "%{"), "}")
}

// customFieldNames returns the placeholder names of the installed template, for formatters that
// emit them as discrete keys.
func customFieldNames() []string {
	if spec := globalCustomFields.Load(); spec != nil {
		return spec.names
	}
	return nil
}

func (format *defaultFormat) format(r *Record) []byte {
	b := &bytes.Buffer{}
	lvl := strings.ToUpper(r.Lvl.String())
	color := 0
	format.logFormat(r, b, color, lvl)

	b.WriteByte('\n')
	return b.Bytes()
}

func (format *defaultFormat) logFormat(r *Record, b *bytes.Buffer, color int, lvl string) (int, error) {
	if format.messageFormat != nil {
		return format.messageFormat(r, b, color, lvl)
	}
	return fmt.Fprintf(b, "[%s] [%s] [request_id=%s] [tenant_id=%s] [thread=-] [class=%s] [x_channel_request_id=%s] %s",
		r.Time.Format(TimeFormat),
		lvl,
		GetValueOrPlaceholder(r.Ctx, RequestIdContextName),
		GetValueOrPlaceholder(r.Ctx, TenantContextName),
		ConstructCallerValueByRecord(r),
		GetValueOrPlaceholder(r.Ctx, ChannelRequestIdContextName),
		// JoinStringsWithSpace drops empty segments, so a record with no custom template and no
		// structured fields produces exactly the bytes this formatter produced before either
		// feature existed.
		JoinStringsWithSpace(AssembleDefaultCustomLogFields(r.Ctx), r.Message, renderFieldsAsText(r.Fields)),
	)
}

func GetValueOrPlaceholder(ctx context.Context, key string) string {
	if ctx != nil {
		value := ctx.Value(key)
		if value != nil {
			switch va := value.(type) {
			case string:
				return va
			case ContextObjectLogValueGetter:
				return va.GetLogValue()
			default:
				return valuePlaceholder
			}
		}
	}
	return valuePlaceholder
}

func constructCallerValue(ctx context.Context, loggerName string) string {
	result := "Default"
	if len(loggerName) > 0 {
		result = loggerName
	}

	if callerVal := GetValueOrPlaceholder(ctx, CallerPropertyName); callerVal != valuePlaceholder {
		result += "." + callerVal
	}

	return result
}

func ConstructCallerValueByRecord(r *Record) string {
	return constructCallerValue(r.Ctx, r.PackageName)
}

func assembleCustomLogFields(customLogFields string, ctx context.Context) string {
	fields := customFieldsPattern.FindAllString(customLogFields, -1)
	if len(fields) == 0 {
		return ""
	}

	finalString := customLogFields
	for _, field := range fields {
		fieldValue := GetValueOrPlaceholder(ctx, customFieldName(field))
		finalString = strings.ReplaceAll(finalString, field, fieldValue)
	}
	return finalString
}

func AssembleDefaultCustomLogFields(ctx context.Context) string {
	spec := globalCustomFields.Load()
	if spec == nil || spec.raw == "" {
		return ""
	}
	return assembleCustomLogFields(spec.raw, ctx)
}

func JoinStringsWithSpace(elem ...string) string {
	var elems []string
	for _, s := range elem {
		if len(s) > 0 {
			elems = append(elems, s)
		}
	}
	return strings.Join(elems, " ")
}
