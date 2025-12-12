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
	TimeFormat           = "2006-01-02T15:04:05.000"
	CallerPropertyName   = "caller"
	valuePlaceholder     = "-"
	RequestIdContextName = "X-Request-Id"   // see implementation in github.com/netcracker/qubership-core-lib-go/v3/context-propagation/xrequestid
	TenantContextName    = "Tenant-Context"
)

var (
	DefaultFormat = defaultFormat{}
)

type (
	messageFmt func(r *Record, b *bytes.Buffer, color int, lvl string) (int, error)
)

type defaultFormat struct {
	messageFormat   messageFmt
	customLogFields atomic.Value
}

type ContextObjectLogValueGetter interface {
	GetLogValue() string
}

func (format *defaultFormat) SetCustomLogFields(lineWithCustomFields string) {
	format.customLogFields.Store(lineWithCustomFields)
}

func (format *defaultFormat) SetMessageFormat(fn messageFmt) {
	format.messageFormat = fn
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
	return fmt.Fprintf(b, "[%s] [%s] [request_id=%s] [tenant_id=%s] [thread=-] [class=%s] %s",
		r.Time.Format(TimeFormat),
		lvl,
		GetValueOrPlaceholder(r.Ctx, RequestIdContextName),
		GetValueOrPlaceholder(r.Ctx, TenantContextName),
		ConstructCallerValueByRecord(r),
		JoinStringsWithSpace(AssembleDefaultCustomLogFields(r.Ctx), r.Message),
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
	regex, er := regexp.Compile("%\\{.[^}]+}")
	if er != nil {
		fmt.Printf("Cannot compile expression: %v", er)
		return ""
	}

	fields := regex.FindAllString(customLogFields, -1)
	if len(fields) == 0 {
		return ""
	}

	finalString := customLogFields
	for _, field := range fields {
		fieldName := strings.TrimRight(strings.TrimLeft(field, "%{"), "}")
		fieldValue := GetValueOrPlaceholder(ctx, fieldName)
		finalString = strings.ReplaceAll(finalString, field, fieldValue)
	}
	return finalString
}

func AssembleDefaultCustomLogFields(ctx context.Context) string {
	customFields, _ := DefaultFormat.customLogFields.Load().(string)
	return assembleCustomLogFields(customFields, ctx)
}

func JoinStringsWithSpace(elem ...string) string {
	elems := []string{}
	for _, s := range elem {
		if len(s) > 0 {
			elems = append(elems, s)
		}
	}
	return strings.Join(elems, " ")
}
