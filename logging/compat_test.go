package logging

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// These tests pin the exact bytes the text formatter produces. They were written and made to pass
// against the text-only implementation BEFORE the JSON format and the structured-field API were
// added, so any later diff in the text output shows up here as a failure rather than as a surprise
// in a downstream log pipeline.
//
// Deliberately assert.Equal on the whole line, not strings.Contains: a Contains assertion would
// happily pass if structured fields leaked into output that is supposed to be untouched.

var compatTime = time.Date(2026, 7, 30, 10, 15, 3, 123000000, time.UTC)

type compatLogValueObject struct{ value string }

func (o *compatLogValueObject) GetLogValue() string { return o.value }

type compatPlainObject struct{ value string }

func compatRecord(ctx context.Context) *Record {
	return &Record{
		PackageName: "orders",
		Time:        compatTime,
		Lvl:         LvlInfo,
		Message:     "order placed",
		Ctx:         ctx,
	}
}

func TestTextFormat_GoldenLine_NoFields(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	got := string(DefaultFormat.format(compatRecord(nil)))

	assert.Equal(t,
		"[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] order placed\n",
		got)
}

func TestTextFormat_ByteIdentity_Table(t *testing.T) {
	withCleanLoggingState(t)

	ctxWithLogValues := context.Background()
	ctxWithLogValues = context.WithValue(ctxWithLogValues, RequestIdContextName, &compatLogValueObject{"req-id"})
	ctxWithLogValues = context.WithValue(ctxWithLogValues, TenantContextName, &compatLogValueObject{"ten-id"})
	ctxWithLogValues = context.WithValue(ctxWithLogValues, ChannelRequestIdContextName, &compatLogValueObject{"chan-id"})

	ctxWithStrings := context.Background()
	ctxWithStrings = context.WithValue(ctxWithStrings, RequestIdContextName, "plain-req")
	ctxWithStrings = context.WithValue(ctxWithStrings, TenantContextName, "plain-ten")

	// A context value that is neither a string nor a ContextObjectLogValueGetter must render as
	// the "-" placeholder, not as its Go representation.
	ctxWithUnknownType := context.Background()
	ctxWithUnknownType = context.WithValue(ctxWithUnknownType, RequestIdContextName, &compatPlainObject{"req-id"})
	ctxWithUnknownType = context.WithValue(ctxWithUnknownType, TenantContextName, 42)

	ctxWithCaller := context.WithValue(context.Background(), CallerPropertyName, "CreateOrder")

	tests := []struct {
		name     string
		ctx      context.Context
		template string
		want     string
	}{
		{
			name: "nil ctx, no template",
			ctx:  nil,
			want: "[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] order placed\n",
		},
		{
			name: "empty ctx, no template",
			ctx:  context.Background(),
			want: "[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] order placed\n",
		},
		{
			name: "ctx with GetLogValue objects",
			ctx:  ctxWithLogValues,
			want: "[2026-07-30T10:15:03.123] [INFO] [request_id=req-id] [tenant_id=ten-id] [thread=-] [class=orders] [x_channel_request_id=chan-id] order placed\n",
		},
		{
			name: "ctx with plain string values",
			ctx:  ctxWithStrings,
			want: "[2026-07-30T10:15:03.123] [INFO] [request_id=plain-req] [tenant_id=plain-ten] [thread=-] [class=orders] [x_channel_request_id=-] order placed\n",
		},
		{
			name: "ctx with values of unsupported types falls back to placeholder",
			ctx:  ctxWithUnknownType,
			want: "[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] order placed\n",
		},
		{
			name: "caller in ctx is appended to class",
			ctx:  ctxWithCaller,
			want: "[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders.CreateOrder] [x_channel_request_id=-] order placed\n",
		},
		{
			name:     "custom template renders before the message",
			ctx:      ctxWithLogValues,
			template: "[custom_req=%{X-Request-Id}]",
			want:     "[2026-07-30T10:15:03.123] [INFO] [request_id=req-id] [tenant_id=ten-id] [thread=-] [class=orders] [x_channel_request_id=chan-id] [custom_req=req-id] order placed\n",
		},
		{
			name:     "custom template with a missing key renders the placeholder",
			ctx:      context.Background(),
			template: "[custom=%{nope}]",
			want:     "[2026-07-30T10:15:03.123] [INFO] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] [custom=-] order placed\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DefaultFormat.SetCustomLogFields(tt.template)
			assert.Equal(t, tt.want, string(DefaultFormat.format(compatRecord(tt.ctx))))
		})
	}
}

func TestTextFormat_GoldenLine_AllLevels(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	for lvl, want := range map[Lvl]string{
		LvlCrit:  "FATAL",
		LvlError: "ERROR",
		LvlWarn:  "WARN",
		LvlInfo:  "INFO",
		LvlDebug: "DEBUG",
	} {
		r := compatRecord(nil)
		r.Lvl = lvl
		assert.Equal(t,
			"[2026-07-30T10:15:03.123] ["+want+"] [request_id=-] [tenant_id=-] [thread=-] [class=orders] [x_channel_request_id=-] order placed\n",
			string(DefaultFormat.format(r)))
	}
}

// TestTextFormat_GoldenLine_CustomMessageFormatInstalled pins the contract that a caller-supplied
// message format owns the entire line: nothing the library adds later may appear in it.
func TestTextFormat_GoldenLine_CustomMessageFormatInstalled(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("[custom=%{X-Request-Id}]")
	DefaultFormat.SetMessageFormat(customLogMessage)

	got := string(DefaultFormat.format(compatRecord(nil)))

	assert.Equal(t, "[2026-07-30] \x1b[0m[INFO]\x1b[0m [packageName=testPackageName] order placed\n", got)
}

func TestRecord_ZeroValue_StillFormats(t *testing.T) {
	withCleanLoggingState(t)
	DefaultFormat.SetCustomLogFields("")

	assert.Equal(t,
		"[0001-01-01T00:00:00.000] [FATAL] [request_id=-] [tenant_id=-] [thread=-] [class=Default] [x_channel_request_id=-] \n",
		string(DefaultFormat.format(&Record{})))
}

// TestLoggerInterface_UnchangedMethodSet freezes the exported Logger interface. Adding a method to
// it is a source-breaking change for every downstream type that implements logging.Logger (mocks,
// test doubles, adapters), so new capability must go on FieldLogger instead. If this test fails,
// that is the reason -- do not "fix" it by updating the list.
func TestLoggerInterface_UnchangedMethodSet(t *testing.T) {
	want := []string{
		"Debug", "DebugC", "Debugf",
		"Error", "ErrorC", "Errorf",
		"GetLevel",
		"Info", "InfoC", "Infof",
		"Panic", "PanicC", "Panicf",
		"SetLevel", "SetLogFormat", "SetMessageFormat",
		"Warn", "WarnC", "Warnf",
	}

	loggerType := reflect.TypeOf((*Logger)(nil)).Elem()
	got := make([]string, 0, loggerType.NumMethod())
	for i := 0; i < loggerType.NumMethod(); i++ {
		got = append(got, loggerType.Method(i).Name)
	}
	sort.Strings(got)

	assert.Equal(t, want, got, "the Logger interface is frozen; add new methods to FieldLogger instead")
}
