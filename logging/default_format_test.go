package logging

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	caller       = "caller"
	caller_value = "someCaller"
	logger_name  = "loggerName"
)

func TestSetMessageFormat_CustomFormat(t *testing.T) {
	message := "New test message logFormat"
	testLogMessageFormat := func(r *Record, b *bytes.Buffer, color int, lvl string) (int, error) {
		return fmt.Fprintf(b, "%s", message)
	}
	DefaultFormat.SetMessageFormat(testLogMessageFormat)
	formatBuffer := DefaultFormat.format(&Record{})
	assert.True(t, strings.Contains(string(formatBuffer), message))
	// have to clear message logFormat or other test won't pass
	DefaultFormat.messageFormat = nil
}

func TestDefaultFormat(t *testing.T) {
	message := "test message"
	packageName := "test"
	timeValue := time.Time{}
	lvl := LvlCrit
	formatBuffer := DefaultFormat.format(&Record{
		PackageName: packageName,
		Time:        timeValue,
		Lvl:         lvl,
		Message:     message,
		Ctx:         nil,
	})
	expectedValue := "[0001-01-01T00:00:00.000] [FATAL] [request_id=-] [x_channel_request_id=-] [tenant_id=-] [thread=-] [class=test] test message"
	assert.True(t, strings.Contains(string(formatBuffer), expectedValue))

	ctx := context.Background()
	ctx = context.WithValue(ctx, RequestIdContextName, &testObjectWithLogValueMethod{"req-id"})
	ctx = context.WithValue(ctx, TenantContextName, &testObjectWithLogValueMethod{"ten-id"})
	ctx = context.WithValue(ctx, ChannelRequestIdContextName, &testObjectWithLogValueMethod{"chan-req-id"})
	formatBuffer = DefaultFormat.format(&Record{
		PackageName: packageName,
		Time:        timeValue,
		Lvl:         lvl,
		Message:     message,
		Ctx:         ctx,
	})
	assert.True(t, strings.Contains(string(formatBuffer), "[request_id=req-id] [x_channel_request_id=chan-req-id] [tenant_id=ten-id]"))

	ctx = context.Background()
	ctx = context.WithValue(ctx, RequestIdContextName, &testObjectWithoutLogValueMethod{"req-id"})
	ctx = context.WithValue(ctx, TenantContextName, &testObjectWithoutLogValueMethod{"ten-id"})
	formatBuffer = DefaultFormat.format(&Record{
		PackageName: packageName,
		Time:        timeValue,
		Lvl:         lvl,
		Message:     message,
		Ctx:         ctx,
	})
	assert.True(t, strings.Contains(string(formatBuffer), "[request_id=-] [x_channel_request_id=-] [tenant_id=-]"))
}

func TestContextObject(t *testing.T) {
	ctx := context.Background()
	ctxWithSimpleTextVale := context.WithValue(ctx, "simple_text_property", "text_value")

	ctxWithObjectAndText := context.WithValue(ctxWithSimpleTextVale, "object", &testObjectWithLogValueMethod{"object_value"})
	result := assembleCustomLogFields("[simple_text_property=%{simple_text_property}] [object=%{object}]", ctxWithObjectAndText)
	assert.Equal(t, "[simple_text_property=text_value] [object=object_value]", result)
}

type testObjectWithoutLogValueMethod struct {
	testObjectValue string
}

type testObjectWithLogValueMethod struct {
	testObjectValue string
}

func (object *testObjectWithLogValueMethod) GetLogValue() string {
	return object.testObjectValue
}

func TestGetLoggerCaller(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, caller, caller_value)
	r := Record{PackageName: logger_name, Ctx: ctx}
	assert.Equal(t, logger_name+"."+caller_value, ConstructCallerValueByRecord(&r))
}

func TestGetDefaultLoggerCaller(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, caller, caller_value)
	r := Record{PackageName: "", Ctx: ctx}
	assert.Equal(t, "Default."+caller_value, ConstructCallerValueByRecord(&r))
}

func TestGetDefaultLoggerWithoutCaller(t *testing.T) {
	r := Record{PackageName: "", Ctx: context.Background()}
	assert.Equal(t, "Default", ConstructCallerValueByRecord(&r))
}
