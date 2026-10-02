package logging

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fieldsStringer struct{ value string }

func (s fieldsStringer) String() string { return s.value }

type fieldsLogValue struct{ value string }

func (o fieldsLogValue) GetLogValue() string { return o.value }

func TestArgsToFields_EvenPairs(t *testing.T) {
	got := argsToFields([]any{"user_id", 42, "tenant", "acme"})
	assert.Equal(t, []Field{{"user_id", 42}, {"tenant", "acme"}}, got)
}

func TestArgsToFields_NilAndEmpty_ReturnNil(t *testing.T) {
	assert.Nil(t, argsToFields(nil))
	assert.Nil(t, argsToFields([]any{}))
}

func TestArgsToFields_OddTrailingArg_BadKey(t *testing.T) {
	got := argsToFields([]any{"user_id", 42, "dangling"})
	assert.Equal(t, []Field{{"user_id", 42}, {BadKeyPlaceholder, "dangling"}}, got)
}

func TestArgsToFields_NonStringKey_BadKey(t *testing.T) {
	// The non-string is consumed on its own, so the following well-formed pair still parses.
	got := argsToFields([]any{7, "user_id", 42})
	assert.Equal(t, []Field{{BadKeyPlaceholder, 7}, {"user_id", 42}}, got)
}

func TestArgsToFields_NilValueIsPreserved(t *testing.T) {
	got := argsToFields([]any{"err", nil})
	assert.Equal(t, []Field{{"err", nil}}, got)
}

func TestArgsToFields_DuplicateKeys_Preserved(t *testing.T) {
	got := argsToFields([]any{"k", 1, "k", 2})
	assert.Equal(t, []Field{{"k", 1}, {"k", 2}}, got)
}

// TestConcatFields_NoBackingArrayAliasing is the most important test in this file. If concatFields
// ever reverts to append(parent, extra...), sibling child loggers silently corrupt each other's
// fields -- a bug that only shows up under specific capacity growth and is near-impossible to
// diagnose from a log line.
func TestConcatFields_NoBackingArrayAliasing(t *testing.T) {
	parent := argsToFields([]any{"a", 1})

	c1 := concatFields(parent, argsToFields([]any{"b", 2}))
	c2 := concatFields(parent, argsToFields([]any{"c", 3}))

	assert.Equal(t, []Field{{"a", 1}}, parent, "parent must not be modified")
	assert.Equal(t, []Field{{"a", 1}, {"b", 2}}, c1)
	assert.Equal(t, []Field{{"a", 1}, {"c", 3}}, c2)
}

func TestConcatFields_EmptyOperands(t *testing.T) {
	parent := []Field{{"a", 1}}
	assert.Equal(t, parent, concatFields(parent, nil))
	assert.Equal(t, parent, concatFields(nil, parent))
	assert.Nil(t, concatFields(nil, nil))
}

func TestRenderFieldsAsText_EmptyReturnsEmptyString(t *testing.T) {
	// Must be exactly "" so JoinStringsWithSpace drops the segment and the legacy line is
	// byte-identical.
	assert.Equal(t, "", renderFieldsAsText(nil))
	assert.Equal(t, "", renderFieldsAsText([]Field{}))
}

func TestRenderFieldsAsText_Table(t *testing.T) {
	tests := []struct {
		name   string
		fields []Field
		want   string
	}{
		{"simple pair", []Field{{"k", "v"}}, "k=v"},
		{"multiple pairs", []Field{{"a", 1}, {"b", true}}, "a=1 b=true"},
		{"value with space is quoted", []Field{{"note", "two words"}}, `note="two words"`},
		{"value with equals is quoted", []Field{{"q", "a=b"}}, `q="a=b"`},
		{"value with quote is escaped", []Field{{"q", `say "hi"`}}, `q="say \"hi\""`},
		{"value with backslash is escaped", []Field{{"p", `c:\tmp`}}, `p="c:\\tmp"`},
		{"newline is escaped", []Field{{"m", "a\nb"}}, `m="a\nb"`},
		{"tab is escaped", []Field{{"m", "a\tb"}}, `m="a\tb"`},
		{"control char is escaped", []Field{{"m", "a\x00b"}}, `m="a\u0000b"`},
		{"empty value renders as empty quotes", []Field{{"k", ""}}, `k=""`},
		{"key with space is quoted", []Field{{"my key", "v"}}, `"my key"=v`},
		{"nil value", []Field{{"k", nil}}, "k=<nil>"},
		{"float", []Field{{"amount", 19.99}}, "amount=19.99"},
		{"negative int", []Field{{"delta", -7}}, "delta=-7"},
		{"byte slice", []Field{{"raw", []byte("abc")}}, "raw=abc"},
		{"error value", []Field{{"err", errors.New("boom")}}, "err=boom"},
		{"stringer value", []Field{{"s", fieldsStringer{"str"}}}, "s=str"},
		{"log value getter", []Field{{"o", fieldsLogValue{"lv"}}}, "o=lv"},
		{"bad key", []Field{{BadKeyPlaceholder, "dangling"}}, "!BADKEY=dangling"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, renderFieldsAsText(tt.fields))
		})
	}
}

func TestFieldValueToString_IntegerWidths(t *testing.T) {
	assert.Equal(t, "1", fieldValueToString(int8(1)))
	assert.Equal(t, "2", fieldValueToString(int16(2)))
	assert.Equal(t, "3", fieldValueToString(int32(3)))
	assert.Equal(t, "4", fieldValueToString(int64(4)))
	assert.Equal(t, "5", fieldValueToString(uint(5)))
	assert.Equal(t, "6", fieldValueToString(uint8(6)))
	assert.Equal(t, "7", fieldValueToString(uint16(7)))
	assert.Equal(t, "8", fieldValueToString(uint32(8)))
	assert.Equal(t, "9", fieldValueToString(uint64(9)))
}

func TestFieldsToMessageSuffix(t *testing.T) {
	assert.Equal(t, "", fieldsToMessageSuffix(nil))
	assert.Equal(t, " k=v", fieldsToMessageSuffix([]Field{{"k", "v"}}))
}
