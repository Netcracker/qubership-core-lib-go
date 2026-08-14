package internal

import (
	"strings"
)

func isFailed(statusCode int) bool {
	return statusCode/100 != 2
}

func getStringField(m map[string]any, field string) string {
	if m == nil {
		return ""
	}
	v, ok := m[field]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func getBoolField(m map[string]any, field string) (bool, bool) {
	if m == nil {
		return false, false
	}
	v, ok := m[field]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func truncateResponseBody(body []byte) string {
	if len(body) <= maxErrorBodyLength {
		return string(body)
	}
	return string(body[:maxErrorBodyLength]) + "..."
}
