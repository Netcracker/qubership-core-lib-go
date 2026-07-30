package localdev

import (
	"strings"
)

func getKubeConfigStringField(m map[string]any, field string) string {
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

func getKubeConfigBoolField(m map[string]any, field string) (bool, bool) {
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

func firstNonBlank(first, second string) string {
	if strings.TrimSpace(first) != "" {
		return first
	}
	return second
}

func truncateResponseBody(body []byte) string {
	if len(body) <= maxErrorBodyLength {
		return string(body)
	}
	return string(body[:maxErrorBodyLength]) + "..."
}

// padBase64Url pads a Base64URL JWT segment so base64 decoding accepts it.
func padBase64Url(value string) string {
	mod := len(value) % jwtBase64PadLength
	if mod == 0 {
		return value
	}
	return value + strings.Repeat("=", jwtBase64PadLength-mod)
}
