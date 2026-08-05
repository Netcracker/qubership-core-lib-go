package localdev

import "net/http"

func isUnauthorizedOrForbidden(statusCode int) bool {
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}

func isFailed(statusCode int) bool {
	return statusCode/100 != 2
}
