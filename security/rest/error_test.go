package rest

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenAcquisitionError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "with wrapped error",
			err:      errors.New("connection timeout"),
			expected: "failed to acquire m2m token: connection timeout",
		},
		{
			name:     "with nil error",
			err:      nil,
			expected: "failed to acquire m2m token: <nil>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tae := &TokenAcquisitionError{Err: tt.err}
			assert.Equal(t, tt.expected, tae.Error())
		})
	}
}

func TestFallbackReason_Message(t *testing.T) {
	tests := []struct {
		name     string
		reason   *fallbackReason
		expected string
	}{
		{
			name: "with error",
			reason: &fallbackReason{
				desc: kubernetesTokenAcquisitionError,
				url:  "https://example.com/api",
				err:  errors.New("token not found"),
			},
			expected: "failed to establish m2m connection to https://example.com/api\n" +
				kubernetesTokenAcquisitionError + "\ntoken not found",
		},
		{
			name: "without error",
			reason: &fallbackReason{
				desc: kubernetesTokenUnauthorizedError,
				url:  "https://example.com/api/v1/resource",
				err:  nil,
			},
			expected: "failed to establish m2m connection to https://example.com/api/v1/resource\n" +
				kubernetesTokenUnauthorizedError,
		},
		{
			name: "custom description",
			reason: &fallbackReason{
				desc: "custom error description",
				url:  "https://api.service.com",
				err:  errors.New("custom error"),
			},
			expected: "failed to establish m2m connection to https://api.service.com\n" +
				"custom error description\ncustom error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.reason.Message())
		})
	}
}
