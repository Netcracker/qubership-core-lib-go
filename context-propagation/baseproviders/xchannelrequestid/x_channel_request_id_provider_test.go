package xchannelrequestid

import (
	"context"
	"testing"
)

func TestXChannelRequestIdProvider_Provide(t *testing.T) {
	provider := XChannelRequestIdProvider{}
	baseCtx := context.Background()

	tests := []struct {
		name         string
		incomingData map[string]interface{}
		wantEmpty    bool
		wantValue    string
		wantCtxSame  bool
	}{
		{
			name: "key present with valid string value",
			incomingData: map[string]interface{}{
				X_CHANNEL_REQUEST_ID_CONTEXT_NAME: "test-request-id",
			},
			wantEmpty: false,
			wantValue: "test-request-id",
		},
		{
			name: "key present with empty string value",
			incomingData: map[string]interface{}{
				X_CHANNEL_REQUEST_ID_CONTEXT_NAME: "",
			},
			wantEmpty: false,
			wantValue: "",
		},
		{
			name:         "key not present",
			incomingData: map[string]interface{}{},
			wantCtxSame:  true,
		},
		{
			name: "key present with non-string value - int",
			incomingData: map[string]interface{}{
				X_CHANNEL_REQUEST_ID_CONTEXT_NAME: 123,
			},
			wantCtxSame: true,
		},
		{
			name: "key present with non-string value - bool",
			incomingData: map[string]interface{}{
				X_CHANNEL_REQUEST_ID_CONTEXT_NAME: true,
			},
			wantCtxSame: true,
		},
		{
			name: "key present with non-string value - nil",
			incomingData: map[string]interface{}{
				X_CHANNEL_REQUEST_ID_CONTEXT_NAME: nil,
			},
			wantCtxSame: true,
		},
		{
			name:         "nil incomingData map",
			incomingData: nil,
			wantCtxSame:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resultCtx := provider.Provide(baseCtx, tt.incomingData)

			if tt.wantCtxSame {
				if resultCtx != baseCtx {
					t.Errorf("expected original ctx to be returned, got a new one")
				}
				return
			}

			ctxObj, ok := resultCtx.Value(X_CHANNEL_REQUEST_ID_CONTEXT_NAME).(*XChannelRequestIdContextObject)
			if !ok || ctxObj == nil {
				t.Fatalf("expected *XChannelRequestIdContextObject in context, got %T", resultCtx.Value(X_CHANNEL_REQUEST_ID_CONTEXT_NAME))
			}
			if ctxObj.channelRequestId != tt.wantValue {
				t.Errorf("expected value=%q, got %q", tt.wantValue, ctxObj.channelRequestId)
			}
		})
	}
}
