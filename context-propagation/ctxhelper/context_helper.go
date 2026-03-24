package ctxhelper

import (
	"context"

	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var logger logging.Logger

func init() {
	logger = logging.GetLogger("accept-language")
}

func AddSerializableContextData(ctx context.Context, f func(string, string)) error {
	logger.Debug("start serialize context data")
	contextData, err := ctxmanager.GetSerializableContextData(ctx)
	if err != nil {
		return err
	}
	addContextData(contextData, f)
	return nil
}

func AddResponsePropagatableContextData(ctx context.Context, f func(string, string)) error {
	logger.Debug("start collect and insert response propagatable context data")
	contextData, err := ctxmanager.GetResponsePropagatableContextData(ctx)
	if err != nil {
		return err
	}
	addContextData(contextData, f)
	return nil
}

func addContextData(contextData map[string]string, f func(string, string)) {
	for headerName, headerVals := range contextData {
		logger.Debug("add context=%s with value=%s", headerName, headerVals)
		f(headerName, headerVals)
	}
}
