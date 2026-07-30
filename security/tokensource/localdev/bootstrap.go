package localdev

import (
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
)

var bootstrapLogger = logging.GetLogger("local-dev-bootstrap")

const localDevTokenSourcePriority = 20

// Bootstrap registers LocalDevTokenSource when PROFILE=dev.
// Call after configloader.Init, before the first tokensource.GetAudienceToken call.
func Bootstrap() {
	if !IsEnabled() {
		return
	}
	bootstrapLogger.Info("local-dev enabled: registering LocalDevTokenSource (kubeconfig TokenRequest)")
	serviceloader.Register(localDevTokenSourcePriority, NewLocalDevTokenSource())
}
