package memlimit

import (
	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

func init() {
	// uses default values:
	//   WithRatio(0.9)
	//   WithProvider(memlimit.FromCgroup)
	// and no logger
	memlimit, _ := memlimit.SetGoMemLimitWithOpts()

	logger := logging.GetLogger("memlimit")
	if memlimit > 0 {
		logger.Info("MEMORY LIMIT set to %d bytes (0.9 of cgroup's memory limit)", memlimit)
	} else {
		logger.Info("failed to set MEMORY LIMIT")
	}
}
