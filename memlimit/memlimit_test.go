package memlimit

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

var (
	logger = logging.GetLogger("memlimit_test")
)

func TestInitializeMemlimit(t *testing.T) {
	t.Run("initializeMemlimit function execution", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("automemlimit will not work on Windows - as cgroup is not available")
		}

		checkAgainstCgroup(t)
	})

}

func checkAgainstCgroup(t *testing.T) {
	data, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		t.Fatalf("failed to read cgroup memory.max: %v", err)
	}

	if strings.TrimSpace(string(data)) == "max" {
		t.Fatalf("expected cgroup memory.max to be limited, got max")
	}

	cgroupLimit, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	goLimit := debug.SetMemoryLimit(-1)

	expected := float64(cgroupLimit) * 90 / 100
	roundedExpected := int64(math.Round(expected))
	if goLimit != roundedExpected {
		t.Fatalf("expected GOMEMLIMIT to equal rounded 0.9 of cgroup limit, got %d vs expected %d",
			goLimit,
			roundedExpected,
		)
	}

	//>> 20 is a right‑shift by 20 bits, which is the same as integer division by 2^20 (1,048,576). It converts bytes to MiB
	logger.Info("cgroup limit=%d Mi, go memlimit=%d Mi, ratio 0.9. automemlimit did its job", cgroupLimit>>20, goLimit>>20)
}
