package cmd

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/golang/glog"
)

const (
	// memLimitRatio leaves 40% of the container limit to the kubectl and jq
	// audit subprocesses, which hold full pod lists in the same cgroup. The old
	// helm default GOMEMLIMIT=500MiB under a 512Mi limit left them ~12Mi.
	memLimitRatio = 0.6

	cgroupV2MemoryPath = "/sys/fs/cgroup/memory.max"
	cgroupV1MemoryPath = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	// cgroup v1 reports "no limit" as a huge page-aligned number near 2^63.
	cgroupV1Unlimited = int64(1) << 60
)

// setMemoryLimit applies memLimitRatio × the cgroup memory limit as the Go soft
// memory limit, reading the cgroup so it tracks the container's real limit. An
// explicit GOMEMLIMIT env wins; no cgroup limit is a no-op.
func setMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	limit, ok := cgroupMemoryLimit(cgroupV2MemoryPath, cgroupV1MemoryPath)
	if !ok {
		return
	}
	soft := int64(float64(limit) * memLimitRatio)
	debug.SetMemoryLimit(soft)
	glog.V(1).Infof("set Go memory limit to %d bytes (cgroup limit %d)", soft, limit)
}

// cgroupMemoryLimit returns the first readable cgroup memory limit in paths,
// or false when none is readable or the limit is unbounded.
func cgroupMemoryLimit(paths ...string) (int64, bool) {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		// "max" (v2) fails to parse; v1's unlimited sentinel is a huge number.
		if err != nil || n <= 0 || n >= cgroupV1Unlimited {
			return 0, false
		}
		return n, true
	}
	return 0, false
}
