//go:build !linux

package prober

import "time"

// pingFromNetns is a stub on non-Linux platforms; the netns + raw ICMP
// path is Linux-only. The exporter logs at debug level when it falls
// through so unit tests on macOS/Windows still execute the surrounding
// scheduling logic.
func pingFromNetns(pid int, targets []string, timeout time.Duration, baseSeq uint16) (map[string]time.Duration, error) {
	return nil, nil
}
