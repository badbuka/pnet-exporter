//go:build linux

package prober

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// pingFromNetns enters the network namespace owning pid on a locked OS
// thread, opens an ICMP socket with a receive timeout and sends one
// echo request per target, collecting RTTs.
func pingFromNetns(pid int, targets []string, timeout time.Duration, baseSeq uint16) (map[string]time.Duration, error) {
	if pid <= 0 || len(targets) == 0 {
		return nil, nil
	}

	runtime.LockOSThread()
	// unlocked tracks ownership of the thread lock: if the netns restore
	// below fails, the thread is poisoned (still inside the container
	// netns) and must NOT be returned to the runtime pool, so the unlock
	// is skipped and the goroutine exits while locked, which makes the
	// runtime destroy the thread.
	unlocked := false
	defer func() {
		if !unlocked {
			runtime.UnlockOSThread()
		}
	}()

	currentNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	defer func() { _ = currentNS.Close() }()

	targetNS, err := os.Open("/proc/" + strconv.Itoa(pid) + "/ns/net")
	if err != nil {
		return nil, err
	}
	defer func() { _ = targetNS.Close() }()

	if err := setns(int(targetNS.Fd())); err != nil {
		return nil, err
	}
	defer func() {
		if err := setns(int(currentNS.Fd())); err != nil {
			// Restore failed: keep the lock and kill this goroutine so the
			// poisoned thread is destroyed instead of leaking back into
			// the pool running in the container's netns.
			unlocked = true
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		unlocked = true
	}()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()

	if timeout <= 0 {
		timeout = time.Second
	}
	tv := unix.Timeval{Sec: int64(timeout / time.Second), Usec: int64((timeout % time.Second) / time.Microsecond)}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}

	results := make(map[string]time.Duration, len(targets))
	for i, target := range targets {
		ip := net.ParseIP(target).To4()
		if ip == nil {
			continue
		}
		seq := baseSeq + uint16(i)
		addr := unix.SockaddrInet4{Port: 0}
		copy(addr.Addr[:], ip)
		packet := makeICMPEcho(seq, seq)
		sentAt := time.Now()
		if err := unix.Sendto(fd, packet, 0, &addr); err != nil {
			continue
		}
		buf := make([]byte, 1500)
		// Hard deadline: SO_RCVTIMEO only bounds a single Recvfrom, so a
		// target streaming wrong-seq replies would otherwise stall the
		// single-threaded prober past its timeout.
		deadline := sentAt.Add(timeout)
		for {
			if time.Now().After(deadline) {
				break
			}
			n, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				break
			}
			if n < 8 {
				continue
			}
			if buf[0] != 0 {
				continue
			}
			// Only accept replies that come from the current target:
			// anything else (including a spoofed echo-reply from another
			// host) must not fabricate a latency sample.
			src, ok := from.(*unix.SockaddrInet4)
			if !ok || src.Addr != addr.Addr {
				continue
			}
			rseq := binary.BigEndian.Uint16(buf[6:8])
			if rseq != seq {
				continue
			}
			results[target] = time.Since(sentAt)
			break
		}
	}
	return results, nil
}

func setns(fd int) error {
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return errors.New("setns not supported on this kernel")
		}
		return err
	}
	return nil
}

func makeICMPEcho(id, seq uint16) []byte {
	pkt := make([]byte, 8)
	pkt[0] = 8
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	return pkt
}
