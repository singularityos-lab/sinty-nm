package sys

import (
	"context"
	"encoding/binary"
	"syscall"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

const rfkillPath = "/dev/rfkill"

// rfkillPollInterval is how often Subscribe drains pending events. Radio block changes
// are rare and not latency-critical, so polling avoids the fd-close races of unblocking
// a goroutine parked in a blocking read.
const rfkillPollInterval = 250 * time.Millisecond

// rfkill switch types (uapi linux/rfkill.h).
const (
	rfkillTypeWLAN = 1
)

// rfkill operations (uapi linux/rfkill.h).
const (
	rfkillOpAdd       = 0
	rfkillOpDel       = 1
	rfkillOpChange    = 2
	rfkillOpChangeAll = 3
)

// rfkillEventSize is the classic (v1) struct rfkill_event wire size in bytes. The kernel
// still accepts and emits this layout; later fields are optional and ignored here.
const rfkillEventSize = 8

// rfkillEvent is the packed /dev/rfkill record: idx uint32, type/op/soft/hard uint8.
type rfkillEvent struct {
	idx  uint32
	typ  uint8
	op   uint8
	soft uint8
	hard uint8
}

func decodeEvent(b []byte) rfkillEvent {
	return rfkillEvent{
		idx:  binary.NativeEndian.Uint32(b[0:4]),
		typ:  b[4],
		op:   b[5],
		soft: b[6],
		hard: b[7],
	}
}

func (e rfkillEvent) encode() []byte {
	b := make([]byte, rfkillEventSize)
	binary.NativeEndian.PutUint32(b[0:4], e.idx)
	b[4] = e.typ
	b[5] = e.op
	b[6] = e.soft
	b[7] = e.hard
	return b
}

// rfkill toggles and reports the wifi radio block via /dev/rfkill.
type rfkill struct{}

// NewRFKill returns an RFKill, failing early if /dev/rfkill cannot be opened.
func NewRFKill() (core.RFKill, error) {
	fd, err := syscall.Open(rfkillPath, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	syscall.Close(fd)
	return &rfkill{}, nil
}

// WifiSoftBlocked reports whether any WLAN switch is software-blocked.
func (r *rfkill) WifiSoftBlocked() (bool, error) {
	soft, _, err := readWLANState()
	return soft, err
}

// WifiHardBlocked reports whether any WLAN switch is hardware-blocked (physical kill).
func (r *rfkill) WifiHardBlocked() (bool, error) {
	_, hard, err := readWLANState()
	return hard, err
}

// SetWifiBlocked sets or clears the software block on every WLAN switch.
func (r *rfkill) SetWifiBlocked(block bool) error {
	fd, err := syscall.Open(rfkillPath, syscall.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	ev := rfkillEvent{op: rfkillOpChangeAll, typ: rfkillTypeWLAN}
	if block {
		ev.soft = 1
	}
	b := ev.encode()
	for {
		if _, err := syscall.Write(fd, b); err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		return nil
	}
}

// Subscribe delivers the current WLAN block state, then delivers again on every change
// until ctx is done. It aggregates across all WLAN switches (blocked if any is blocked).
func (r *rfkill) Subscribe(ctx context.Context, fn func(soft, hard bool)) error {
	fd, err := syscall.Open(rfkillPath, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Opening the subscription fd queues an ADD burst for the current switches; drain it
	// before taking the snapshot so a change landing in between is not swallowed.
	consumeEvents(fd)
	lastSoft, lastHard, _ := readWLANState()
	fn(lastSoft, lastHard)

	ticker := time.NewTicker(rfkillPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !consumeEvents(fd) {
				continue
			}
			soft, hard, err := readWLANState()
			if err != nil {
				continue
			}
			if soft != lastSoft || hard != lastHard {
				lastSoft, lastHard = soft, hard
				fn(soft, hard)
			}
		}
	}
}

// consumeEvents drains all pending records on a non-blocking fd, reporting whether any
// WLAN event was seen (a hint that the aggregate state may have moved). DEL counts too:
// removing the last blocked switch changes the aggregate.
func consumeEvents(fd int) bool {
	buf := make([]byte, rfkillEventSize)
	seen := false
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			break // EAGAIN or a real error: nothing more to drain now
		}
		if n < rfkillEventSize {
			break
		}
		ev := decodeEvent(buf)
		if ev.typ == rfkillTypeWLAN {
			seen = true
		}
	}
	return seen
}

// readWLANState opens /dev/rfkill non-blocking, reads the ADD burst describing current
// switches, and returns the aggregate WLAN soft/hard block state.
func readWLANState() (soft, hard bool, err error) {
	fd, err := syscall.Open(rfkillPath, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false, false, err
	}
	defer syscall.Close(fd)
	buf := make([]byte, rfkillEventSize)
	for {
		n, rerr := syscall.Read(fd, buf)
		if rerr != nil {
			if rerr == syscall.EINTR {
				continue
			}
			break // EAGAIN: the initial burst is fully read
		}
		if n < rfkillEventSize {
			break
		}
		ev := decodeEvent(buf)
		if ev.typ != rfkillTypeWLAN || ev.op == rfkillOpDel {
			continue
		}
		if ev.soft != 0 {
			soft = true
		}
		if ev.hard != 0 {
			hard = true
		}
	}
	return soft, hard, nil
}
