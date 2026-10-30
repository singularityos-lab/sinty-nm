package dhcp

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

// BPF requests with the sizes of the kernel that runs Linux binaries without AF_PACKET.
const (
	bpfGetBufLen      = 2<<30 | 4<<16 | 'B'<<8 | 102
	bpfSetInterface   = 1<<30 | 32<<16 | 'B'<<8 | 108
	bpfSetReadTimeout = 1<<30 | 16<<16 | 'B'<<8 | 109
	bpfImmediate      = 1<<30 | 4<<16 | 'B'<<8 | 112
)

// bpfHeaderCapLen and friends locate the fields of struct bpf_hdr, and bpfAlign is the
// boundary packets are padded to inside one read.
const (
	bpfHeaderCapLen = 16
	bpfHeaderLen    = 24
	bpfAlign        = 8
	ethHeaderLen    = 14
)

// bpfState holds what the raw packet socket otherwise does for us: the ethernet header on
// send, and splitting one read into packets on receive.
type bpfState struct {
	mac     net.HardwareAddr
	buf     []byte
	pending []byte
}

func bpfIoctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// openBPFSock is the fallback where the kernel has no AF_PACKET.
func openBPFSock(ifindex int) (*rawSock, error) {
	iface, err := net.InterfaceByIndex(ifindex)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open("/dev/bpf", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var ifr [32]byte
	copy(ifr[:15], iface.Name)
	var on, blen uint32 = 1, 0
	for _, step := range []struct {
		req uintptr
		arg unsafe.Pointer
	}{
		{bpfSetInterface, unsafe.Pointer(&ifr)},
		{bpfImmediate, unsafe.Pointer(&on)},
		{bpfGetBufLen, unsafe.Pointer(&blen)},
	} {
		if err := bpfIoctl(fd, step.req, step.arg); err != nil {
			syscall.Close(fd)
			return nil, err
		}
	}
	return &rawSock{fd: fd, index: ifindex, bpf: &bpfState{mac: iface.HardwareAddr, buf: make([]byte, blen)}}, nil
}

func (b *bpfState) send(fd int, packet []byte) error {
	frame := make([]byte, ethHeaderLen+len(packet))
	copy(frame, broadcastMAC[:6])
	copy(frame[6:], b.mac)
	binary.BigEndian.PutUint16(frame[12:], ethPIP)
	copy(frame[ethHeaderLen:], packet)
	_, err := syscall.Write(fd, frame)
	return err
}

// next returns the next IPv4 packet, or nil with no error when the read timed out empty.
func (b *bpfState) next(fd int) ([]byte, error) {
	for {
		if len(b.pending) == 0 {
			n, err := syscall.Read(fd, b.buf)
			if err != nil {
				return nil, err
			}
			if n <= 0 {
				return nil, nil
			}
			b.pending = b.buf[:n]
		}
		frame, rest := splitBPF(b.pending)
		b.pending = rest
		if len(frame) >= ethHeaderLen && binary.BigEndian.Uint16(frame[12:]) == ethPIP {
			return frame[ethHeaderLen:], nil
		}
	}
}

// splitBPF takes the first captured frame off a BPF read and returns the remainder.
func splitBPF(data []byte) (frame, rest []byte) {
	if len(data) < bpfHeaderLen {
		return nil, nil
	}
	caplen := int(binary.LittleEndian.Uint32(data[bpfHeaderCapLen:]))
	hdrlen := int(binary.LittleEndian.Uint16(data[bpfHeaderCapLen+8:]))
	end := hdrlen + caplen
	if hdrlen < bpfHeaderLen || end > len(data) {
		return nil, nil
	}
	frame = data[hdrlen:end]
	next := (end + bpfAlign - 1) &^ (bpfAlign - 1)
	if next >= len(data) {
		return frame, nil
	}
	return frame, data[next:]
}
