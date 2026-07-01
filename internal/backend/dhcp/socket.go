package dhcp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"
)

// Wire constants for the L3/L4 framing we build by hand on the raw socket.
const (
	ethPIP     = 0x0800 // ETH_P_IP
	ipHdrLen   = 20
	udpHdrLen  = 8
	clientPort = 68
	serverPort = 67
)

// broadcastMAC is the L2 destination for DISCOVER/REQUEST; the kernel fills the source.
var broadcastMAC = [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// rawSock is an AF_PACKET (SOCK_DGRAM) socket bound to one interface. SOCK_DGRAM means the
// kernel adds/strips the ethernet header, so we send and receive bare IPv4 packets.
type rawSock struct {
	fd    int
	index int
}

// openRawSock opens a broadcast-capable packet socket bound to the given interface index.
func openRawSock(ifindex int) (*rawSock, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(ethPIP)))
	if err != nil {
		return nil, err
	}
	lsa := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  ifindex,
	}
	if err := syscall.Bind(fd, lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &rawSock{fd: fd, index: ifindex}, nil
}

func (s *rawSock) close() { syscall.Close(s.fd) }

// send wraps a DHCP payload in UDP+IP and transmits it as an L2 broadcast frame.
func (s *rawSock) send(dhcp []byte) error {
	frame := encodeIPUDP(net.IPv4zero, net.IPv4bcast, clientPort, serverPort, dhcp)
	dst := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  s.index,
		Halen:    6,
		Addr:     broadcastMAC,
	}
	return syscall.Sendto(s.fd, frame, 0, dst)
}

// recvReply reads IPv4/UDP DHCP packets until one matches xid and the wanted message type,
// or the deadline passes. It ignores unrelated traffic and yields to ctx cancellation.
func (s *rawSock) recvReply(ctx context.Context, xid uint32, want byte, budget time.Duration) (*reply, error) {
	deadline := time.Now().Add(budget)
	buf := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("timeout waiting for reply")
		}
		// Cap the blocking recv so ctx and the deadline are checked periodically.
		slice := remaining
		if slice > 500*time.Millisecond {
			slice = 500 * time.Millisecond
		}
		if err := s.setReadTimeout(slice); err != nil {
			return nil, err
		}
		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		payload := decodeIPUDP(buf[:n])
		if payload == nil {
			continue
		}
		r, err := parseReply(payload)
		if err != nil {
			continue
		}
		if r.xid != xid || r.msgType() != want {
			continue
		}
		return r, nil
	}
}

// setReadTimeout arms SO_RCVTIMEO so Recvfrom returns EAGAIN after d.
func (s *rawSock) setReadTimeout(d time.Duration) error {
	tv := syscall.NsecToTimeval(int64(d))
	return syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

// htons converts a uint16 to network byte order, required for AF_PACKET protocol fields.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// encodeIPUDP builds an IPv4 packet carrying a UDP datagram with the DHCP payload.
func encodeIPUDP(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	src4, dst4 := src.To4(), dst.To4()
	udpLen := udpHdrLen + len(payload)
	total := ipHdrLen + udpLen
	pkt := make([]byte, total)

	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = syscall.IPPROTO_UDP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:ipHdrLen]))

	udp := pkt[ipHdrLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[udpHdrLen:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksum(src4, dst4, udp))
	return pkt
}

// decodeIPUDP validates an inbound IPv4/UDP packet destined for the DHCP client port and
// returns the UDP payload, or nil if it is not a DHCP reply we care about.
func decodeIPUDP(pkt []byte) []byte {
	if len(pkt) < ipHdrLen {
		return nil
	}
	if pkt[0]>>4 != 4 {
		return nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipHdrLen || len(pkt) < ihl+udpHdrLen {
		return nil
	}
	if pkt[9] != syscall.IPPROTO_UDP {
		return nil
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total > len(pkt) || total < ihl+udpHdrLen {
		return nil
	}
	udp := pkt[ihl:total]
	if binary.BigEndian.Uint16(udp[2:4]) != clientPort {
		return nil
	}
	if binary.BigEndian.Uint16(udp[0:2]) != serverPort {
		return nil
	}
	ulen := int(binary.BigEndian.Uint16(udp[4:6]))
	if ulen < udpHdrLen || ulen > len(udp) {
		return nil
	}
	return udp[udpHdrLen:ulen]
}

// checksum is the standard 16-bit ones-complement sum used for IP and UDP headers.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum over the IPv4 pseudo-header plus the datagram.
func udpChecksum(src, dst, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = syscall.IPPROTO_UDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	c := checksum(pseudo)
	if c == 0 {
		return 0xffff // 0 means "no checksum"; send all-ones instead
	}
	return c
}

// sendRelease unicasts a DHCPRELEASE to the granting server via an ordinary UDP socket,
// letting the kernel route and resolve L2 now that the interface has its address.
func sendRelease(st leaseState) error {
	xid, err := newXID()
	if err != nil {
		return err
	}
	msg := buildMsg(msgRelease, xid, st.mac, st.clientIP, st.serverID)
	laddr := &net.UDPAddr{IP: st.clientIP, Port: clientPort}
	raddr := &net.UDPAddr{IP: st.serverID, Port: serverPort}
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(msg)
	return err
}
