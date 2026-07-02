package wg

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// This file is the minimal rtnetlink needed to own a wireguard link's L2: create it with
// IFLA_INFO_KIND=wireguard, bring it up, and delete it. All crypto/peer state goes
// through wgctrl; nothing here touches addresses or routes.

const (
	nlHdrLen  = unix.NLMSG_HDRLEN // 16
	ifiMsgLen = 16                // sizeof(struct ifinfomsg)
)

// createLink issues RTM_NEWLINK creating a wireguard device named ifname.
func createLink(ifname string) error {
	attrs := append(
		strAttr(unix.IFLA_IFNAME, ifname),
		linkInfoWireGuard()...,
	)
	if err := rtnl(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ifinfomsg{}, attrs); err != nil {
		return fmt.Errorf("wg: create link %q: %w", ifname, err)
	}
	return nil
}

// setUp issues RTM_NEWLINK setting IFF_UP on an existing link.
func setUp(ifname string) error {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("wg: lookup %q: %w", ifname, err)
	}
	ifi := ifinfomsg{Index: int32(iface.Index), Flags: unix.IFF_UP, Change: unix.IFF_UP}
	if err := rtnl(unix.RTM_NEWLINK, 0, ifi, nil); err != nil {
		return fmt.Errorf("wg: set up %q: %w", ifname, err)
	}
	return nil
}

// delLink issues RTM_DELLINK removing the named link.
func delLink(ifname string) error {
	if err := rtnl(unix.RTM_DELLINK, 0, ifinfomsg{}, strAttr(unix.IFLA_IFNAME, ifname)); err != nil {
		return fmt.Errorf("wg: delete link %q: %w", ifname, err)
	}
	return nil
}

// ifinfomsg is the rtnetlink link message header.
type ifinfomsg struct {
	Index  int32
	Flags  uint32
	Change uint32
}

func (m ifinfomsg) marshal() []byte {
	b := make([]byte, ifiMsgLen)
	// b[0] family, b[1] pad, b[2:4] type: all zero for our operations.
	binary.NativeEndian.PutUint32(b[4:], uint32(m.Index))
	binary.NativeEndian.PutUint32(b[8:], m.Flags)
	binary.NativeEndian.PutUint32(b[12:], m.Change)
	return b
}

// strAttr builds a NUL-terminated string rtattr, padded to a 4-byte boundary.
func strAttr(typ uint16, s string) []byte {
	data := append([]byte(s), 0)
	return attr(typ, data)
}

// linkInfoWireGuard builds the nested IFLA_LINKINFO/IFLA_INFO_KIND=wireguard attribute.
func linkInfoWireGuard() []byte {
	kind := strAttr(unix.IFLA_INFO_KIND, "wireguard")
	return attr(unix.IFLA_LINKINFO, kind)
}

// attr serializes one rtattr (header + data) padded to a 4-byte boundary.
func attr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, align4(l))
	binary.NativeEndian.PutUint16(b[0:], uint16(l))
	binary.NativeEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func align4(n int) int { return (n + 3) &^ 3 }

// rtnl sends one request-with-ack to the routing netlink family and returns the kernel's
// reply status.
func rtnl(msgType, extraFlags uint16, ifi ifinfomsg, attrs []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	body := append(ifi.marshal(), attrs...)
	total := nlHdrLen + len(body)
	msg := make([]byte, align4(total))
	binary.NativeEndian.PutUint32(msg[0:], uint32(total))
	binary.NativeEndian.PutUint16(msg[4:], msgType)
	binary.NativeEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|extraFlags)
	binary.NativeEndian.PutUint32(msg[8:], 1)  // sequence
	binary.NativeEndian.PutUint32(msg[12:], 0) // pid: kernel assigns
	copy(msg[nlHdrLen:], body)

	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}
	return recvAck(fd)
}

// recvAck reads the reply and decodes the NLMSG_ERROR ack (errno 0 means success).
func recvAck(fd int) error {
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}
	if n < nlHdrLen {
		return fmt.Errorf("netlink: short reply (%d bytes)", n)
	}
	msgType := binary.NativeEndian.Uint16(buf[4:])
	if msgType != unix.NLMSG_ERROR {
		return fmt.Errorf("netlink: unexpected reply type %d", msgType)
	}
	if n < nlHdrLen+4 {
		return fmt.Errorf("netlink: truncated error reply")
	}
	errno := int32(binary.NativeEndian.Uint32(buf[nlHdrLen:]))
	if errno != 0 {
		return fmt.Errorf("netlink: %w", unix.Errno(-errno))
	}
	return nil
}
