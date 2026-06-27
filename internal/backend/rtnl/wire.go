package rtnl

import (
	"net"
	"os"
	"syscall"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// align rounds n up to the 4-byte netlink attribute/message boundary.
func align(n int) int { return (n + 3) &^ 3 }

// buildMessage frames a payload as an nlmsg: a 16-byte NlMsghdr (Len, Type, Flags, Seq,
// Pid) followed by the payload, with Len set to the total.
func buildMessage(msgType, flags uint16, seq uint32, payload []byte) []byte {
	total := syscall.NLMSG_HDRLEN + len(payload)
	buf := make([]byte, syscall.NLMSG_HDRLEN, align(total))
	hostOrder.PutUint32(buf[0:4], uint32(total))
	hostOrder.PutUint16(buf[4:6], msgType)
	hostOrder.PutUint16(buf[6:8], flags)
	hostOrder.PutUint32(buf[8:12], seq)
	// buf[12:16] Pid stays 0: the kernel fills the source port on receipt.
	buf = append(buf, payload...)
	return buf
}

// appendAttr appends one rtattr TLV (Len uint16, Type uint16, value) with padding.
func appendAttr(b []byte, typ uint16, data []byte) []byte {
	l := syscall.SizeofRtAttr + len(data)
	hdr := make([]byte, syscall.SizeofRtAttr)
	hostOrder.PutUint16(hdr[0:2], uint16(l))
	hostOrder.PutUint16(hdr[2:4], typ)
	b = append(b, hdr...)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// appendAttrU32 appends a 4-byte attribute holding v.
func appendAttrU32(b []byte, typ uint16, v uint32) []byte {
	var d [4]byte
	hostOrder.PutUint32(d[:], v)
	return appendAttr(b, typ, d[:])
}

// ifInfomsg builds the 16-byte ifinfomsg header (RTM_*LINK): Family, pad, Type, Index,
// Flags, Change.
func ifInfomsg(family uint8, index int, flags, change uint32) []byte {
	b := make([]byte, syscall.SizeofIfInfomsg)
	b[0] = family
	hostOrder.PutUint32(b[4:8], uint32(int32(index)))
	hostOrder.PutUint32(b[8:12], flags)
	hostOrder.PutUint32(b[12:16], change)
	return b
}

// ifAddrmsg builds the 8-byte ifaddrmsg header (RTM_*ADDR): Family, Prefixlen, Flags,
// Scope, Index.
func ifAddrmsg(family uint8, prefixLen, index int) []byte {
	b := make([]byte, syscall.SizeofIfAddrmsg)
	b[0] = family
	b[1] = byte(prefixLen)
	hostOrder.PutUint32(b[4:8], uint32(int32(index)))
	return b
}

// rtMsg builds the 12-byte rtmsg header (RTM_*ROUTE): a main-table unicast route with
// the given family, destination prefix length, and scope.
func rtMsg(family, dstLen int, scope uint8) []byte {
	b := make([]byte, syscall.SizeofRtMsg)
	b[0] = byte(family)
	b[1] = byte(dstLen)
	b[4] = syscall.RT_TABLE_MAIN
	b[5] = syscall.RTPROT_BOOT
	b[6] = scope
	b[7] = syscall.RTN_UNICAST
	return b
}

// ipFamily returns the AF_* family and the raw 4- or 16-byte address for ip, or a nil
// slice if ip is not a valid IPv4/IPv6 address.
func ipFamily(ip net.IP) (int, []byte) {
	if v4 := ip.To4(); v4 != nil {
		return syscall.AF_INET, v4
	}
	if v6 := ip.To16(); v6 != nil {
		return syscall.AF_INET6, v6
	}
	return syscall.AF_UNSPEC, nil
}

// forEachAttr walks a run of rtattr TLVs and calls fn(type, value) for each.
func forEachAttr(b []byte, fn func(typ uint16, data []byte)) {
	for len(b) >= syscall.SizeofRtAttr {
		l := int(hostOrder.Uint16(b[0:2]))
		t := hostOrder.Uint16(b[2:4])
		if l < syscall.SizeofRtAttr || l > len(b) {
			break
		}
		fn(t, b[syscall.SizeofRtAttr:l])
		b = b[align(l):]
	}
}

// parseLink decodes an RTM_*LINK payload (ifinfomsg + attributes) into a LinkInfo.
func parseLink(data []byte) (core.LinkInfo, bool) {
	if len(data) < syscall.SizeofIfInfomsg {
		return core.LinkInfo{}, false
	}
	arphrd := hostOrder.Uint16(data[2:4])
	index := int(int32(hostOrder.Uint32(data[4:8])))
	flags := hostOrder.Uint32(data[8:12])

	li := core.LinkInfo{
		Index: index,
		Up:    flags&syscall.IFF_UP != 0,
	}
	var infoKind string
	var operstate uint8
	forEachAttr(data[syscall.SizeofIfInfomsg:], func(t uint16, d []byte) {
		switch t {
		case syscall.IFLA_IFNAME:
			li.Name = cstr(d)
		case syscall.IFLA_ADDRESS:
			li.MAC = net.HardwareAddr(d).String()
		case syscall.IFLA_MTU:
			if len(d) >= 4 {
				li.MTU = int(hostOrder.Uint32(d))
			}
		case syscall.IFLA_OPERSTATE:
			if len(d) >= 1 {
				operstate = d[0]
			}
		case syscall.IFLA_LINKINFO:
			// IFLA_LINKINFO nests attributes; IFLA_INFO_KIND (1) carries the virtual
			// device kind string ("bridge", "wireguard", "tun", ...).
			forEachAttr(d, func(nt uint16, nd []byte) {
				if nt == iflaInfoKind {
					infoKind = cstr(nd)
				}
			})
		}
	})

	// Carrier is the operational-up signal: either the kernel's IFF_LOWER_UP flag or an
	// operstate of IF_OPER_UP.
	li.Carrier = flags&iffLowerUp != 0 || operstate == ifOperUp
	li.Kind = classify(li.Name, arphrd, flags, infoKind)
	return li, true
}

// classify maps kernel link facts to a core.DeviceKind.
//
// Heuristic: IFF_LOOPBACK wins first. A non-empty IFLA_INFO_KIND names a virtual device
// directly (wireguard/bridge/tun). The hard case is a device with no info-kind and
// ARPHRD_ETHER: it can be either wired or wifi (wifi NICs also report ARPHRD_ETHER), so
// we treat it as wifi only if sysfs exposes a wireless/phy80211 node for it, otherwise
// as plain ethernet. Anything else falls through to Unknown.
func classify(name string, arphrd uint16, flags uint32, infoKind string) core.DeviceKind {
	if flags&syscall.IFF_LOOPBACK != 0 || arphrd == syscall.ARPHRD_LOOPBACK {
		return core.KindLoopback
	}
	switch infoKind {
	case "wireguard":
		return core.KindWireGuard
	case "bridge":
		return core.KindBridge
	case "tun", "tap":
		return core.KindTun
	case "":
		if arphrd == syscall.ARPHRD_ETHER {
			if isWireless(name) {
				return core.KindWifi
			}
			return core.KindEthernet
		}
	}
	return core.KindUnknown
}

// isWireless reports whether the interface has a sysfs wireless/phy80211 node, which is
// how a wifi NIC is told apart from a wired one (both are ARPHRD_ETHER).
func isWireless(name string) bool {
	if name == "" {
		return false
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err == nil {
		return true
	}
	_, err := os.Stat("/sys/class/net/" + name + "/phy80211")
	return err == nil
}

// cstr trims a null-terminated netlink string attribute to its Go string.
func cstr(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
