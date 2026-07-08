package rtnl

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// Constants absent from the standard library's syscall package on Linux.
const (
	iflaInfoKind = 1       // nested IFLA_LINKINFO attr: the kind string ("bridge", "wireguard", ...)
	rtmgrpLink   = 0x1     // RTMGRP_LINK multicast group (link add/change/remove)
	iffLowerUp   = 0x10000 // IFF_LOWER_UP: physical carrier present
	ifOperUp     = 6       // IF_OPER_UP operstate value
)

// hostOrder is the machine byte order; netlink is native-endian on the wire.
var hostOrder binary.ByteOrder = func() binary.ByteOrder {
	var x uint16 = 1
	if *(*byte)(unsafe.Pointer(&x)) == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

// Backend is the rtnetlink LinkBackend. The command socket serves request/ack
// operations; dumps go through syscall.NetlinkRIB, and Subscribe opens its own socket.
type Backend struct {
	mu     sync.Mutex // serializes send+ack on the command socket
	fd     int
	kernel *syscall.SockaddrNetlink
	seq    uint32
}

// New opens a NETLINK_ROUTE command socket bound to the kernel.
func New() (*Backend, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("rtnl: socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("rtnl: bind: %w", err)
	}
	return &Backend{fd: fd, kernel: &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}}, nil
}

// Close releases the command socket.
func (b *Backend) Close() error { return syscall.Close(b.fd) }

// exec sends one request on the command socket and waits for its ack. NLM_F_REQUEST and
// NLM_F_ACK are added here so the kernel always replies with an NLMSG_ERROR to sync on.
func (b *Backend) exec(msgType, flags uint16, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	seq := atomic.AddUint32(&b.seq, 1)
	msg := buildMessage(msgType, flags|syscall.NLM_F_REQUEST|syscall.NLM_F_ACK, seq, payload)
	if err := syscall.Sendto(b.fd, msg, 0, b.kernel); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(b.fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case syscall.NLMSG_ERROR:
				// NLMSG_ERROR payload starts with an int32 errno; 0 means success (a plain ack).
				if len(m.Data) < 4 {
					return fmt.Errorf("rtnl: short NLMSG_ERROR")
				}
				if e := int32(hostOrder.Uint32(m.Data[:4])); e != 0 {
					return fmt.Errorf("rtnl: %w", syscall.Errno(-e))
				}
				return nil
			case syscall.NLMSG_DONE:
				return nil
			}
		}
	}
}

// DumpLinks returns every kernel interface via an RTM_GETLINK dump.
func (b *Backend) DumpLinks() ([]core.LinkInfo, error) {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("rtnl: dump links: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, err
	}
	out := make([]core.LinkInfo, 0, len(msgs))
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		if li, ok := parseLink(m.Data); ok {
			out = append(out, li)
		}
	}
	return out, nil
}

// LinkByName returns the single link with the given name, dumping and filtering.
func (b *Backend) LinkByName(name string) (core.LinkInfo, error) {
	links, err := b.DumpLinks()
	if err != nil {
		return core.LinkInfo{}, err
	}
	for _, l := range links {
		if l.Name == name {
			return l, nil
		}
	}
	return core.LinkInfo{}, fmt.Errorf("rtnl: link %q not found", name)
}

// SetUp brings a link administratively up or down (IFF_UP) via RTM_NEWLINK.
func (b *Backend) SetUp(index int, up bool) error {
	var flags uint32
	if up {
		flags = syscall.IFF_UP
	}
	// Change=IFF_UP tells the kernel to touch only the IFF_UP bit; other flags stay put.
	payload := ifInfomsg(syscall.AF_UNSPEC, index, flags, syscall.IFF_UP)
	return b.exec(syscall.RTM_NEWLINK, 0, payload)
}

// SetMTU sets a link's MTU via RTM_NEWLINK with an IFLA_MTU attribute.
func (b *Backend) SetMTU(index, mtu int) error {
	payload := ifInfomsg(syscall.AF_UNSPEC, index, 0, 0)
	payload = appendAttrU32(payload, syscall.IFLA_MTU, uint32(mtu))
	return b.exec(syscall.RTM_NEWLINK, 0, payload)
}

// AddAddr adds an IPv4 or IPv6 address to a link via RTM_NEWADDR.
func (b *Backend) AddAddr(index int, ip net.IP, prefixLen int) error {
	fam, raw := ipFamily(ip)
	if raw == nil {
		return fmt.Errorf("rtnl: invalid address %v", ip)
	}
	payload := ifAddrmsg(uint8(fam), prefixLen, index)
	payload = appendAttr(payload, syscall.IFA_LOCAL, raw)
	payload = appendAttr(payload, syscall.IFA_ADDRESS, raw)
	if fam == syscall.AF_INET && prefixLen < 31 {
		// Directed broadcast: local | ^mask, as `ip addr add` does for IPv4.
		mask := net.CIDRMask(prefixLen, 32)
		bcast := make([]byte, 4)
		for i := range bcast {
			bcast[i] = raw[i] | ^mask[i]
		}
		payload = appendAttr(payload, syscall.IFA_BROADCAST, bcast)
	}
	return b.exec(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE, payload)
}

// FlushAddrs removes every address on a link, dumping RTM_GETADDR then RTM_DELADDR each.
func (b *Backend) FlushAddrs(index int) error {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("rtnl: dump addrs: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return err
	}
	var errs []error
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWADDR || len(m.Data) < syscall.SizeofIfAddrmsg {
			continue
		}
		fam := m.Data[0]
		prefix := int(m.Data[1])
		aidx := int(hostOrder.Uint32(m.Data[4:8]))
		if aidx != index {
			continue
		}
		var addr []byte
		forEachAttr(m.Data[syscall.SizeofIfAddrmsg:], func(t uint16, d []byte) {
			switch t {
			case syscall.IFA_LOCAL:
				addr = d
			case syscall.IFA_ADDRESS:
				if addr == nil {
					addr = d
				}
			}
		})
		if addr == nil {
			continue
		}
		payload := ifAddrmsg(fam, prefix, index)
		payload = appendAttr(payload, syscall.IFA_LOCAL, addr)
		payload = appendAttr(payload, syscall.IFA_ADDRESS, addr)
		// Best effort: keep deleting so one failure doesn't leave a half-flushed link.
		if err := b.exec(syscall.RTM_DELADDR, 0, payload); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// AddRoute installs a route via RTM_NEWROUTE. A nil r.Dst is the default route, whose
// family is taken from the gateway; Metric maps to RTA_PRIORITY.
func (b *Backend) AddRoute(index int, r core.RouteInfo) error {
	return b.route(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_REPLACE, index, r)
}

// DelRoute removes a route via RTM_DELROUTE, matched on the same fields.
func (b *Backend) DelRoute(index int, r core.RouteInfo) error {
	return b.route(syscall.RTM_DELROUTE, 0, index, r)
}

// route builds and sends an RTM_{NEW,DEL}ROUTE message for r on link index.
func (b *Backend) route(msgType, flags uint16, index int, r core.RouteInfo) error {
	var fam int
	var dst []byte
	dstLen := 0
	if r.Dst != nil {
		ones, _ := r.Dst.Mask.Size()
		dstLen = ones
		fam, dst = ipFamily(r.Dst.IP)
		if dst == nil {
			return fmt.Errorf("rtnl: invalid route dst %v", r.Dst)
		}
	}
	var gw []byte
	if r.Gw != nil {
		gfam, graw := ipFamily(r.Gw)
		if graw == nil {
			return fmt.Errorf("rtnl: invalid gateway %v", r.Gw)
		}
		gw = graw
		if r.Dst == nil {
			fam = gfam // default route: family comes from the gateway
		}
	}
	if fam == 0 {
		return fmt.Errorf("rtnl: route has neither dst nor gateway family")
	}
	// A route with a gateway is UNIVERSE-scope; a gateway-less on-link route resolves
	// only to its link, so it takes LINK scope.
	scope := uint8(syscall.RT_SCOPE_UNIVERSE)
	if gw == nil {
		scope = syscall.RT_SCOPE_LINK
	}
	payload := rtMsg(fam, dstLen, scope)
	if dst != nil {
		payload = appendAttr(payload, syscall.RTA_DST, dst)
	}
	if gw != nil {
		payload = appendAttr(payload, syscall.RTA_GATEWAY, gw)
	}
	payload = appendAttrU32(payload, syscall.RTA_OIF, uint32(index))
	if r.Metric > 0 {
		payload = appendAttrU32(payload, syscall.RTA_PRIORITY, uint32(r.Metric))
	}
	return b.exec(msgType, flags, payload)
}

// Subscribe opens a second socket in the RTMGRP_LINK group and delivers link events
// until ctx is cancelled. The bool means present (RTM_NEWLINK, also fired on link
// changes such as down) vs removed (RTM_DELLINK); read li.Up/li.Carrier for up/down.
func (b *Backend) Subscribe(ctx context.Context, fn func(core.LinkInfo, bool)) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("rtnl: event socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: rtmgrpLink}); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("rtnl: event bind: %w", err)
	}
	var closeOnce sync.Once
	closeFd := func() { closeOnce.Do(func() { syscall.Close(fd) }) }
	defer closeFd()
	// Closing the fd on cancellation unblocks the Recvfrom below.
	go func() {
		<-ctx.Done()
		closeFd()
	}()
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// ENOBUFS is a multicast overrun (events were dropped, socket still
			// works); EINTR is a plain interrupted read. Neither ends the stream.
			if err == syscall.ENOBUFS || err == syscall.EINTR {
				continue
			}
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
				if li, ok := parseLink(m.Data); ok {
					fn(li, m.Header.Type == syscall.RTM_NEWLINK)
				}
			}
		}
	}
}
