package dhcp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// DHCP message types (option 53) and the option codes we encode or read.
const (
	msgDiscover = 1
	msgOffer    = 2
	msgRequest  = 3
	msgAck      = 5
	msgRelease  = 7

	optSubnetMask  = 1
	optRouter      = 3
	optDNS         = 6
	optDomain      = 15
	optRequestedIP = 50
	optLeaseTime   = 51
	optMsgType     = 53
	optServerID    = 54
	optParamList   = 55
	optClientID    = 61
	optEnd         = 255
)

// magicCookie precedes the options field in a BOOTP/DHCP packet (RFC 2131).
var magicCookie = [4]byte{0x63, 0x82, 0x53, 0x63}

// newXID returns a random 32-bit transaction id used to match replies to our request.
func newXID() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// buildMsg encodes a BOOTREQUEST for the given message type. reqIP/serverID are only used
// for REQUEST/RELEASE (option 50/54); pass nil otherwise. The BROADCAST flag is set so a
// server replies to 255.255.255.255, which is required while we still have no address.
func buildMsg(mtype byte, xid uint32, mac net.HardwareAddr, reqIP, serverID net.IP) []byte {
	buf := make([]byte, 240) // 236-byte BOOTP header + 4-byte magic cookie
	buf[0] = 1               // op: BOOTREQUEST
	buf[1] = 1               // htype: ethernet
	buf[2] = 6               // hlen
	binary.BigEndian.PutUint32(buf[4:8], xid)
	if mtype != msgRelease {
		binary.BigEndian.PutUint16(buf[10:12], 0x8000) // flags: BROADCAST
	} else if reqIP != nil {
		copy(buf[12:16], reqIP.To4()) // ciaddr: release is sent from the bound address
	}
	copy(buf[28:34], mac) // chaddr
	copy(buf[236:240], magicCookie[:])

	opts := []byte{optMsgType, 1, mtype}
	opts = append(opts, optClientID, 7, 1)
	opts = append(opts, mac...)
	if reqIP != nil && mtype == msgRequest {
		opts = append(opts, optRequestedIP, 4)
		opts = append(opts, reqIP.To4()...)
	}
	if serverID != nil {
		opts = append(opts, optServerID, 4)
		opts = append(opts, serverID.To4()...)
	}
	if mtype == msgDiscover || mtype == msgRequest {
		opts = append(opts, optParamList, 6,
			optSubnetMask, optRouter, optDNS, optDomain, 28, optLeaseTime)
	}
	opts = append(opts, optEnd)

	return append(buf, opts...)
}

// reply is a decoded DHCP message: the xid and yiaddr fields plus a code->value option map.
type reply struct {
	xid    uint32
	yiaddr net.IP
	opts   map[byte][]byte
}

// parseReply decodes a BOOTP/DHCP payload (the UDP body) into a reply, or errors if it is
// too short or lacks the magic cookie.
func parseReply(b []byte) (*reply, error) {
	if len(b) < 240 {
		return nil, errors.New("short dhcp packet")
	}
	if [4]byte{b[236], b[237], b[238], b[239]} != magicCookie {
		return nil, errors.New("bad magic cookie")
	}
	r := &reply{
		xid:    binary.BigEndian.Uint32(b[4:8]),
		yiaddr: net.IPv4(b[16], b[17], b[18], b[19]),
		opts:   make(map[byte][]byte),
	}
	// Options are code/length/value triples, terminated by 255; 0 is a pad byte.
	for i := 240; i < len(b); {
		code := b[i]
		if code == optEnd {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		r.opts[code] = b[i+2 : i+2+l]
		i += 2 + l
	}
	return r, nil
}

// msgType returns the DHCP message type (option 53), or 0 if absent.
func (r *reply) msgType() byte {
	if v, ok := r.opts[optMsgType]; ok && len(v) == 1 {
		return v[0]
	}
	return 0
}

// opt4 returns a 4-byte option as an IPv4 address, or nil if absent/malformed.
func (r *reply) opt4(code byte) net.IP {
	if v, ok := r.opts[code]; ok && len(v) == 4 {
		return net.IPv4(v[0], v[1], v[2], v[3])
	}
	return nil
}

// toLease turns a decoded ACK into a core.Lease.
func (r *reply) toLease() (*core.Lease, error) {
	if r.yiaddr == nil || r.yiaddr.Equal(net.IPv4zero) {
		return nil, errors.New("ack has no yiaddr")
	}
	lease := &core.Lease{
		IP:       r.yiaddr,
		Gateway:  r.opt4(optRouter),
		ServerID: r.opt4(optServerID),
	}
	if m, ok := r.opts[optSubnetMask]; ok && len(m) == 4 {
		ones, _ := net.IPv4Mask(m[0], m[1], m[2], m[3]).Size()
		lease.PrefixLen = ones
	}
	if v, ok := r.opts[optDNS]; ok {
		for i := 0; i+4 <= len(v); i += 4 {
			lease.DNS = append(lease.DNS, net.IPv4(v[i], v[i+1], v[i+2], v[i+3]))
		}
	}
	if v, ok := r.opts[optDomain]; ok && len(v) > 0 {
		lease.Domains = []string{string(v)}
	}
	if v, ok := r.opts[optLeaseTime]; ok && len(v) == 4 {
		lease.LeaseSeconds = binary.BigEndian.Uint32(v)
	}
	return lease, nil
}
