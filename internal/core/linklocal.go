package core

import (
	"hash/fnv"
	"net"
)

// LinkLocalLease is the IPv4 link-local fallback (RFC 3927) for a wired link where no
// DHCP server answered, so two machines cabled together still reach each other. The
// address is derived from the MAC, stable across boots, and avoids the reserved first
// and last /24 of 169.254.0.0/16. It carries no gateway and no DNS.
func LinkLocalLease(mac net.HardwareAddr) *Lease {
	h := fnv.New32a()
	h.Write(mac)
	v := h.Sum32() % (254 * 256)
	return &Lease{
		IP:        net.IPv4(169, 254, byte(1+v/256), byte(v%256)).To4(),
		PrefixLen: 16,
	}
}
