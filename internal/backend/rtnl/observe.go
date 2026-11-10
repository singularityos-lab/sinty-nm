package rtnl

import (
	"net"
	"syscall"

	ss "github.com/singularityos-lab/libsingularity/src/system/core/go/sintysystem"
	"github.com/singularityos-lab/sinty-nm/internal/core"
)

const mainTable = 254

func (b *Backend) IPv4(index int) (*core.Lease, error) {
	addrs, err := ss.NetAddresses()
	if err != nil {
		return nil, err
	}
	routes, err := ss.NetRoutes()
	if err != nil {
		return nil, err
	}
	return observeIPv4(addrs, routes, index), nil
}

func observeIPv4(addrs []ss.NetAddress, routes []ss.NetRoute, index int) *core.Lease {
	l := &core.Lease{}
	for _, a := range addrs {
		if int(a.Index) != index || a.Family != syscall.AF_INET || a.Scope != syscall.RT_SCOPE_UNIVERSE {
			continue
		}
		if ip := net.ParseIP(a.Address).To4(); ip != nil {
			l.IP, l.PrefixLen = ip, int(a.Prefix)
			break
		}
	}
	var metric uint32
	for _, r := range routes {
		if int(r.Oif) != index || r.Family != syscall.AF_INET || r.Prefix != 0 || r.Table != mainTable || r.Gateway == "" {
			continue
		}
		gw := net.ParseIP(r.Gateway).To4()
		if gw != nil && (l.Gateway == nil || r.Priority < metric) {
			l.Gateway, metric = gw, r.Priority
		}
	}
	return l
}
