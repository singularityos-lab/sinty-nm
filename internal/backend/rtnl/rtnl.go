package rtnl

// Link is a normalized kernel network interface.
type Link struct {
	Index int
	Name  string
	Kind  string // "device" (ethernet), "wireless", "loopback", "wireguard", ...
	Up    bool
	MAC   string
	MTU   int
}

// TODO(M1): DumpLinks() []Link via RTM_GETLINK; classify Kind (ethernet vs wifi vs
//           wireguard vs bridge...) so nmapi reports the right NM DeviceType.
// TODO(M3): AddAddr/DelAddr (RTM_NEWADDR), AddRoute/DelRoute (RTM_NEWROUTE), SetMTU.
// TODO(M3): default-route election across active connections (metrics).
// TODO(M1): a netlink event socket (RTMGRP_LINK|IPV4_IFADDR) to drive live state.
