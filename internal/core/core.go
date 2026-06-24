package core

import (
	"context"
	"net"
)

// DeviceKind is the class of a network device, mapped to an NM DeviceType in nmapi.
type DeviceKind int

const (
	KindUnknown DeviceKind = iota
	KindEthernet
	KindWifi
	KindWireGuard
	KindLoopback
	KindBridge
	KindTun
)

// WifiSecurity is the coarse security class of an access point.
type WifiSecurity int

const (
	SecOpen WifiSecurity = iota
	SecWEP
	SecPSK
	SecEnterprise
)

// LinkInfo is a normalized L2 interface as reported by the kernel.
type LinkInfo struct {
	Index   int
	Name    string
	Kind    DeviceKind
	Up      bool // administratively up (IFF_UP)
	Carrier bool // link-layer carrier present (operationally up)
	MAC     string
	MTU     int
}

// AddrInfo is an address configured on a link.
type AddrInfo struct {
	IP        net.IP
	PrefixLen int
}

// RouteInfo is a single route. A nil Dst means the default route.
type RouteInfo struct {
	Dst    *net.IPNet
	Gw     net.IP
	Metric int
}

// Lease is the result of a successful DHCP acquisition, enough to configure the link.
type Lease struct {
	IP           net.IP
	PrefixLen    int
	Gateway      net.IP
	DNS          []net.IP
	Domains      []string
	ServerID     net.IP
	LeaseSeconds uint32
}

// ScannedAP is one access point seen during a scan, backend-normalized. Strength is a
// 0..100 percentage (nmapi maps it straight onto NM's AccessPoint.Strength byte).
type ScannedAP struct {
	SSID      []byte
	BSSID     string
	Strength  uint8
	Frequency uint32 // MHz
	Security  WifiSecurity
	Known     bool // a saved/known network
	Handle    string // backend-opaque reference (iwd network object path)
}

// WifiDevice is a wifi-capable device as the wifi backend sees it.
type WifiDevice struct {
	Name    string
	Powered bool
	Handle  string // backend-opaque reference (iwd device object path)
}

// WifiState is the connection state of a wifi device, backend-normalized.
type WifiState int

const (
	WifiDisconnected WifiState = iota
	WifiConnecting
	WifiConnected
	WifiDisconnecting
)

// WifiEvent is pushed on any change the wifi backend observes for a device.
type WifiEvent struct {
	Device string
	State  WifiState
	// ConnectedSSID is set when State is WifiConnected.
	ConnectedSSID []byte
}

// SecretFunc is called by a backend when it needs a secret (e.g. a PSK) to proceed. It
// returns the secret for the given SSID, or an error to abort. nmapi wires this to the
// secret agent / keyring; a backend must never prompt or store secrets itself.
type SecretFunc func(ssid []byte) (string, error)

// WGPeer is one WireGuard peer.
type WGPeer struct {
	PublicKey    string
	PresharedKey string
	Endpoint     string // host:port
	AllowedIPs   []net.IPNet
	Keepalive    int // seconds, 0 = off
}

// WGConfig is a full WireGuard interface configuration.
type WGConfig struct {
	PrivateKey string
	ListenPort int
	FwMark     int
	Peers      []WGPeer
}

// DNSEntry is the DNS configuration contributed by one interface.
type DNSEntry struct {
	Iface       string
	Nameservers []net.IP
	Domains     []string
	// Priority mirrors NM's per-connection DNS priority (lower wins); the manager
	// orders resolv.conf accordingly.
	Priority int
}

// Connectivity mirrors NM's NMConnectivityState so nmapi can pass it through unchanged.
type Connectivity uint32

const (
	ConnUnknown Connectivity = iota
	ConnNone
	ConnPortal
	ConnLimited
	ConnFull
)

// LinkBackend is the kernel L2/L3 mechanism (rtnetlink). It never shells out.
type LinkBackend interface {
	DumpLinks() ([]LinkInfo, error)
	LinkByName(name string) (LinkInfo, error)
	SetUp(index int, up bool) error
	AddAddr(index int, ip net.IP, prefixLen int) error
	FlushAddrs(index int) error
	AddRoute(index int, r RouteInfo) error
	DelRoute(index int, r RouteInfo) error
	SetMTU(index, mtu int) error
	// Subscribe delivers link add/change/remove events until ctx is cancelled.
	Subscribe(ctx context.Context, fn func(LinkInfo, bool)) error
}

// WifiBackend is the wifi mechanism (iwd over net.connman.iwd).
type WifiBackend interface {
	ListDevices() ([]WifiDevice, error)
	SetPowered(dev string, on bool) error
	Scan(dev string) error
	OrderedNetworks(dev string) ([]ScannedAP, error)
	Connect(dev string, ssid []byte, secret SecretFunc) error
	Disconnect(dev string) error
	Forget(dev string, ssid []byte) error
	State(dev string) (WifiState, error)
	Subscribe(ctx context.Context, fn func(WifiEvent)) error
}

// DHCPClient is the built-in DHCPv4 client. Acquire blocks until a lease is obtained or
// ctx is cancelled; it does not itself apply the lease to the link.
type DHCPClient interface {
	Acquire(ctx context.Context, ifname string, mac net.HardwareAddr) (*Lease, error)
	Release(ifname string) error
}

// WGBackend configures WireGuard interfaces via the wireguard netlink family.
type WGBackend interface {
	Configure(ifname string, cfg WGConfig) error
	Remove(ifname string) error
}

// DNSManager owns the system resolver configuration, merging per-interface entries.
type DNSManager interface {
	Set(entry DNSEntry) error
	Revert(iface string) error
}

// RFKill exposes and toggles the wifi radio soft/hard block.
type RFKill interface {
	WifiSoftBlocked() (bool, error)
	WifiHardBlocked() (bool, error)
	SetWifiBlocked(block bool) error
	Subscribe(ctx context.Context, fn func(soft, hard bool)) error
}

// ConnChecker probes reachability for the NM-style connectivity state.
type ConnChecker interface {
	Check(ctx context.Context) (Connectivity, error)
}
