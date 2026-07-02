package wg

import (
	"fmt"
	"net"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Backend configures WireGuard interfaces. It satisfies core.WGBackend.
type Backend struct {
	wg *wgctrl.Client
}

// New opens a wgctrl client over the wireguard netlink family.
func New() (*Backend, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wg: open wgctrl: %w", err)
	}
	return &Backend{wg: c}, nil
}

// Configure ensures a wireguard link named ifname exists, applies cfg to it, and brings
// it administratively up. It does not touch addresses or routes.
func (b *Backend) Configure(ifname string, cfg core.WGConfig) error {
	// The link must exist before wgctrl can address it; the kernel only creates a
	// wireguard device on an explicit RTM_NEWLINK with IFLA_INFO_KIND=wireguard.
	if _, err := net.InterfaceByName(ifname); err != nil {
		if cerr := createLink(ifname); cerr != nil {
			return cerr
		}
	}

	wc, err := translate(cfg)
	if err != nil {
		return err
	}
	if err := b.wg.ConfigureDevice(ifname, wc); err != nil {
		return fmt.Errorf("wg: configure %q: %w", ifname, err)
	}
	return setUp(ifname)
}

// Remove deletes the wireguard link.
func (b *Backend) Remove(ifname string) error {
	return delLink(ifname)
}

// translate maps a core.WGConfig onto a wgtypes.Config, replacing the peer list.
func translate(cfg core.WGConfig) (wgtypes.Config, error) {
	priv, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("wg: private key: %w", err)
	}
	port := cfg.ListenPort
	mark := cfg.FwMark
	out := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   &port,
		FirewallMark: &mark,
		ReplacePeers: true,
		Peers:        make([]wgtypes.PeerConfig, 0, len(cfg.Peers)),
	}
	for i := range cfg.Peers {
		pc, err := translatePeer(cfg.Peers[i])
		if err != nil {
			return wgtypes.Config{}, err
		}
		out.Peers = append(out.Peers, pc)
	}
	return out, nil
}

// translatePeer maps one core.WGPeer onto a wgtypes.PeerConfig.
func translatePeer(p core.WGPeer) (wgtypes.PeerConfig, error) {
	pub, err := wgtypes.ParseKey(p.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("wg: peer public key: %w", err)
	}
	pc := wgtypes.PeerConfig{
		PublicKey:         pub,
		ReplaceAllowedIPs: true,
		AllowedIPs:        p.AllowedIPs,
	}
	if p.PresharedKey != "" {
		psk, err := wgtypes.ParseKey(p.PresharedKey)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("wg: peer preshared key: %w", err)
		}
		pc.PresharedKey = &psk
	}
	if p.Endpoint != "" {
		ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return wgtypes.PeerConfig{}, fmt.Errorf("wg: peer endpoint %q: %w", p.Endpoint, err)
		}
		pc.Endpoint = ep
	}
	if p.Keepalive > 0 {
		ka := time.Duration(p.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
	}
	return pc, nil
}
