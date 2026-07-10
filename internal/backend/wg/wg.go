package wg

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/singularityos-lab/sinty-nm/internal/core"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Backend configures WireGuard interfaces. It satisfies core.WGBackend.
type Backend struct {
	mu sync.Mutex
	wg *wgctrl.Client
}

// New builds the backend. The wgctrl client is opened lazily on first use, so a kernel
// without the wireguard family does not prevent the daemon from starting; the error
// surfaces at Configure time instead.
func New() (*Backend, error) {
	return &Backend{}, nil
}

// client returns the wgctrl client, opening it on first use.
func (b *Backend) client() (*wgctrl.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.wg != nil {
		return b.wg, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wg: open wgctrl: %w", err)
	}
	b.wg = c
	return c, nil
}

// Configure ensures a wireguard link named ifname exists, applies cfg to it, and brings
// it administratively up. It does not touch addresses or routes.
func (b *Backend) Configure(ifname string, cfg core.WGConfig) error {
	// The link must exist before wgctrl can address it; the kernel only creates a
	// wireguard device on an explicit RTM_NEWLINK with IFLA_INFO_KIND=wireguard.
	if _, err := net.InterfaceByName(ifname); err != nil {
		if !isNotFound(err) {
			return fmt.Errorf("wg: lookup %q: %w", ifname, err)
		}
		// EEXIST means someone created it between the lookup and here; fine, configure it.
		if cerr := createLink(ifname); cerr != nil && !errors.Is(cerr, unix.EEXIST) {
			return cerr
		}
	}

	wc, err := translate(cfg)
	if err != nil {
		return err
	}
	c, cerr := b.client()
	if cerr != nil {
		return cerr
	}
	if err := c.ConfigureDevice(ifname, wc); err != nil {
		return fmt.Errorf("wg: configure %q: %w", ifname, err)
	}
	return setUp(ifname)
}

// isNotFound reports whether an InterfaceByName error means the link does not exist.
// The net package keeps its "no such network interface" sentinel unexported, so match
// the message alongside the errno.
func isNotFound(err error) bool {
	return errors.Is(err, unix.ENODEV) ||
		strings.Contains(err.Error(), "no such network interface")
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
	out := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers:        make([]wgtypes.PeerConfig, 0, len(cfg.Peers)),
	}
	// 0 means "leave alone": sending an explicit zero would pick a random ephemeral
	// port / clear the fwmark on every Configure.
	if cfg.ListenPort != 0 {
		out.ListenPort = &cfg.ListenPort
	}
	if cfg.FwMark != 0 {
		out.FirewallMark = &cfg.FwMark
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
