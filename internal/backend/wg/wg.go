package wg

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	ss "github.com/singularityos-lab/libsingularity/src/system/core/go/sintysystem"
	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// Backend configures WireGuard interfaces through the system core. It satisfies
// core.WGBackend.
type Backend struct{}

// New builds the backend.
func New() (*Backend, error) {
	return &Backend{}, nil
}

// Configure ensures a wireguard link named ifname exists, applies cfg to it, and brings
// it administratively up. It does not touch addresses or routes.
func (b *Backend) Configure(ifname string, cfg core.WGConfig) error {
	text, err := render(cfg, resolve)
	if err != nil {
		return err
	}
	if err := ss.WgApply(ifname, text); err != nil {
		return fmt.Errorf("wg: configure %q: %w", ifname, err)
	}
	return nil
}

// Remove deletes the wireguard link.
func (b *Backend) Remove(ifname string) error {
	if err := ss.NetDeleteLink(ifname); err != nil {
		return fmt.Errorf("wg: delete link %q: %w", ifname, err)
	}
	return nil
}

func resolve(endpoint string) (string, error) {
	ep, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ep.IP.String(), strconv.Itoa(ep.Port)), nil
}

func render(cfg core.WGConfig, resolve func(string) (string, error)) (string, error) {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey)
	if cfg.ListenPort != 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
	}
	if cfg.FwMark != 0 {
		fmt.Fprintf(&b, "FwMark = %d\n", cfg.FwMark)
	}
	for _, p := range cfg.Peers {
		b.WriteString("[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if p.Endpoint != "" {
			ep, err := resolve(p.Endpoint)
			if err != nil {
				return "", fmt.Errorf("wg: peer endpoint %q: %w", p.Endpoint, err)
			}
			fmt.Fprintf(&b, "Endpoint = %s\n", ep)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
		if len(p.AllowedIPs) > 0 {
			ips := make([]string, len(p.AllowedIPs))
			for i, n := range p.AllowedIPs {
				ips[i] = n.String()
			}
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(ips, ", "))
		}
	}
	return b.String(), nil
}
