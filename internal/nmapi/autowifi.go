package nmapi

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

var resolvConf = "/etc/resolv.conf"

var resolvconfDir = "/run/resolvconf/interfaces"

const observeTries = 20

var observeDelay = 500 * time.Millisecond

func (s *Settings) wifiProfile(ssid []byte) *SettingsConnection {
	s.mu.Lock()
	conns := append([]*SettingsConnection(nil), s.conns...)
	s.mu.Unlock()
	for _, sc := range conns {
		if sc.connType() == "802-11-wireless" && bytes.Equal(sc.ssid(), ssid) {
			return sc
		}
	}
	return nil
}

func (m *Manager) adoptWifi(d *Device, ssid []byte) {
	if len(ssid) == 0 {
		return
	}
	d.mu.Lock()
	busy := d.activeConn != nullPath
	d.mu.Unlock()
	if busy {
		return
	}
	var ac *ActiveConnection
	sc := m.settings.wifiProfile(ssid)
	if sc != nil {
		ac = m.newActiveConnection(sc, d, d.apPathForSSID(ssid))
	} else {
		ac = &ActiveConnection{
			m:        m,
			path:     m.acGen.next(prefixActive),
			conn:     nullPath,
			specific: orNull(d.apPathForSSID(ssid)),
			id:       string(ssid),
			typ:      "802-11-wireless",
			device:   d,
			ip4:      nullPath,
			ip6:      nullPath,
		}
	}
	ac.state = acStateActivated
	ac.adopted = true
	m.mu.Lock()
	m.activeConns[ac.path] = ac
	m.mu.Unlock()
	if err := ac.export(); err != nil {
		m.mu.Lock()
		delete(m.activeConns, ac.path)
		m.mu.Unlock()
		return
	}
	d.setActiveConnection(ac.path)
	m.mu.Lock()
	if m.primary == nullPath || m.activeConns[m.primary] == nil {
		m.primary = ac.path
	}
	m.mu.Unlock()
	m.refreshRootLists()
	go func() {
		if !m.observeIPv4(ac, d) {
			m.leaseAdoptedWifi(ac, sc, d)
		}
	}()
	go m.pollConnectivity(m.runCtx())
}

func (m *Manager) observeIPv4(ac *ActiveConnection, d *Device) bool {
	ctx := m.runCtx()
	for i := 0; i < observeTries; i++ {
		if l, err := m.b.Link.IPv4(d.index); err == nil && l.IP != nil {
			l.DNS, l.Domains = adoptedResolver(d.iface)
			m.mu.Lock()
			live := m.activeConns[ac.path] == ac
			m.mu.Unlock()
			if live {
				_ = m.b.DNS.Set(core.DNSEntry{Iface: d.iface, Nameservers: l.DNS, Domains: l.Domains, Priority: 100})
				m.publishIP4(ac, d, l)
			}
			return true
		}
		select {
		case <-ctx.Done():
			return true
		case <-time.After(observeDelay):
		}
	}
	return false
}

func (m *Manager) leaseAdoptedWifi(ac *ActiveConnection, sc *SettingsConnection, d *Device) {
	m.mu.Lock()
	live := m.activeConns[ac.path] == ac
	m.mu.Unlock()
	if !live {
		return
	}
	mac, _ := net.ParseMAC(d.mac)
	lease, err := m.b.DHCP.Acquire(m.runCtx(), d.iface, mac)
	if err != nil {
		log.Printf("sinty-nmd: no address on %s after it reconnected: %v", d.iface, err)
		return
	}
	m.mu.Lock()
	live = m.activeConns[ac.path] == ac
	m.mu.Unlock()
	if !live {
		return
	}
	if sc != nil {
		sc.mergeDNS(lease)
	}
	if err := m.applyLease(ac, d, lease, nil); err != nil {
		log.Printf("sinty-nmd: apply lease on %s: %v", d.iface, err)
	}
}

func adoptedResolver(iface string) ([]net.IP, []string) {
	var dns []net.IP
	var domains []string
	entries, _ := os.ReadDir(resolvconfDir)
	for _, e := range entries {
		name := e.Name()
		if name != iface && !strings.HasPrefix(name, iface+".") {
			continue
		}
		ns, ds, _ := parseResolver(filepath.Join(resolvconfDir, name))
		dns = append(dns, ns...)
		domains = append(domains, ds...)
	}
	if len(dns) > 0 {
		return dns, domains
	}
	ns, ds, owned := parseResolver(resolvConf)
	if owned {
		return nil, domains
	}
	return ns, ds
}

func parseResolver(path string) ([]net.IP, []string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, false
	}
	defer f.Close()
	var dns []net.IP
	var domains []string
	owned := false
	sc := bufio.NewScanner(f)
	for first := true; sc.Scan(); first = false {
		line := sc.Text()
		if first && strings.TrimSpace(line) == core.ResolvConfMarker {
			owned = true
		}
		w := strings.Fields(line)
		if len(w) < 2 {
			continue
		}
		switch w[0] {
		case "nameserver":
			if ip := net.ParseIP(w[1]).To4(); ip != nil {
				dns = append(dns, ip)
			}
		case "search", "domain":
			domains = append(domains, w[1:]...)
		}
	}
	return dns, domains, owned
}

func (m *Manager) dropAdoptedWifi(d *Device) {
	d.mu.Lock()
	p := d.activeConn
	d.mu.Unlock()
	if p == nullPath {
		return
	}
	m.mu.Lock()
	ac := m.activeConns[p]
	if ac == nil || !ac.adopted {
		m.mu.Unlock()
		return
	}
	delete(m.activeConns, p)
	if m.primary == p {
		m.primary = nullPath
	}
	m.mu.Unlock()
	ac.setState(acStateDeactivated, devReasonNone)
	ac.unexport()
	_ = m.b.DNS.Revert(d.iface)
	m.dropIP4(d)
	d.setActiveConnection(nullPath)
	m.refreshRootLists()
	go m.pollConnectivity(m.runCtx())
}
