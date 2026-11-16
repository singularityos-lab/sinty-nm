package nmapi

import (
	"bufio"
	"bytes"
	"net"
	"os"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

var resolvConf = "/etc/resolv.conf"

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
	if sc := m.settings.wifiProfile(ssid); sc != nil {
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
	go m.observeIPv4(ac, d)
	go m.pollConnectivity(m.runCtx())
}

func (m *Manager) observeIPv4(ac *ActiveConnection, d *Device) {
	ctx := m.runCtx()
	for i := 0; i < observeTries; i++ {
		if l, err := m.b.Link.IPv4(d.index); err == nil && l.IP != nil {
			l.DNS = nameservers(resolvConf)
			l.Domains = searchDomains(resolvConf)
			m.mu.Lock()
			live := m.activeConns[ac.path] == ac
			m.mu.Unlock()
			if live {
				_ = m.b.DNS.Set(core.DNSEntry{Iface: d.iface, Nameservers: l.DNS, Domains: l.Domains, Priority: 100})
				m.publishIP4(ac, d, l)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(observeDelay):
		}
	}
}

func nameservers(path string) []net.IP {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.Fields(sc.Text())
		if len(w) >= 2 && w[0] == "nameserver" {
			if ip := net.ParseIP(w[1]).To4(); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

func searchDomains(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.Fields(sc.Text())
		if len(w) >= 2 && (w[0] == "search" || w[0] == "domain") {
			out = append(out, w[1:]...)
		}
	}
	return out
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
