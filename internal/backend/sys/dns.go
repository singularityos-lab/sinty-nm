package sys

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// resolvPath is the resolver file this backend owns.
const resolvPath = "/etc/resolv.conf"

// marker is written as the first line so an operator can tell who owns the file.
const marker = "# managed by sinty-nm"

// maxNameservers caps the emitted nameserver lines: libc resolvers (glibc MAXNS) stop
// reading after three, so extra entries would be silently ignored.
const maxNameservers = 3

// maxSearchDomains and maxSearchChars cap the search line: glibc (MAXDNSRCH) stops at
// six domains and about 256 characters, so anything past that would be ignored anyway.
const maxSearchDomains = 6
const maxSearchChars = 256

// dnsManager merges per-interface DNS contributions into a single resolv.conf.
type dnsManager struct {
	mu      sync.Mutex
	path    string
	entries map[string]core.DNSEntry // keyed by DNSEntry.Iface
}

// NewDNS returns a DNSManager that owns /etc/resolv.conf.
func NewDNS() core.DNSManager {
	return &dnsManager{path: resolvPath, entries: make(map[string]core.DNSEntry)}
}

// Set stores or replaces the given interface's DNS entry and rewrites resolv.conf.
func (m *dnsManager) Set(entry core.DNSEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy the slices so a caller mutating them later cannot corrupt our state.
	entry.Nameservers = append([]net.IP(nil), entry.Nameservers...)
	entry.Domains = append([]string(nil), entry.Domains...)
	m.entries[entry.Iface] = entry
	return m.rewrite()
}

// Revert drops the given interface's DNS entry and rewrites resolv.conf.
func (m *dnsManager) Revert(iface string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, iface)
	return m.rewrite()
}

// render builds the resolv.conf body from all entries, ordered by Priority (lower first,
// iface name as a stable tie-break), deduping nameservers and unioning search domains.
func (m *dnsManager) render() []byte {
	entries := make([]core.DNSEntry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Priority != entries[j].Priority {
			return entries[i].Priority < entries[j].Priority
		}
		return entries[i].Iface < entries[j].Iface
	})

	var servers []string
	seen := make(map[string]bool)
	for _, e := range entries {
		for _, ns := range e.Nameservers {
			if len(ns) == 0 || ns.To16() == nil {
				continue
			}
			s := ns.String()
			if seen[s] {
				continue
			}
			seen[s] = true
			servers = append(servers, s)
		}
	}
	if len(servers) > maxNameservers {
		servers = servers[:maxNameservers]
	}

	var domains []string
	dseen := make(map[string]bool)
	for _, e := range entries {
		for _, d := range e.Domains {
			d = strings.TrimSpace(d)
			if d == "" || dseen[d] {
				continue
			}
			dseen[d] = true
			domains = append(domains, d)
		}
	}
	if len(domains) > maxSearchDomains {
		domains = domains[:maxSearchDomains]
	}
	total := 0
	for i, d := range domains {
		total += len(d) + 1
		if total > maxSearchChars {
			domains = domains[:i]
			break
		}
	}

	var b strings.Builder
	b.WriteString(marker)
	b.WriteByte('\n')
	for _, s := range servers {
		b.WriteString("nameserver ")
		b.WriteString(s)
		b.WriteByte('\n')
	}
	if len(domains) > 0 {
		b.WriteString("search ")
		b.WriteString(strings.Join(domains, " "))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// rewrite writes the rendered body to the owned path atomically.
func (m *dnsManager) rewrite() error {
	data := m.render()
	target := m.targetPath()
	if err := writeAtomic(target, data); err != nil {
		// The symlink destination was not writable after all (e.g. a read-only /run);
		// fall back to replacing the symlink at m.path with a regular file.
		if target != m.path {
			return writeAtomic(m.path, data)
		}
		return err
	}
	return nil
}

// targetPath resolves the file to write. If the owned path is a symlink (as it is under
// systemd-resolved or a stub resolver) and the destination directory is writable, it
// writes through to the destination so the link is preserved; otherwise it returns the
// symlink path itself, and rewrite replaces the link with a regular file. It never
// follows a link into a read-only directory.
func (m *dnsManager) targetPath() string {
	fi, err := os.Lstat(m.path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return m.path
	}
	dst, err := os.Readlink(m.path)
	if err != nil {
		return m.path
	}
	if !filepath.IsAbs(dst) {
		dst = filepath.Join(filepath.Dir(m.path), dst)
	}
	if syscall.Access(filepath.Dir(dst), 2) != nil { // W_OK
		return m.path
	}
	return dst
}

// writeAtomic writes data to a temp file in the destination directory, then renames it
// over path so readers never observe a half-written resolver file.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sinty-nm-resolv-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	return nil
}
