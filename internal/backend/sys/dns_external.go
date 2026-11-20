package sys

import (
	"bufio"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

const ExternalDNSDir = "/run/sinty/dns.d"

func readExternal(dir string) []core.DNSEntry {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []core.DNSEntry
	for _, f := range files {
		name := f.Name()
		if f.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		fh, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		e := core.DNSEntry{Iface: "external:" + name, Priority: 100}
		s := bufio.NewScanner(fh)
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) != 2 {
				continue
			}
			switch fields[0] {
			case "nameserver":
				if ip := net.ParseIP(fields[1]); ip != nil {
					e.Nameservers = append(e.Nameservers, ip)
				}
			case "search":
				e.Domains = append(e.Domains, fields[1])
			case "priority":
				if n, err := strconv.Atoi(fields[1]); err == nil {
					e.Priority = n
				}
			}
		}
		fh.Close()
		if len(e.Nameservers) > 0 {
			out = append(out, e)
		}
	}
	return out
}

func (m *dnsManager) WatchExternal() {
	if err := os.MkdirAll(m.external, 0o755); err != nil {
		log.Printf("dns: %s: %v", m.external, err)
		return
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
	if err != nil {
		log.Printf("dns: inotify: %v", err)
		return
	}
	mask := uint32(syscall.IN_CLOSE_WRITE | syscall.IN_MOVED_TO | syscall.IN_MOVED_FROM | syscall.IN_DELETE | syscall.IN_CREATE)
	if _, err := syscall.InotifyAddWatch(fd, m.external, mask); err != nil {
		syscall.Close(fd)
		log.Printf("dns: watch %s: %v", m.external, err)
		return
	}
	m.mu.Lock()
	m.rewrite()
	m.mu.Unlock()
	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 4096)
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				if err == syscall.EINTR {
					continue
				}
				log.Printf("dns: inotify read: %v", err)
				return
			}
			changed := false
			for off := 0; off+syscall.SizeofInotifyEvent <= n; {
				ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
				changed = changed || ev.Mask&syscall.IN_ISDIR == 0
				off += syscall.SizeofInotifyEvent + int(ev.Len)
			}
			if changed {
				m.mu.Lock()
				if err := m.rewrite(); err != nil {
					log.Printf("dns: rewrite: %v", err)
				}
				m.mu.Unlock()
			}
		}
	}()
}
