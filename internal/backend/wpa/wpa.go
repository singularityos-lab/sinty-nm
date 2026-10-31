// Package wpa drives wpa_supplicant over its control socket, for systems where the
// kernel has no nl80211 and iwd cannot run. Saved networks use iwd's profile files, so a
// disk moving between the two backends keeps its networks.
package wpa

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

const (
	// DefaultCtrlDir is where wpa_supplicant publishes one socket per interface.
	DefaultCtrlDir = "/run/wpa_supplicant"
	// DefaultProfileDir is iwd's profile directory.
	DefaultProfileDir = "/var/lib/iwd"

	requestTimeout = 5 * time.Second
	connectTimeout = 30 * time.Second
	scanWait       = 8 * time.Second
	devicePoll     = 3 * time.Second
)

// Backend implements core.WifiBackend on wpa_supplicant.
type Backend struct {
	CtrlDir    string
	ProfileDir string

	mu        sync.Mutex
	unpowered map[string]bool
	seq       int
}

// New returns a Backend on the default paths.
func New() *Backend {
	ctrl := DefaultCtrlDir
	if dir := os.Getenv("SINTY_NM_WPA_CTRL"); dir != "" {
		ctrl = dir
	}
	return &Backend{CtrlDir: ctrl, ProfileDir: DefaultProfileDir, unpowered: map[string]bool{}}
}

// client is one bound control socket. The supplicant answers to its source address, so
// each caller needs its own.
type client struct {
	conn  *net.UnixConn
	local string
}

func (b *Backend) dial(dev string) (*client, error) {
	b.mu.Lock()
	b.seq++
	local := filepath.Join(b.CtrlDir, fmt.Sprintf(".nm-%d-%d", os.Getpid(), b.seq))
	b.mu.Unlock()
	raddr := &net.UnixAddr{Name: filepath.Join(b.CtrlDir, dev), Net: "unixgram"}
	laddr := &net.UnixAddr{Name: local, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		return nil, err
	}
	return &client{conn: conn, local: local}, nil
}

func (c *client) close() {
	c.conn.Close()
	os.Remove(c.local)
}

func (c *client) request(cmd string) (string, error) {
	if _, err := c.conn.Write([]byte(cmd)); err != nil {
		return "", err
	}
	buf := make([]byte, 65536)
	for {
		c.conn.SetReadDeadline(time.Now().Add(requestTimeout))
		n, err := c.conn.Read(buf)
		if err != nil {
			return "", err
		}
		// An attached client also receives events, which start with a priority tag.
		if n > 0 && buf[0] == '<' {
			continue
		}
		return string(buf[:n]), nil
	}
}

func (b *Backend) do(dev, cmd string) (string, error) {
	c, err := b.dial(dev)
	if err != nil {
		return "", err
	}
	defer c.close()
	return c.request(cmd)
}

func (b *Backend) doOK(dev, cmd string) error {
	r, err := b.do(dev, cmd)
	if err != nil {
		return err
	}
	if strings.TrimSpace(r) != "OK" {
		return fmt.Errorf("wpa: %s: %s", strings.Fields(cmd)[0], strings.TrimSpace(r))
	}
	return nil
}

// ListDevices reports one device per control socket.
func (b *Backend) ListDevices() ([]core.WifiDevice, error) {
	entries, err := os.ReadDir(b.CtrlDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []core.WifiDevice
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || e.Type()&os.ModeSocket == 0 {
			continue
		}
		b.mu.Lock()
		off := b.unpowered[e.Name()]
		b.mu.Unlock()
		out = append(out, core.WifiDevice{Name: e.Name(), Powered: !off, Handle: e.Name()})
	}
	return out, nil
}

// SetPowered stops or resumes association. The radio itself stays up.
func (b *Backend) SetPowered(dev string, on bool) error {
	b.mu.Lock()
	b.unpowered[dev] = !on
	b.mu.Unlock()
	if on {
		return b.doOK(dev, "REASSOCIATE")
	}
	return b.doOK(dev, "DISCONNECT")
}

// Scan requests a scan and waits for it to finish.
func (b *Backend) Scan(dev string) error {
	c, err := b.dial(dev)
	if err != nil {
		return err
	}
	defer c.close()
	if _, err := c.request("ATTACH"); err != nil {
		return err
	}
	r, err := c.request("SCAN")
	if err != nil {
		return err
	}
	if s := strings.TrimSpace(r); s != "OK" && s != "FAIL-BUSY" {
		return fmt.Errorf("wpa: SCAN: %s", s)
	}
	deadline := time.Now().Add(scanWait)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		c.conn.SetReadDeadline(deadline)
		n, err := c.conn.Read(buf)
		if err != nil {
			return nil
		}
		if strings.Contains(string(buf[:n]), "CTRL-EVENT-SCAN-RESULTS") {
			return nil
		}
	}
	return nil
}

// OrderedNetworks returns one entry per SSID, strongest first.
func (b *Backend) OrderedNetworks(dev string) ([]core.ScannedAP, error) {
	r, err := b.do(dev, "SCAN_RESULTS")
	if err != nil {
		return nil, err
	}
	nets := parseScanResults(r)
	for i := range nets {
		nets[i].Known = b.profile(nets[i].SSID) != nil
		nets[i].Handle = string(nets[i].SSID)
	}
	return nets, nil
}

func parseScanResults(text string) []core.ScannedAP {
	var out []core.ScannedAP
	seen := map[string]int{}
	lines := strings.Split(text, "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.SplitN(line, "\t", 5)
		if len(f) < 5 || f[4] == "" {
			continue
		}
		freq, _ := strconv.Atoi(f[1])
		sig, _ := strconv.Atoi(f[2])
		ap := core.ScannedAP{
			SSID:      unescape(f[4]),
			BSSID:     f[0],
			Frequency: uint32(freq),
			Strength:  strength(sig),
			Security:  securityOf(f[3]),
		}
		if i, ok := seen[string(ap.SSID)]; ok {
			if ap.Strength > out[i].Strength {
				out[i] = ap
			}
			continue
		}
		seen[string(ap.SSID)] = len(out)
		out = append(out, ap)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Strength > out[j-1].Strength; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func strength(signal int) uint8 {
	// Drivers without a dBm scale report a small positive quality.
	if signal >= 0 {
		return uint8(min(signal*2, 100))
	}
	return uint8(max(min(2*(signal+100), 100), 0))
}

func securityOf(flags string) core.WifiSecurity {
	switch {
	case strings.Contains(flags, "EAP"):
		return core.SecEnterprise
	case strings.Contains(flags, "PSK"), strings.Contains(flags, "SAE"):
		return core.SecPSK
	case strings.Contains(flags, "WEP"):
		return core.SecWEP
	default:
		return core.SecOpen
	}
}

// unescape reverses wpa_supplicant's printf_encode of an SSID.
func unescape(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			out = append(out, s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'e':
			out = append(out, 0x1b)
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					out = append(out, byte(v))
					i += 2
				}
			}
		default:
			out = append(out, s[i])
		}
	}
	return out
}

// Connect associates with ssid and blocks until connected or failed.
func (b *Backend) Connect(dev string, ssid []byte, secret core.SecretFunc) error {
	r, err := b.do(dev, "SCAN_RESULTS")
	if err != nil {
		return err
	}
	var sec = core.SecOpen
	flags := ""
	for _, line := range strings.Split(r, "\n") {
		f := strings.SplitN(line, "\t", 5)
		if len(f) == 5 && string(unescape(f[4])) == string(ssid) {
			sec, flags = securityOf(f[3]), f[3]
			break
		}
	}
	if sec == core.SecEnterprise || sec == core.SecWEP {
		return errors.New("wpa: unsupported network security")
	}
	cred, saved := b.profile(ssid), true
	if sec == core.SecPSK && (cred == nil || cred.psk == "") {
		if secret == nil {
			return errors.New("wpa: no secret for network")
		}
		pass, err := secret(ssid)
		if err != nil {
			return err
		}
		cred, saved = &profile{psk: pass}, false
	}

	c, err := b.dial(dev)
	if err != nil {
		return err
	}
	defer c.close()
	if _, err := c.request("ATTACH"); err != nil {
		return err
	}
	if _, err := c.request("REMOVE_NETWORK all"); err != nil {
		return err
	}
	idr, err := c.request("ADD_NETWORK")
	if err != nil {
		return err
	}
	id := strings.TrimSpace(idr)
	if _, err := strconv.Atoi(id); err != nil {
		return fmt.Errorf("wpa: ADD_NETWORK: %s", id)
	}
	set := []string{"ssid " + hexOf(ssid)}
	switch {
	case sec != core.SecPSK:
		set = append(set, "key_mgmt NONE")
	case strings.Contains(flags, "SAE"):
		set = append(set, "key_mgmt WPA-PSK SAE", "ieee80211w 1")
	}
	if sec == core.SecPSK {
		set = append(set, "psk "+pskValue(cred.psk))
	}
	for _, s := range set {
		if err := request(c, "SET_NETWORK "+id+" "+s); err != nil {
			return fmt.Errorf("wpa: SET_NETWORK %s", strings.Fields(s)[0])
		}
	}
	if err := request(c, "SELECT_NETWORK "+id); err != nil {
		return err
	}
	if err := awaitConnected(c); err != nil {
		return err
	}
	if !saved {
		return b.saveProfile(ssid, sec, cred.psk)
	}
	if sec == core.SecOpen && cred == nil {
		return b.saveProfile(ssid, sec, "")
	}
	return nil
}

func request(c *client, cmd string) error {
	r, err := c.request(cmd)
	if err != nil {
		return err
	}
	if strings.TrimSpace(r) != "OK" {
		return errors.New(strings.TrimSpace(r))
	}
	return nil
}

func awaitConnected(c *client) error {
	deadline := time.Now().Add(connectTimeout)
	buf := make([]byte, 4096)
	for {
		c.conn.SetReadDeadline(deadline)
		n, err := c.conn.Read(buf)
		if err != nil {
			return errors.New("wpa: association timed out")
		}
		ev := string(buf[:n])
		switch {
		case strings.Contains(ev, "CTRL-EVENT-CONNECTED"):
			return nil
		case strings.Contains(ev, "CTRL-EVENT-SSID-TEMP-DISABLED"),
			strings.Contains(ev, "WRONG_KEY"),
			strings.Contains(ev, "CTRL-EVENT-ASSOC-REJECT"):
			return errors.New("wpa: association failed")
		}
	}
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }

var rawPSK = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func pskValue(p string) string {
	if rawPSK.MatchString(p) {
		return p
	}
	return strconv.Quote(p)
}

// Disconnect leaves the current network.
func (b *Backend) Disconnect(dev string) error { return b.doOK(dev, "DISCONNECT") }

// Forget removes the saved profile for ssid.
func (b *Backend) Forget(dev string, ssid []byte) error {
	var firstErr error
	removed := false
	for _, ext := range []string{".psk", ".open"} {
		err := os.Remove(filepath.Join(b.ProfileDir, profileName(ssid)+ext))
		if err == nil {
			removed = true
		} else if !errors.Is(err, os.ErrNotExist) {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}
	if !removed {
		return fmt.Errorf("wpa: %q is not a known network", string(ssid))
	}
	return nil
}

// State reports the supplicant state of dev.
func (b *Backend) State(dev string) (core.WifiState, error) {
	r, err := b.do(dev, "STATUS")
	if err != nil {
		return core.WifiDisconnected, err
	}
	state, _ := parseStatus(r)
	return state, nil
}

func parseStatus(text string) (core.WifiState, []byte) {
	state := core.WifiDisconnected
	var ssid []byte
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "wpa_state":
			state = stateOf(v)
		case "ssid":
			ssid = unescape(v)
		}
	}
	return state, ssid
}

func stateOf(s string) core.WifiState {
	switch s {
	case "COMPLETED":
		return core.WifiConnected
	case "AUTHENTICATING", "ASSOCIATING", "ASSOCIATED", "4WAY_HANDSHAKE", "GROUP_HANDSHAKE":
		return core.WifiConnecting
	default:
		return core.WifiDisconnected
	}
}

// Subscribe follows every interface and reports state changes until ctx is cancelled.
func (b *Backend) Subscribe(ctx context.Context, fn func(core.WifiEvent)) error {
	go func() {
		watched := map[string]bool{}
		var mu sync.Mutex
		for ctx.Err() == nil {
			devs, _ := b.ListDevices()
			for _, d := range devs {
				mu.Lock()
				seen := watched[d.Name]
				watched[d.Name] = true
				mu.Unlock()
				if !seen {
					go func(name string) {
						b.follow(ctx, name, fn)
						mu.Lock()
						delete(watched, name)
						mu.Unlock()
					}(d.Name)
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(devicePoll):
			}
		}
	}()
	return nil
}

func (b *Backend) follow(ctx context.Context, dev string, fn func(core.WifiEvent)) {
	c, err := b.dial(dev)
	if err != nil {
		return
	}
	defer c.close()
	if _, err := c.request("ATTACH"); err != nil {
		return
	}
	last := core.WifiState(-1)
	report := func() bool {
		r, err := b.do(dev, "STATUS")
		if err != nil {
			return false
		}
		state, ssid := parseStatus(r)
		if state != last {
			last = state
			ev := core.WifiEvent{Device: dev, State: state}
			if state == core.WifiConnected {
				ev.ConnectedSSID = ssid
			}
			fn(ev)
		}
		return true
	}
	if !report() {
		return
	}
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		c.conn.SetReadDeadline(time.Now().Add(devicePoll))
		if _, err := c.conn.Read(buf); err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				return
			}
		}
		if !report() {
			return
		}
	}
}

// profile is a saved network. psk is empty for an open network.
type profile struct{ psk string }

// profileName encodes an SSID the way iwd names its files.
func profileName(ssid []byte) string {
	for _, c := range ssid {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == ' ') {
			return "=" + hexOf(ssid)
		}
	}
	return string(ssid)
}

func (b *Backend) profile(ssid []byte) *profile {
	name := filepath.Join(b.ProfileDir, profileName(ssid))
	if _, err := os.Stat(name + ".open"); err == nil {
		return &profile{}
	}
	data, err := os.ReadFile(name + ".psk")
	if err != nil {
		return nil
	}
	p := &profile{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Passphrase":
			p.psk = strings.TrimSpace(v)
		case "PreSharedKey":
			if p.psk == "" {
				p.psk = strings.TrimSpace(v)
			}
		}
	}
	return p
}

func (b *Backend) saveProfile(ssid []byte, sec core.WifiSecurity, psk string) error {
	if err := os.MkdirAll(b.ProfileDir, 0o700); err != nil {
		return err
	}
	name := filepath.Join(b.ProfileDir, profileName(ssid))
	if sec == core.SecOpen {
		return os.WriteFile(name+".open", nil, 0o600)
	}
	key := "Passphrase"
	if rawPSK.MatchString(psk) {
		key = "PreSharedKey"
	}
	return os.WriteFile(name+".psk", []byte("[Security]\n"+key+"="+psk+"\n"), 0o600)
}
