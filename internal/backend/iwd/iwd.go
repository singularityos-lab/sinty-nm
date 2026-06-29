package iwd

import (
	"context"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// Dest is the iwd well-known bus name (system bus).
const Dest = "net.connman.iwd"

const (
	ifaceObjectManager = "org.freedesktop.DBus.ObjectManager"
	ifaceProps         = "org.freedesktop.DBus.Properties"

	ifaceDevice       = "net.connman.iwd.Device"
	ifaceStation      = "net.connman.iwd.Station"
	ifaceNetwork      = "net.connman.iwd.Network"
	ifaceKnownNetwork = "net.connman.iwd.KnownNetwork"
	ifaceAgentManager = "net.connman.iwd.AgentManager"
	ifaceAgent        = "net.connman.iwd.Agent"

	agentManagerPath = dbus.ObjectPath("/net/connman/iwd")
	agentPath        = dbus.ObjectPath("/io/sinty/nm/iwd/agent")
)

// managedObjects is the shape returned by ObjectManager.GetManagedObjects:
// object path -> interface name -> property name -> value.
type managedObjects map[dbus.ObjectPath]map[string]map[string]dbus.Variant

// Backend holds the system-bus connection to iwd and the secret agent.
type Backend struct {
	conn  *dbus.Conn
	agent *agent
}

// New builds the backend and registers the secret agent with iwd. If iwd is not yet on
// the bus the agent registration is skipped silently; the backend then reports empty
// lists until iwd appears, rather than failing.
func New(conn *dbus.Conn) (*Backend, error) {
	b := &Backend{
		conn:  conn,
		agent: &agent{pending: make(map[dbus.ObjectPath]func() (string, error))},
	}
	// A failure here is almost always "iwd not on the bus yet"; not fatal.
	_ = b.registerAgent()
	return b, nil
}

func (b *Backend) registerAgent() error {
	if err := b.conn.Export(b.agent, agentPath, ifaceAgent); err != nil {
		return err
	}
	return b.conn.Object(Dest, agentManagerPath).
		Call(ifaceAgentManager+".RegisterAgent", 0, agentPath).Err
}

// objects returns the full iwd object tree, or an empty map if iwd is unreachable.
func (b *Backend) objects() managedObjects {
	var objs managedObjects
	err := b.conn.Object(Dest, "/").
		Call(ifaceObjectManager+".GetManagedObjects", 0).Store(&objs)
	if err != nil {
		return managedObjects{}
	}
	return objs
}

// ListDevices enumerates every net.connman.iwd.Device. It returns an empty slice (no
// error) when iwd is absent, so the manager keeps running until iwd shows up.
func (b *Backend) ListDevices() ([]core.WifiDevice, error) {
	var out []core.WifiDevice
	for path, ifaces := range b.objects() {
		props, ok := ifaces[ifaceDevice]
		if !ok {
			continue
		}
		out = append(out, core.WifiDevice{
			Name:    variantString(props["Name"]),
			Powered: variantBool(props["Powered"]),
			Handle:  string(path),
		})
	}
	return out, nil
}

// SetPowered toggles the Device.Powered property.
func (b *Backend) SetPowered(dev string, on bool) error {
	return b.conn.Object(Dest, dbus.ObjectPath(dev)).
		SetProperty(ifaceDevice+".Powered", dbus.MakeVariant(on))
}

// Scan triggers a Station scan; results are read later via OrderedNetworks.
func (b *Backend) Scan(dev string) error {
	return b.conn.Object(Dest, dbus.ObjectPath(dev)).Call(ifaceStation+".Scan", 0).Err
}

// orderedNetwork is one entry of Station.GetOrderedNetworks: (network path, signal).
type orderedNetwork struct {
	Path   dbus.ObjectPath
	Signal int16
}

// OrderedNetworks returns the device's visible networks, iwd-ranked best first.
func (b *Backend) OrderedNetworks(dev string) ([]core.ScannedAP, error) {
	var ranked []orderedNetwork
	err := b.conn.Object(Dest, dbus.ObjectPath(dev)).
		Call(ifaceStation+".GetOrderedNetworks", 0).Store(&ranked)
	if err != nil {
		return nil, err
	}
	objs := b.objects()
	out := make([]core.ScannedAP, 0, len(ranked))
	for _, n := range ranked {
		props := objs[n.Path][ifaceNetwork]
		out = append(out, core.ScannedAP{
			SSID:     []byte(variantString(props["Name"])),
			Strength: signalToPercent(n.Signal),
			Security: securityOf(variantString(props["Type"])),
			Known:    variantPath(props["KnownNetwork"]) != "",
			Handle:   string(n.Path),
		})
	}
	return out, nil
}

// Connect associates the device with the named network. For a PSK network iwd calls
// back into our agent for the passphrase; we key the SecretFunc by the network path so
// the callback resolves the right secret. Network.Connect blocks until iwd is associated
// or returns an error.
func (b *Backend) Connect(dev string, ssid []byte, secret core.SecretFunc) error {
	netPath, err := b.findNetwork(dev, ssid)
	if err != nil {
		return err
	}
	b.agent.set(netPath, func() (string, error) { return secret(ssid) })
	defer b.agent.clear(netPath)
	return b.conn.Object(Dest, netPath).Call(ifaceNetwork+".Connect", 0).Err
}

// Disconnect tears down the current association on the device's Station.
func (b *Backend) Disconnect(dev string) error {
	return b.conn.Object(Dest, dbus.ObjectPath(dev)).Call(ifaceStation+".Disconnect", 0).Err
}

// Forget removes the saved profile for ssid by calling Forget on its KnownNetwork.
func (b *Backend) Forget(dev string, ssid []byte) error {
	netPath, err := b.findNetwork(dev, ssid)
	if err != nil {
		return err
	}
	known := variantPath(b.objects()[netPath][ifaceNetwork]["KnownNetwork"])
	if known == "" {
		return fmt.Errorf("iwd: %q is not a known network", string(ssid))
	}
	return b.conn.Object(Dest, known).Call(ifaceKnownNetwork+".Forget", 0).Err
}

// State reports the device's Station.State, normalized.
func (b *Backend) State(dev string) (core.WifiState, error) {
	v, err := b.conn.Object(Dest, dbus.ObjectPath(dev)).GetProperty(ifaceStation + ".State")
	if err != nil {
		return core.WifiDisconnected, err
	}
	return stateOf(variantString(v)), nil
}

// Subscribe watches Station.State changes (and interface add/remove) and pushes a
// WifiEvent per change until ctx is cancelled.
func (b *Backend) Subscribe(ctx context.Context, fn func(core.WifiEvent)) error {
	matches := []dbus.MatchOption{
		dbus.WithMatchInterface(ifaceProps),
		dbus.WithMatchMember("PropertiesChanged"),
	}
	if err := b.conn.AddMatchSignal(matches...); err != nil {
		return err
	}
	added := []dbus.MatchOption{dbus.WithMatchInterface(ifaceObjectManager)}
	_ = b.conn.AddMatchSignal(added...)

	ch := make(chan *dbus.Signal, 16)
	b.conn.Signal(ch)
	go func() {
		defer func() {
			b.conn.RemoveSignal(ch)
			_ = b.conn.RemoveMatchSignal(matches...)
			_ = b.conn.RemoveMatchSignal(added...)
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case sig, ok := <-ch:
				if !ok {
					return
				}
				b.dispatch(sig, fn)
			}
		}
	}()
	return nil
}

// dispatch turns a raw D-Bus signal into a WifiEvent when it is a Station state change or
// a newly added Station interface.
func (b *Backend) dispatch(sig *dbus.Signal, fn func(core.WifiEvent)) {
	switch sig.Name {
	case ifaceProps + ".PropertiesChanged":
		if len(sig.Body) < 2 {
			return
		}
		iface, _ := sig.Body[0].(string)
		if iface != ifaceStation {
			return
		}
		changed, _ := sig.Body[1].(map[string]dbus.Variant)
		state, ok := changed["State"]
		if !ok {
			return
		}
		b.emit(fn, string(sig.Path), variantString(state))
	case ifaceObjectManager + ".InterfacesAdded":
		if len(sig.Body) < 2 {
			return
		}
		path, _ := sig.Body[0].(dbus.ObjectPath)
		ifaces, _ := sig.Body[1].(map[string]map[string]dbus.Variant)
		if props, ok := ifaces[ifaceStation]; ok {
			b.emit(fn, string(path), variantString(props["State"]))
		}
	}
}

func (b *Backend) emit(fn func(core.WifiEvent), dev, rawState string) {
	ev := core.WifiEvent{Device: dev, State: stateOf(rawState)}
	if ev.State == core.WifiConnected {
		ev.ConnectedSSID = b.connectedSSID(dbus.ObjectPath(dev))
	}
	fn(ev)
}

// connectedSSID reads Station.ConnectedNetwork then that network's Name.
func (b *Backend) connectedSSID(dev dbus.ObjectPath) []byte {
	v, err := b.conn.Object(Dest, dev).GetProperty(ifaceStation + ".ConnectedNetwork")
	if err != nil {
		return nil
	}
	netPath := variantPath(v)
	if netPath == "" {
		return nil
	}
	name, err := b.conn.Object(Dest, netPath).GetProperty(ifaceNetwork + ".Name")
	if err != nil {
		return nil
	}
	return []byte(variantString(name))
}

// findNetwork locates the Network object on dev whose SSID matches ssid.
func (b *Backend) findNetwork(dev string, ssid []byte) (dbus.ObjectPath, error) {
	want := string(ssid)
	for path, ifaces := range b.objects() {
		props, ok := ifaces[ifaceNetwork]
		if !ok {
			continue
		}
		if variantPath(props["Device"]) != dbus.ObjectPath(dev) {
			continue
		}
		if variantString(props["Name"]) == want {
			return path, nil
		}
	}
	return "", fmt.Errorf("iwd: network %q not found on %s", want, dev)
}

// agent is the exported net.connman.iwd.Agent. iwd invokes it to obtain secrets during
// Network.Connect; pending maps an in-flight network path to its SecretFunc closure.
type agent struct {
	mu      sync.Mutex
	pending map[dbus.ObjectPath]func() (string, error)
}

func (a *agent) set(net dbus.ObjectPath, fn func() (string, error)) {
	a.mu.Lock()
	a.pending[net] = fn
	a.mu.Unlock()
}

func (a *agent) clear(net dbus.ObjectPath) {
	a.mu.Lock()
	delete(a.pending, net)
	a.mu.Unlock()
}

// RequestPassphrase resolves the PSK for net through the SecretFunc registered by Connect.
func (a *agent) RequestPassphrase(net dbus.ObjectPath) (string, *dbus.Error) {
	a.mu.Lock()
	fn := a.pending[net]
	a.mu.Unlock()
	if fn == nil {
		return "", dbus.NewError(ifaceAgent+".Error.Canceled", []interface{}{"no secret provider"})
	}
	secret, err := fn()
	if err != nil {
		return "", dbus.NewError(ifaceAgent+".Error.Canceled", []interface{}{err.Error()})
	}
	return secret, nil
}

// RequestPrivateKeyPassphrase is an EAP path we do not support yet.
func (a *agent) RequestPrivateKeyPassphrase(net dbus.ObjectPath) (string, *dbus.Error) {
	return "", errNotSupported()
}

// RequestUserNameAndPassword is an EAP path we do not support yet.
func (a *agent) RequestUserNameAndPassword(net dbus.ObjectPath) (string, string, *dbus.Error) {
	return "", "", errNotSupported()
}

// Release is called by iwd when the agent is unregistered.
func (a *agent) Release() *dbus.Error { return nil }

// Cancel is called by iwd when a pending request is aborted.
func (a *agent) Cancel(reason string) *dbus.Error { return nil }

func errNotSupported() *dbus.Error {
	return dbus.NewError(ifaceAgent+".Error.NotSupported", nil)
}

// signalToPercent converts iwd's signal (units of 100*dBm) to a 0..100 quality:
// dBm = signal/100, quality = clamp(2*(dBm+100), 0, 100).
func signalToPercent(signal int16) uint8 {
	q := 2 * (int(signal)/100 + 100)
	if q < 0 {
		q = 0
	}
	if q > 100 {
		q = 100
	}
	return uint8(q)
}

func securityOf(t string) core.WifiSecurity {
	switch t {
	case "wep":
		return core.SecWEP
	case "psk":
		return core.SecPSK
	case "8021x":
		return core.SecEnterprise
	default:
		return core.SecOpen
	}
}

func stateOf(s string) core.WifiState {
	switch s {
	case "connected":
		return core.WifiConnected
	case "connecting":
		return core.WifiConnecting
	case "disconnecting":
		return core.WifiDisconnecting
	default:
		return core.WifiDisconnected
	}
}

func variantString(v dbus.Variant) string {
	s, _ := v.Value().(string)
	return s
}

func variantBool(v dbus.Variant) bool {
	b, _ := v.Value().(bool)
	return b
}

func variantPath(v dbus.Variant) dbus.ObjectPath {
	p, _ := v.Value().(dbus.ObjectPath)
	return p
}
