package sys

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const (
	nl80211CmdSetPowerSave = 61
	nl80211AttrIfindex     = 3
	nl80211AttrPSState     = 93
)

var netClass = "/sys/class/net"

func wirelessInterfaces() []string {
	var out []string
	dirs, _ := filepath.Glob(filepath.Join(netClass, "*"))
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, "wireless")); err == nil {
			out = append(out, filepath.Base(d))
		}
	}
	return out
}

func powerSaveRequest(family uint16, version uint8, ifindex int, on bool) (genetlink.Message, error) {
	state := uint32(0)
	if on {
		state = 1
	}
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(nl80211AttrIfindex, uint32(ifindex))
	ae.Uint32(nl80211AttrPSState, state)
	data, err := ae.Encode()
	if err != nil {
		return genetlink.Message{}, err
	}
	return genetlink.Message{
		Header: genetlink.Header{Command: nl80211CmdSetPowerSave, Version: version},
		Data:   data,
	}, nil
}

// SetWifiPowerSave turns power saving on or off on every wireless interface.
func SetWifiPowerSave(on bool) error {
	ifaces := wirelessInterfaces()
	if len(ifaces) == 0 {
		return nil
	}
	c, err := genetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer c.Close()
	family, err := c.GetFamily("nl80211")
	if err != nil {
		return err
	}
	var first error
	for _, name := range ifaces {
		idx, err := ifindex(name)
		if err != nil {
			continue
		}
		msg, err := powerSaveRequest(family.ID, family.Version, idx, on)
		if err == nil {
			_, err = c.Execute(msg, family.ID, netlink.Request|netlink.Acknowledge)
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

func ifindex(name string) (int, error) {
	data, err := os.ReadFile(filepath.Join(netClass, name, "ifindex"))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
