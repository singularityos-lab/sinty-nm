package sys

import (
	"os"
	"path/filepath"

	ss "github.com/singularityos-lab/libsingularity/src/system/core/go/sintysystem"
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

// SetWifiPowerSave turns power saving on or off on every wireless interface.
func SetWifiPowerSave(on bool) error {
	var first error
	for _, name := range wirelessInterfaces() {
		if err := ss.WifiSetPowerSave(name, on); err != nil && first == nil {
			first = err
		}
	}
	return first
}
