package nmapi

import "github.com/singularityos-lab/sinty-nm/internal/core"

// setCarrier publishes the wired Carrier property from a link event. Kept separate so the
// ethernet-specific surface stays out of the generic device path.
func (d *Device) setCarrier(up bool) {
	if d.kind != core.KindEthernet || d.props == nil {
		return
	}
	d.props.SetMust(ifaceWired, "Carrier", up)
}
