package nmapi

import "github.com/singularityos-lab/sinty-nm/internal/core"

// D-Bus interface names for the object tree, matching NM exactly.
const (
	ifaceDevice     = "org.freedesktop.NetworkManager.Device"
	ifaceWireless   = "org.freedesktop.NetworkManager.Device.Wireless"
	ifaceWired      = "org.freedesktop.NetworkManager.Device.Wired"
	ifaceWireguard  = "org.freedesktop.NetworkManager.Device.WireGuard"
	ifaceAP         = "org.freedesktop.NetworkManager.AccessPoint"
	ifaceSettings   = "org.freedesktop.NetworkManager.Settings"
	ifaceConnection = "org.freedesktop.NetworkManager.Settings.Connection"
	ifaceActive     = "org.freedesktop.NetworkManager.Connection.Active"
	ifaceIP4        = "org.freedesktop.NetworkManager.IP4Config"
	ifaceIP6        = "org.freedesktop.NetworkManager.IP6Config"
)

// NMDeviceType (NM's NMDeviceType enum). Only the kinds we classify are named.
const (
	devTypeUnknown   uint32 = 0
	devTypeEthernet  uint32 = 1
	devTypeWifi      uint32 = 2
	devTypeBridge    uint32 = 13
	devTypeGeneric   uint32 = 14
	devTypeTun       uint32 = 16
	devTypeWireguard uint32 = 29
	devTypeLoopback  uint32 = 32
)

// NMDeviceState (NM's NMDeviceState enum).
const (
	devStateUnknown      uint32 = 0
	devStateUnmanaged    uint32 = 10
	devStateUnavailable  uint32 = 20
	devStateDisconnected uint32 = 30
	devStatePrepare      uint32 = 40
	devStateConfig       uint32 = 50
	devStateNeedAuth     uint32 = 60
	devStateIPConfig     uint32 = 70
	devStateIPCheck      uint32 = 80
	devStateActivated    uint32 = 100
	devStateDeactivating uint32 = 110
	devStateFailed       uint32 = 120
)

// NMDeviceStateReason values we use (0 = none/unknown).
const (
	devReasonNone          uint32 = 0
	devReasonNowManaged    uint32 = 2
	devReasonUserRequested uint32 = 39
)

// NMActiveConnectionState.
const (
	acStateUnknown      uint32 = 0
	acStateActivating   uint32 = 1
	acStateActivated    uint32 = 2
	acStateDeactivating uint32 = 3
	acStateDeactivated  uint32 = 4
)

// NM80211Mode (AP / device wireless mode).
const (
	wifiModeUnknown uint32 = 0
	wifiModeAdhoc   uint32 = 1
	wifiModeInfra   uint32 = 2
	wifiModeAP      uint32 = 3
)

// NM80211ApFlags.
const (
	apFlagNone    uint32 = 0
	apFlagPrivacy uint32 = 0x1
)

// NM80211ApSecurityFlags (subset we emit).
const (
	apSecNone         uint32 = 0x0
	apSecPairWEP40    uint32 = 0x1
	apSecKeyMgmtPSK   uint32 = 0x100
	apSecKeyMgmt8021X uint32 = 0x200
)

// deviceTypeFor maps a core.DeviceKind to NM's NMDeviceType.
func deviceTypeFor(k core.DeviceKind) uint32 {
	switch k {
	case core.KindEthernet:
		return devTypeEthernet
	case core.KindWifi:
		return devTypeWifi
	case core.KindWireGuard:
		return devTypeWireguard
	case core.KindLoopback:
		return devTypeLoopback
	case core.KindBridge:
		return devTypeBridge
	case core.KindTun:
		return devTypeTun
	default:
		return devTypeGeneric
	}
}

// apSecFlags maps a coarse core.WifiSecurity to NM's (flags, wpaFlags, rsnFlags) triple.
// Open networks advertise nothing; PSK sets PRIVACY plus an RSN key-mgmt-PSK bit;
// enterprise uses the 802.1X key-mgmt bit; WEP only sets the PRIVACY flag.
func apSecFlags(s core.WifiSecurity) (flags, wpa, rsn uint32) {
	switch s {
	case core.SecPSK:
		return apFlagPrivacy, apSecNone, apSecKeyMgmtPSK
	case core.SecEnterprise:
		return apFlagPrivacy, apSecNone, apSecKeyMgmt8021X
	case core.SecWEP:
		return apFlagPrivacy, apSecPairWEP40, apSecNone
	default:
		return apFlagNone, apSecNone, apSecNone
	}
}
