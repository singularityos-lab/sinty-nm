package iwd

import (
	"testing"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

func TestRoamingKeepsTheStationConnected(t *testing.T) {
	cases := map[string]core.WifiState{
		"connected":     core.WifiConnected,
		"roaming":       core.WifiConnected,
		"connecting":    core.WifiConnecting,
		"disconnecting": core.WifiDisconnecting,
		"disconnected":  core.WifiDisconnected,
	}
	for raw, want := range cases {
		if got := stateOf(raw); got != want {
			t.Fatalf("stateOf(%q) = %v, want %v", raw, got, want)
		}
	}
}
