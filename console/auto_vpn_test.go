package main

import "testing"

func TestTunnelSelectionFailsClosed(t *testing.T) {
	list := []adapterInfo{{index: 1, name: "Ethernet", description: "Realtek PCIe", kind: 6, up: true}, {index: 7, name: "tun_incy", description: "Wintun Tunnel", kind: 6, up: true}}
	if _, e := selectTunnel(list, 1, "auto"); e == nil {
		t.Fatal("physical internet route accepted")
	}
	if a, e := selectTunnel(list, 7, "auto"); e != nil || a.name != "tun_incy" {
		t.Fatal(a, e)
	}
	list[1].up = false
	if _, e := selectTunnel(list, 7, "auto"); e == nil {
		t.Fatal("disconnected tunnel accepted")
	}
}
func TestTunnelSelectionSupportsDifferentNames(t *testing.T) {
	for _, a := range []adapterInfo{{name: "Example", kind: 131}, {name: "Example", kind: 23}, {name: "Proton", description: "WireGuard Tunnel"}, {name: "OpenVPN", description: "TAP-Windows Adapter V9"}, {name: "New VPN", description: "Virtual VPN Adapter"}} {
		a.index = 3
		a.up = true
		if _, e := selectTunnel([]adapterInfo{a}, 3, "auto"); e != nil {
			t.Fatal(a, e)
		}
	}
}
