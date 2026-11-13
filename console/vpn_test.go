package main

import (
	"golang.org/x/sys/windows"
	"net"
	"testing"
)

func TestVPNRejectsOtherNetworksAndAddresses(t *testing.T) {
	v := &vpnNet{ip: net.ParseIP("198.18.0.1")}
	for _, n := range []string{"udp6", "tcp6", "unix"} {
		if _, e := network4(n); e == nil {
			t.Fatal("accepted", n)
		}
	}
	if _, e := v.listenAddress("192.168.3.2:0"); e == nil {
		t.Fatal("accepted non-VPN bind")
	}
	if a, e := v.listenAddress("0.0.0.0:0"); e != nil || a != "198.18.0.1:0" {
		t.Fatal(a, e)
	}
}
func TestMissingVPNFailsClosed(t *testing.T) {
	if _, e := newVPN(VPNConfig{Interface: "nonexistent-snowflake-test"}); e == nil {
		t.Fatal("missing VPN accepted")
	}
}
func TestUDPSocketPinnedToVPN(t *testing.T) {
	cfg, e := loadVPN("D:/snowflake-proxy")
	if e != nil {
		t.Skip(e)
	}
	v, e := newVPN(cfg)
	if e != nil {
		t.Skip(e)
	}
	c, e := v.ListenPacket("udp4", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	udp := c.(*net.UDPConn)
	raw, e := udp.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var index int
	var socketErr error
	raw.Control(func(fd uintptr) { index, socketErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31) })
	// Windows returns this value in host byte order, unlike setsockopt.
	if socketErr != nil || index != v.index {
		t.Fatalf("interface pin mismatch %d %v", index, socketErr)
	}
	if !udp.LocalAddr().(*net.UDPAddr).IP.Equal(v.ip) {
		t.Fatal("wrong local address")
	}
}
