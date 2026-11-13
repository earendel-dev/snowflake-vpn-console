package main

import (
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	"net"
	"strings"
	"testing"
)

func TestIPv6PolicyBlocksTCPAndUDP(t *testing.T) {
	if !verifyIPv6Blocked(&vpnNet{}) {
		t.Fatal("IPv6 policy is not enforced")
	}
}
func TestRealSnowflakePathWarning(t *testing.T) {
	c := &Collector{vpnIP: net.ParseIP("198.18.0.1")}
	c.OnNewSnowflakeEvent(event.EventOnProxyPeerPath{LocalIP: "198.18.0.1", CandidateType: "host"})
	if countryLine(c.snapshot().CountryCheck) != "" {
		t.Fatal("unexpected warning for VPN host path")
	}
	c.OnNewSnowflakeEvent(event.EventOnProxyPeerPath{LocalIP: "192.168.3.10", CandidateType: "host"})
	if !strings.Contains(countryLine(c.snapshot().CountryCheck), "\x1b[1;31m") {
		t.Fatal("missing red warning")
	}
}
func TestRealSnowflakeDirectPublicIP(t *testing.T) {
	c := &Collector{vpnIP: net.ParseIP("198.18.0.1")}
	c.OnNewSnowflakeEvent(event.EventOnProxyPeerPath{LocalIP: "192.0.2.1", CandidateType: "srflx"})
	c.setCountryCheck(CountryCheck{directIPs: []net.IP{net.ParseIP("192.0.2.1")}})
	if !strings.Contains(countryLine(c.snapshot().CountryCheck), "direct public IP") {
		t.Fatal("direct WebRTC IP was not flagged")
	}
}
func TestNoPositiveSecurityMessage(t *testing.T) {
	if countryLine(CountryCheck{Checked: "now", Verified: true, VPNCountry: "US", DirectCountry: "DE"}) != "" {
		t.Fatal("positive status should be hidden")
	}
}
