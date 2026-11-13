package main

import "testing"

func TestProxyStopsOnPositiveRoutingFindings(t *testing.T) {
	good := CountryCheck{Verified: true, VPNCountry: "DE", DirectCountry: "UZ"}
	if r := proxyBlockReason(good, "UZ"); r != "" {
		t.Fatal(r)
	}
	cases := []CountryCheck{{SameCountry: true}, {SameIP: true}, {Warning: "WebRTC selected direct path"}, {VPNCountry: "UZ"}}
	for _, s := range cases {
		if proxyBlockReason(s, "UZ") == "" {
			t.Fatalf("unsafe state authorized: %+v", s)
		}
	}
}

func TestUnavailableCountryServicesDoNotStopProxy(t *testing.T) {
	for _, s := range []CountryCheck{{}, {Verified: false, Error: "HTTPS country probe"}, {Verified: false, VPNCountry: "DE", Error: "direct check blocked"}} {
		if reason := proxyBlockReason(s, "UZ"); reason != "" {
			t.Fatalf("inconclusive result treated as a leak: %s", reason)
		}
	}
}
