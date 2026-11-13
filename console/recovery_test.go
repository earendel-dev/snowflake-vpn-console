package main

import "testing"

func TestCountryRecoveryRequiresSuccessfulRecheck(t *testing.T) {
	good := CountryCheck{Verified: true, VPNCountry: "DE", DirectCountry: "UZ"}
	if !countryRecoveryPassed(good) {
		t.Fatal("valid recovery rejected")
	}
	for _, s := range []CountryCheck{{}, {Verified: true, SameCountry: true}, {Verified: true, VPNCountry: "DE", DirectCountry: "UZ", Error: "timeout"}} {
		if countryRecoveryPassed(s) {
			t.Fatal("incomplete or unsafe recovery accepted")
		}
	}
}
func TestRecoveryRechecksEgressViolations(t *testing.T) {
	for _, s := range []string{"VPN exit country matches the start country", "WebRTC selected the direct public IP", "Exit-country recheck incomplete", "selected an interface outside the VPN"} {
		if !needsCountryRecheck(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"VPN interface or route disappeared", "NAT connectivity check failed"} {
		if needsCountryRecheck(s) {
			t.Fatal(s)
		}
	}
}
