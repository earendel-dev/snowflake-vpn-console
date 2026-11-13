package main

import "strings"

func countryRecoveryPassed(s CountryCheck) bool {
	return s.Verified && s.Error == "" && len(s.VPNCountry) == 2 && len(s.DirectCountry) == 2 && proxyBlockReason(s, "") == ""
}

// A previously detected egress violation requires a successful country recheck.
// Ordinary tunnel loss still requires fresh discovery and Snowflake's NAT probe.
func needsCountryRecheck(reason string) bool {
	reason = strings.ToLower(reason)
	for _, marker := range []string{"country", "public ip", "direct path", "outside the vpn"} {
		if strings.Contains(reason, marker) {
			return true
		}
	}
	return false
}
