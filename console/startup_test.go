package main

import (
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	sf "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/proxy/lib"
	"strings"
	"testing"
)

func TestNATProbeFailureBlocksStartup(t *testing.T) {
	p := sf.SnowflakeProxy{EventDispatcher: event.NewSnowflakeEventDispatcher(), NATProbeURL: "://invalid", RequireKnownNAT: true, RelayDomainNamePattern: "snowflake.torproject.net$"}
	err := p.Start()
	if err == nil || !strings.Contains(err.Error(), "NAT connectivity check failed; proxy blocked") {
		t.Fatalf("startup was not blocked: %v", err)
	}
}
