package main

import (
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/event"
	"testing"
	"time"
)

func TestConnectionAndTrafficAccounting(t *testing.T) {
	c := &Collector{}
	c.OnNewSnowflakeEvent(event.EventOnProxyClientConnected{})
	c.OnNewSnowflakeEvent(event.EventOnProxyClientConnected{})
	c.OnNewSnowflakeEvent(event.EventOnProxyConnectionOver{Duration: 45 * time.Second})
	c.OnNewSnowflakeEvent(event.EventOnProxyConnectionFailed{})
	c.OnNewSnowflakeEvent(event.EventOnProxyStats{RawInboundBytes: 987, RawOutboundBytes: 1234})
	s := c.snapshot()
	if s.Active != 1 || s.Connections != 2 || s.Failed != 1 || s.InBytes != 987 || s.OutBytes != 1234 {
		t.Fatalf("wrong counters: %+v", s)
	}
	if s.LastDuration != 45 || s.MaxDuration != 45 || s.Closed != 1 {
		t.Fatalf("wrong duration: %+v", s)
	}
}
func TestTotalsSurviveWorkerRestart(t *testing.T) {
	saved := Saved{Connections: 8, InBytes: 100}
	prev := Snapshot{}
	addSnapshot(&saved, &prev, Snapshot{Connections: 2, InBytes: 35})
	addSnapshot(&saved, &prev, Snapshot{Connections: 3, InBytes: 90})
	prev = Snapshot{}
	addSnapshot(&saved, &prev, Snapshot{Connections: 1, InBytes: 11})
	if saved.Connections != 12 || saved.InBytes != 201 {
		t.Fatalf("wrong totals: %+v", saved)
	}
}
func TestLimitValidation(t *testing.T) {
	for _, s := range []string{"0", "-1", "1001", "abc", ""} {
		if _, e := validLimit(s); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	for _, s := range []string{"1", "10", "100", "1000"} {
		if _, e := validLimit(s); e != nil {
			t.Fatal(e)
		}
	}
}
