package main

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unsafe"
)

const countryEndpoint = "https://ipwho.is/?fields=success,message,ip,country_code&lang=en"
const countryCheckInterval = 5 * time.Minute

type CountryCheck struct {
	VPNCountry    string `json:"vpn_country"`
	DirectCountry string `json:"direct_country"`
	SameCountry   bool   `json:"same_country"`
	SameIP        bool   `json:"same_ip"`
	Error         string `json:"error,omitempty"`
	Checked       string `json:"checked"`
	Verified      bool   `json:"verified"`
	Warning       string `json:"warning,omitempty"`
	directIPs     []net.IP
}
type geoReply struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	IP      string `json:"ip"`
	Country string `json:"country_code"`
}

func lookupCountry(client *http.Client, url string) (geoReply, error) {
	var reply geoReply
	resp, e := client.Get(url)
	if e != nil {
		return reply, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return reply, fmt.Errorf("country lookup HTTP %d", resp.StatusCode)
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&reply); e != nil {
		return reply, e
	}
	if !reply.Success || net.ParseIP(reply.IP).To4() == nil || len(reply.Country) != 2 {
		return reply, fmt.Errorf("country lookup returned incomplete data")
	}
	reply.Country = strings.ToUpper(reply.Country)
	return reply, nil
}
func compareCountries(vpn, direct geoReply) CountryCheck {
	return CountryCheck{VPNCountry: vpn.Country, DirectCountry: direct.Country, SameCountry: vpn.Country == direct.Country, SameIP: net.ParseIP(vpn.IP).Equal(net.ParseIP(direct.IP)), Checked: time.Now().Format(time.RFC3339)}
}
func directAdapter() (adapterInfo, error) {
	list, e := adapters()
	if e != nil {
		return adapterInfo{}, e
	}
	var table *windows.MibIpForwardTable2
	if e = windows.GetIpForwardTable2(windows.AF_INET, &table); e != nil {
		return adapterInfo{}, e
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var best adapterInfo
	var metric uint64 = ^uint64(0)
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		for _, a := range list {
			if !a.up || a.index != row.InterfaceIndex || looksLikeTunnel(a) || (a.kind != 6 && a.kind != 71) {
				continue
			}
			combined := uint64(row.Metric) + uint64(a.metric)
			if combined < metric {
				best = a
				metric = combined
			}
		}
	}
	if best.name == "" {
		return best, fmt.Errorf("no direct Ethernet/Wi-Fi default route")
	}
	return best, nil
}
func directCountryClient() (*http.Client, error) {
	a, e := directAdapter()
	if e != nil {
		return nil, e
	}
	direct, e := newVPN(VPNConfig{Interface: a.name})
	if e != nil {
		return nil, e
	}
	direct.diagnosticOnly = true
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialTLSContext = nil
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		// Only fixed geolocation endpoints are allowed to bypass the tunnel.
		host, port, e := net.SplitHostPort(address)
		if e != nil || (host != "ipwho.is" && host != "www.cloudflare.com") || port != "443" {
			return nil, fmt.Errorf("direct diagnostic destination blocked")
		}
		return direct.DialContext(ctx, network, address)
	}
	tr.ForceAttemptHTTP2 = true
	return &http.Client{Transport: tr, Timeout: 12 * time.Second}, nil
}
func checkCountries(vpn *vpnNet) CountryCheck { return verifyVPN(vpn) }
func (c *Collector) setCountryCheck(s CountryCheck) {
	c.Lock()
	defer c.Unlock()
	c.state.CountryCheck = s
	c.checkPeerPaths()
}

// Caller holds the collector lock. Store only our endpoints, never user IPs.
func (c *Collector) checkPeerPaths() {
	for _, p := range c.paths {
		ip := net.ParseIP(p.LocalIP)
		if ip == nil {
			continue
		}
		if p.CandidateType == "host" && c.vpnIP != nil && !ip.Equal(c.vpnIP) {
			c.pathWarning = "Snowflake/WebRTC selected an interface outside the VPN"
			return
		}
		for _, direct := range c.state.CountryCheck.directIPs {
			if ip.Equal(direct) {
				c.pathWarning = "Snowflake/WebRTC selected the direct public IP"
				return
			}
		}
	}
}
func countryLine(s CountryCheck) string {
	if s.Checked == "" {
		return ""
	}
	if s.Warning != "" {
		return "\x1b[1;31m  WARNING: " + s.Warning + "\x1b[0m"
	}
	if s.Error != "" && !s.SameIP && !s.SameCountry {
		return ""
	}
	if s.SameIP {
		return "\x1b[1;31m  WARNING: VPN and direct public IP are IDENTICAL (" + s.VPNCountry + ")!\x1b[0m"
	}
	if s.SameCountry {
		return "\x1b[1;31m  WARNING: VPN and direct exit countries match (" + s.VPNCountry + ")!\x1b[0m"
	}
	return ""
}
