package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/pion/stun/v3"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func lookupTrace(client *http.Client) (geoReply, error) {
	var result geoReply
	resp, e := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if e != nil {
		return result, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return result, fmt.Errorf("trace HTTP %d", resp.StatusCode)
	}
	scan := bufio.NewScanner(io.LimitReader(resp.Body, 16384))
	for scan.Scan() {
		key, value, ok := strings.Cut(scan.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "ip":
			result.IP = value
		case "loc":
			result.Country = strings.ToUpper(value)
		}
	}
	if scan.Err() != nil || net.ParseIP(result.IP).To4() == nil || len(result.Country) != 2 {
		return result, fmt.Errorf("incomplete IPv4 trace")
	}
	result.Success = true
	return result, nil
}
func verifyIPv6Blocked(v *vpnNet) bool {
	c, e := v.DialContext(context.Background(), "tcp6", "[2606:4700:4700::1111]:443")
	if c != nil {
		c.Close()
	}
	if !errors.Is(e, errIPv6Blocked) {
		return false
	}
	p, e := v.ListenPacket("udp6", "[::]:0")
	if p != nil {
		p.Close()
	}
	return errors.Is(e, errIPv6Blocked)
}
func stunExit(v *vpnNet, server string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, e := v.DialContext(ctx, "udp4", server)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, e = c.Write(request.Raw); e != nil {
		return nil, e
	}
	buf := make([]byte, 2048)
	n, e := c.Read(buf)
	if e != nil {
		return nil, e
	}
	response := &stun.Message{Raw: buf[:n]}
	if e = response.Decode(); e != nil {
		return nil, e
	}
	if response.TransactionID != request.TransactionID || response.Type != stun.BindingSuccess {
		return nil, fmt.Errorf("invalid STUN response")
	}
	var address stun.XORMappedAddress
	if e = address.GetFrom(response); e != nil {
		return nil, e
	}
	if address.IP.To4() == nil {
		return nil, fmt.Errorf("STUN did not return IPv4")
	}
	return address.IP, nil
}
func ipMatches(ip net.IP, replies []geoReply) bool {
	for _, r := range replies {
		if ip.Equal(net.ParseIP(r.IP)) {
			return true
		}
	}
	return false
}
func verifyVPN(v *vpnNet) CountryCheck {
	result := CountryCheck{Checked: time.Now().Format(time.RFC3339)}
	incomplete := []string{}
	if e := v.alive(); e != nil {
		result.Warning = "VPN interface or public route changed"
		return result
	}
	if !verifyIPv6Blocked(v) {
		result.Warning = "IPv6 TCP/UDP blocking could not be confirmed"
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", "www.google.com")
	cancel()
	if e != nil || len(ips) == 0 {
		incomplete = append(incomplete, "DNS")
	}
	vpnClient := &http.Client{Timeout: 12 * time.Second}
	directClient, directErr := directCountryClient()
	if directErr != nil {
		incomplete = append(incomplete, "direct route")
	}
	if directClient != nil {
		if tr, ok := directClient.Transport.(*http.Transport); ok {
			defer tr.CloseIdleConnections()
		}
	}
	type probe struct {
		direct bool
		reply  geoReply
		err    error
	}
	results := make(chan probe, 4)
	count := 0
	for _, isDirect := range []bool{false, true} {
		client := vpnClient
		if isDirect {
			client = directClient
		}
		if client == nil {
			continue
		}
		for _, trace := range []bool{false, true} {
			count++
			go func(direct, trace bool, client *http.Client) {
				var r geoReply
				var e error
				if trace {
					r, e = lookupTrace(client)
				} else {
					r, e = lookupCountry(client, countryEndpoint)
				}
				results <- probe{direct, r, e}
			}(isDirect, trace, client)
		}
	}
	var vpnReplies, directReplies []geoReply
	for i := 0; i < count; i++ {
		p := <-results
		if p.err != nil {
			incomplete = append(incomplete, "HTTPS country probe")
			continue
		}
		if p.direct {
			directReplies = append(directReplies, p.reply)
		} else {
			vpnReplies = append(vpnReplies, p.reply)
		}
	}
	for _, r := range directReplies {
		result.directIPs = append(result.directIPs, net.ParseIP(r.IP))
	}
	for _, group := range [][]geoReply{vpnReplies, directReplies} {
		for _, r := range group {
			if len(group) > 0 && r.Country != group[0].Country {
				incomplete = append(incomplete, "country services disagree")
			}
		}
	}
	for _, a := range vpnReplies {
		result.VPNCountry = a.Country
		for _, b := range directReplies {
			result.DirectCountry = b.Country
			if net.ParseIP(a.IP).Equal(net.ParseIP(b.IP)) {
				result.SameIP = true
			}
			if a.Country == b.Country {
				result.SameCountry = true
			}
		}
	}
	if len(vpnReplies) < 2 || len(directReplies) < 2 {
		incomplete = append(incomplete, "multi-site comparison")
	}
	// A third independent HTTPS destination checks general TCP/TLS reachability.
	resp, e := vpnClient.Get("https://www.google.com/generate_204")
	if e != nil {
		incomplete = append(incomplete, "Google HTTPS")
	} else {
		resp.Body.Close()
		if resp.StatusCode != 204 {
			incomplete = append(incomplete, "Google HTTPS")
		}
	}
	for _, server := range []string{"stun.l.google.com:19302", "stun.voip.blackberry.com:3478"} {
		ip, e := stunExit(v, server)
		if e != nil {
			incomplete = append(incomplete, "UDP/STUN")
			continue
		}
		if ipMatches(ip, directReplies) {
			result.Warning = "UDP/STUN exit IP matches the direct connection"
			continue
		}
		if !ipMatches(ip, vpnReplies) {
			r, e := lookupCountry(vpnClient, "https://ipwho.is/"+ip.String()+"?fields=success,message,ip,country_code&lang=en")
			if e != nil {
				incomplete = append(incomplete, "UDP exit country")
				continue
			}
			for _, d := range directReplies {
				if r.Country == d.Country {
					result.Warning = "UDP/STUN exit country matches the direct connection"
				}
			}
		}
	}
	if e = v.alive(); e != nil {
		result.Warning = "VPN route changed during verification"
	}
	result.Error = strings.Join(incomplete, ", ")
	result.Verified = len(incomplete) == 0
	return result
}

// External probe failures are inconclusive, not evidence of direct routing.
// Tunnel/interface enforcement is independent of these geolocation services.
func proxyBlockReason(s CountryCheck, startCountry string) string {
	if s.Warning != "" {
		return s.Warning
	}
	if s.SameIP {
		return "Proxy stopped: VPN and direct public IP are identical"
	}
	if s.SameCountry {
		return "Proxy stopped: VPN exit country matches the start country"
	}
	if startCountry != "" && s.VPNCountry == startCountry {
		return "Proxy stopped: exit country matches the start country"
	}
	return ""
}
