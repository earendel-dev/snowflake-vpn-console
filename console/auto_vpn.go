package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"regexp"
	"strings"
	"unsafe"
)

type adapterInfo struct {
	index             uint32
	name, description string
	kind              uint32
	up                bool
	dns               string
	metric            uint32
}

var tunnelName = regexp.MustCompile(`(?i)(^|[ _-])(tun|tap|wg|vpn)([ _-]|[0-9]|$)`)

func looksLikeTunnel(a adapterInfo) bool {
	if a.kind == 23 || a.kind == 131 {
		return true
	} // PPP and tunnel interfaces.
	text := strings.ToLower(a.description + " " + a.name)
	for _, marker := range []string{"wintun", "wireguard", "tap-windows", "openvpn", "vpn", "nordlynx", "tailscale", "zerotier"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return tunnelName.MatchString(text)
}
func adapters() ([]adapterInfo, error) {
	size := uint32(15000)
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		e := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, first, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			return nil, e
		}
		var result []adapterInfo
		for a := first; a != nil; a = a.Next {
			info := adapterInfo{index: a.IfIndex, name: windows.UTF16PtrToString(a.FriendlyName), description: windows.UTF16PtrToString(a.Description), kind: a.IfType, up: a.OperStatus == 1, metric: a.Ipv4Metric}
			for dns := a.FirstDnsServerAddress; dns != nil; dns = dns.Next {
				ip := dns.Address.IP().To4()
				if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
					info.dns = ip.String()
					break
				}
			}
			result = append(result, info)
		}
		return result, nil
	}
	return nil, fmt.Errorf("unable to enumerate network adapters")
}
func publicRouteIndex() (uint32, error) {
	var first, second uint32
	if e := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &first); e != nil {
		return 0, e
	}
	if e := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}}, &second); e != nil {
		return 0, e
	}
	if first != second {
		return 0, fmt.Errorf("public routes use different adapters; VPN-only mode requires a consistent tunnel route")
	}
	return first, nil
}
func selectTunnel(list []adapterInfo, route uint32, requested string) (adapterInfo, error) {
	for _, a := range list {
		if !a.up || a.index != route || !looksLikeTunnel(a) {
			continue
		}
		if requested != "" && requested != "auto" && !strings.EqualFold(requested, a.name) {
			continue
		}
		return a, nil
	}
	return adapterInfo{}, fmt.Errorf("no active VPN tunnel carrying public traffic; connect a VPN in tunnel mode and restart")
}
func resolveVPNConfig(cfg VPNConfig) (VPNConfig, error) {
	list, e := adapters()
	if e != nil {
		return cfg, e
	}
	route, e := publicRouteIndex()
	if e != nil {
		return cfg, e
	}
	a, e := selectTunnel(list, route, cfg.Interface)
	if e != nil {
		return cfg, e
	}
	cfg.Interface = a.name
	if cfg.DNS == "" || cfg.DNS == "auto" {
		cfg.DNS = a.dns
		if cfg.DNS == "" {
			cfg.DNS = "1.1.1.1"
		}
	}
	if net.ParseIP(cfg.DNS).To4() == nil {
		return cfg, fmt.Errorf("VPN DNS discovery did not return an IPv4 address")
	}
	return cfg, nil
}
