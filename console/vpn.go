package main

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/stdnet"
	"golang.org/x/sys/windows"
)

type VPNConfig struct {
	Interface string `json:"interface"`
	DNS       string `json:"dns"`
}
type vpnNet struct {
	transport.Net
	name  string
	index int
	ip    net.IP
	// Only the country-check HTTP client may bypass the VPN route check.
	diagnosticOnly bool
}

func loadVPN(_ string) (VPNConfig, error) {
	return resolveVPNConfig(VPNConfig{Interface: "auto", DNS: "auto"})
}
func newVPN(cfg VPNConfig) (*vpnNet, error) {
	iface, e := net.InterfaceByName(cfg.Interface)
	if e != nil {
		return nil, fmt.Errorf("VPN interface %s unavailable: %w", cfg.Interface, e)
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("VPN interface %s is down", cfg.Interface)
	}
	addresses, e := iface.Addrs()
	if e != nil {
		return nil, e
	}
	var ip net.IP
	for _, a := range addresses {
		v, _, _ := net.ParseCIDR(a.String())
		if v.To4() != nil {
			ip = v.To4()
			break
		}
	}
	if ip == nil {
		return nil, fmt.Errorf("VPN interface has no IPv4 address")
	}
	base, e := stdnet.NewNet()
	if e != nil {
		return nil, e
	}
	return &vpnNet{Net: base, name: cfg.Interface, index: iface.Index, ip: ip}, nil
}
func (v *vpnNet) alive() error {
	if !v.diagnosticOnly {
		route, e := publicRouteIndex()
		if e != nil || route != uint32(v.index) {
			return fmt.Errorf("VPN route disappeared or changed; direct connections blocked")
		}
	}
	iface, e := net.InterfaceByName(v.name)
	if e != nil || iface.Index != v.index || iface.Flags&net.FlagUp == 0 {
		return fmt.Errorf("VPN disconnected or changed; direct connections blocked")
	}
	addrs, e := iface.Addrs()
	if e != nil {
		return e
	}
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if v.ip.Equal(ip) {
			return nil
		}
	}
	return fmt.Errorf("VPN address changed; restart the application")
}

// Windows IP_UNICAST_IF takes the index in network byte order (option 31).
// Pinning both the outgoing interface and local address prevents route fallback.
func (v *vpnNet) control(network, address string, raw syscall.RawConn) error {
	if e := v.alive(); e != nil {
		return e
	}
	if strings.HasSuffix(network, "6") {
		return fmt.Errorf("IPv6 disabled in VPN-only mode")
	}
	var socketErr error
	if e := raw.Control(func(fd uintptr) {
		socketErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(uint32(v.index))))
	}); e != nil {
		return e
	}
	return socketErr
}

var errIPv6Blocked = errors.New("IPv6 disabled by VPN-only policy")

func network4(network string) (string, error) {
	switch network {
	case "tcp6", "udp6":
		return "", errIPv6Blocked
	case "tcp", "tcp4":
		return "tcp4", nil
	case "udp", "udp4":
		return "udp4", nil
	default:
		return "", fmt.Errorf("network %s blocked in VPN-only mode", network)
	}
}
func (v *vpnNet) dialer(network string, local net.Addr) (*net.Dialer, string, error) {
	n, e := network4(network)
	if e != nil {
		return nil, "", e
	}
	d := &net.Dialer{Timeout: 20 * time.Second, Control: v.control}
	port := 0
	switch a := local.(type) {
	case *net.TCPAddr:
		if a != nil {
			port = a.Port
		}
	case *net.UDPAddr:
		if a != nil {
			port = a.Port
		}
	}
	if n == "tcp4" {
		d.LocalAddr = &net.TCPAddr{IP: v.ip, Port: port}
	} else {
		d.LocalAddr = &net.UDPAddr{IP: v.ip, Port: port}
	}
	return d, n, nil
}
func (v *vpnNet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d, n, e := v.dialer(network, nil)
	if e != nil {
		return nil, e
	}
	return d.DialContext(ctx, n, address)
}
func (v *vpnNet) Dial(network, address string) (net.Conn, error) {
	return v.DialContext(context.Background(), network, address)
}
func (v *vpnNet) DialUDP(network string, local, remote *net.UDPAddr) (transport.UDPConn, error) {
	d, n, e := v.dialer(network, local)
	if e != nil {
		return nil, e
	}
	c, e := d.Dial(n, remote.String())
	if e != nil {
		return nil, e
	}
	return c.(*net.UDPConn), nil
}
func (v *vpnNet) DialTCP(network string, local, remote *net.TCPAddr) (transport.TCPConn, error) {
	d, n, e := v.dialer(network, local)
	if e != nil {
		return nil, e
	}
	c, e := d.Dial(n, remote.String())
	if e != nil {
		return nil, e
	}
	return c.(*net.TCPConn), nil
}
func (v *vpnNet) listenAddress(address string) (string, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return "", e
	}
	if host != "" && host != "0.0.0.0" && !net.ParseIP(host).Equal(v.ip) {
		return "", fmt.Errorf("binding outside the VPN is blocked")
	}
	return net.JoinHostPort(v.ip.String(), port), nil
}
func (v *vpnNet) ListenPacket(network, address string) (net.PacketConn, error) {
	n, e := network4(network)
	if e != nil {
		return nil, e
	}
	a, e := v.listenAddress(address)
	if e != nil {
		return nil, e
	}
	lc := net.ListenConfig{Control: v.control}
	return lc.ListenPacket(context.Background(), n, a)
}
func (v *vpnNet) ListenUDP(network string, local *net.UDPAddr) (transport.UDPConn, error) {
	if local == nil {
		local = &net.UDPAddr{}
	}
	c, e := v.ListenPacket(network, local.String())
	if e != nil {
		return nil, e
	}
	return c.(*net.UDPConn), nil
}

type pinnedListener struct{ *net.TCPListener }

func (p pinnedListener) AcceptTCP() (transport.TCPConn, error) { return p.TCPListener.AcceptTCP() }
func (v *vpnNet) ListenTCP(network string, local *net.TCPAddr) (transport.TCPListener, error) {
	if local == nil {
		local = &net.TCPAddr{}
	}
	c, e := v.listen(context.Background(), network, local.String())
	if e != nil {
		return nil, e
	}
	return pinnedListener{c.(*net.TCPListener)}, nil
}
func (v *vpnNet) listen(ctx context.Context, network, address string) (net.Listener, error) {
	n, e := network4(network)
	if e != nil {
		return nil, e
	}
	a, e := v.listenAddress(address)
	if e != nil {
		return nil, e
	}
	lc := net.ListenConfig{Control: v.control}
	return lc.Listen(ctx, n, a)
}

type pinnedDialer struct {
	v *vpnNet
	d *net.Dialer
}

func (d pinnedDialer) Dial(network, address string) (net.Conn, error) {
	fresh, n, e := d.v.dialer(network, d.d.LocalAddr)
	if e != nil {
		return nil, e
	}
	fresh.Timeout = d.d.Timeout
	fresh.Resolver = d.d.Resolver
	return fresh.Dial(n, address)
}
func (v *vpnNet) CreateDialer(d *net.Dialer) transport.Dialer { return pinnedDialer{v, d} }

type pinnedListenConfig struct{ v *vpnNet }

func (l pinnedListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return l.v.listen(ctx, network, address)
}
func (l pinnedListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return l.v.ListenPacket(network, address)
}
func (v *vpnNet) CreateListenConfig(_ *net.ListenConfig) transport.ListenConfig {
	return pinnedListenConfig{v}
}
func installVPN(root string) (*vpnNet, error) {
	cfg, e := loadVPN(root)
	if e != nil {
		return nil, e
	}
	v, e := newVPN(cfg)
	if e != nil {
		return nil, e
	}
	// Force DNS through the VPN DNS server; never use the Windows/native resolver.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return v.DialContext(ctx, network, net.JoinHostPort(cfg.DNS, "53"))
	}}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = v.DialContext
	tr.DialTLSContext = nil
	tr.ForceAttemptHTTP2 = true
	http.DefaultTransport = tr
	websocket.DefaultDialer.Proxy = nil
	websocket.DefaultDialer.NetDialContext = v.DialContext
	return v, nil
}
