// Package ssrf guards every outbound request whose destination is influenced
// by a user (scan targets, credential login/verify URLs).
//
// Two layers are needed:
//
//  1. Parse validates the shape of the URL (scheme, port, no userinfo).
//  2. Client validates the *resolved IP* at dial time via net.Dialer.Control,
//     which is what defeats DNS rebinding (evil.com -> 127.0.0.1).
package ssrf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var (
	ErrInvalidTarget    = errors.New("target is not a valid URL")
	ErrInvalidScheme    = errors.New("only http and https targets are allowed")
	ErrPortNotAllowed   = errors.New("target port is not allowed")
	ErrBlockedAddress   = errors.New("target resolves to a blocked address")
	ErrTooManyRedirects = errors.New("too many redirects")
)

// Guard validates outbound URLs and builds hardened HTTP clients.
type Guard struct {
	allowedPorts map[string]struct{}
	allowPrivate bool
	blocked      []netip.Prefix
}

// New builds a Guard. allowedPorts is a list of port strings, e.g.
// ["80","443","8080"]. allowPrivate should stay false outside lab setups.
func New(allowedPorts []string, allowPrivate bool) *Guard {
	g := &Guard{
		allowedPorts: make(map[string]struct{}, len(allowedPorts)),
		allowPrivate: allowPrivate,
	}
	for _, p := range allowedPorts {
		p = strings.TrimSpace(p)
		if p != "" {
			g.allowedPorts[p] = struct{}{}
		}
	}
	g.blocked = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
		netip.MustParsePrefix("127.0.0.0/8"),    // loopback
		netip.MustParsePrefix("169.254.0.0/16"), // link-local + cloud metadata
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
		netip.MustParsePrefix("::ffff:0:0/96"), // IPv4-mapped, re-checked after Unmap
	}
	return g
}

// Parse validates the URL shape without touching the network.
func (g *Guard) Parse(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return nil, ErrInvalidTarget
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, ErrInvalidTarget
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrInvalidScheme
	}
	if u.User != nil {
		return nil, ErrInvalidTarget
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if _, ok := g.allowedPorts[port]; !ok {
		return nil, ErrPortNotAllowed
	}
	return u, nil
}

// Validate performs Parse plus a DNS resolution and rejects any address in a
// blocked range. Use it when persisting a user-supplied URL.
func (g *Guard) Validate(ctx context.Context, raw string) (*url.URL, error) {
	u, err := g.Parse(raw)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if g.IsBlocked(ip) {
			return nil, ErrBlockedAddress
		}
		return u, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return nil, ErrInvalidTarget
	}
	for _, ip := range addrs {
		if g.IsBlocked(ip) {
			return nil, ErrBlockedAddress
		}
	}
	return u, nil
}

// IsBlocked reports whether ip must not be dialled.
func (g *Guard) IsBlocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	// Never reachable, regardless of lab mode: metadata endpoints, multicast,
	// unspecified addresses and link-local ranges.
	if ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return !g.allowPrivate
	}
	for _, p := range g.blocked {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// checkDialAddr is the last line of defence: it sees the address the dialer is
// about to connect to, i.e. after DNS resolution.
func (g *Guard) checkDialAddr(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: unresolved %q", ErrBlockedAddress, host)
	}
	if g.IsBlocked(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	return nil
}

// Client returns an HTTP client that cannot reach blocked addresses, follows
// at most maxRedirects redirects, and re-validates each hop.
func (g *Guard) Client(timeout time.Duration, maxRedirects int) *http.Client {
	if maxRedirects <= 0 {
		maxRedirects = 5
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			return g.checkDialAddr(address)
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		Proxy:                 nil, // env proxies would bypass the dialer Control
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   4,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return ErrTooManyRedirects
			}
			if _, err := g.Parse(req.URL.String()); err != nil {
				return err
			}
			return nil
		},
	}
}
