package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	http2 "github.com/lingulingo/tlsprint/http2"
	"github.com/lingulingo/tlsprint/preset"
	tlsutls "github.com/lingulingo/tlsprint/utls"
)

// protocolFallbackError is returned by the h2 dialer when the server
// negotiated HTTP/1.1 (or nothing) instead of h2. It signals the round
// tripper that the request was not sent and should be retried over h1.
type protocolFallbackError struct{ addr string }

func (e *protocolFallbackError) Error() string {
	return fmt.Sprintf("client: server at %s did not negotiate h2", e.addr)
}

// dialSnapshot is an immutable copy of the client settings used for one
// round trip.
type dialSnapshot struct {
	preset    *preset.Preset
	insecure  bool
	rootCAs   *x509.CertPool
	proxy     *url.URL
	forceH1   bool // explicit ForceHTTP1
	forceH2   bool // explicit UseHTTP2
	h2Capable bool // preset carries HTTP/2 behaviour
	permute   bool // shuffle extension order on every new connection
}

type roundTripper struct {
	owner *Client

	mu   sync.Mutex
	h1   http.RoundTripper
	h2   *http2.Transport
	noH2 map[string]bool // host → known to be HTTP/1.1 only
}

func newRoundTripper() *roundTripper {
	return &roundTripper{noH2: make(map[string]bool)}
}

// invalidate drops cached transports and protocol preferences (called when
// preset/security settings change).
func (rt *roundTripper) invalidate() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.h1 != nil {
		if c, ok := rt.h1.(*http.Transport); ok {
			c.CloseIdleConnections()
		}
	}
	if rt.h2 != nil {
		rt.h2.CloseIdleConnections()
	}
	rt.h1 = nil
	rt.h2 = nil
	rt.noH2 = make(map[string]bool)
}

func (rt *roundTripper) snapshot() dialSnapshot {
	c := rt.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	s := dialSnapshot{
		preset:   c.preset,
		insecure: c.insecure,
		rootCAs:  c.rootCAs,
		proxy:    c.proxyURL,
		permute:  c.permute,
	}
	switch c.forceProto {
	case "h1":
		s.forceH1 = true
	case "h2":
		s.forceH2 = true
	}
	s.h2Capable = c.preset != nil && c.preset.HTTP2 != nil
	return s
}

// RoundTrip implements http.RoundTripper.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	snap := rt.snapshot()
	if snap.preset == nil {
		return nil, errors.New("client: no preset selected")
	}

	// Plain http (no TLS): the h1 transport dials directly.
	if req.URL.Scheme == "http" {
		return rt.h1Transport(snap).RoundTrip(req)
	}

	host := req.URL.Hostname()
	switch {
	case snap.forceH1 || !snap.h2Capable || rt.hostNoH2(host):
		return rt.h1Transport(snap).RoundTrip(req)
	case snap.forceH2:
		return rt.h2Transport(snap).RoundTrip(req)
	}

	// Auto mode: try h2 first; fall back to h1 only when the failure
	// happened before the request body was transmitted (h2 not negotiated /
	// connection-stage error).
	resp, err := rt.h2Transport(snap).RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	var fb *protocolFallbackError
	if errors.As(err, &fb) {
		rt.rememberNoH2(host)
		return rt.h1Transport(snap).RoundTrip(req)
	}
	// Idempotent methods may retry over h1 on a connection-stage error, but
	// only when the body is replayable (nil or GetBody != nil). Otherwise a
	// failed h2 attempt may have already consumed the body, and re-sending
	// would use a corrupt/empty body.
	if isIdempotent(req.Method) && (req.Body == nil || req.GetBody != nil) {
		rt.rememberNoH2(host)
		return rt.h1Transport(snap).RoundTrip(req)
	}
	return nil, err
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace,
		http.MethodPut, http.MethodDelete:
		return true
	}
	return false
}

func (rt *roundTripper) hostNoH2(host string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.noH2[host]
}

func (rt *roundTripper) rememberNoH2(host string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.noH2[host] = true
}

// h1Transport returns (building on demand) an HTTP/1.1 transport whose TLS
// connections use the preset fingerprint and ALPN http/1.1 only.
func (rt *roundTripper) h1Transport(snap dialSnapshot) http.RoundTripper {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.h1 == nil {
		t := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return rt.dial(ctx, network, addr, snap, []string{"http/1.1"})
			},
			DisableCompression:  false,
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
		}
		if snap.proxy != nil {
			proxy := snap.proxy
			// Cleartext targets must go through net/http's own proxy support
			// (absolute-form request line); without this they were dialled
			// directly and the proxy was silently bypassed. TLS targets are
			// tunnelled by DialTLSContext, which performs the CONNECT itself,
			// so they must not be proxied twice.
			t.Proxy = func(req *http.Request) (*url.URL, error) {
				if req.URL.Scheme != "http" {
					return nil, nil
				}
				if proxy.Scheme != "http" {
					return nil, fmt.Errorf("client: plain http:// targets require a plain http:// proxy, got %q", proxy.Scheme)
				}
				return proxy, nil
			}
		}
		rt.h1 = t
	}
	return rt.h1
}
func (rt *roundTripper) h2Transport(snap dialSnapshot) *http2.Transport {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.h2 == nil {
		rt.h2 = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return rt.dial(ctx, network, addr, snap, nil /* browser default ALPN */)
			},
			Fingerprint: buildFingerprint(snap),
		}
	}
	return rt.h2
}

// buildFingerprint translates the preset's HTTP/2 and header fingerprints into
// the forked transport's connection-level h2 fingerprint (byte-exact SETTINGS
// order, WINDOW_UPDATE, pseudo/header order and stream priority).
func buildFingerprint(snap dialSnapshot) *http2.Fingerprint {
	p := snap.preset
	if p == nil || p.HTTP2 == nil {
		return nil
	}
	fp := &http2.Fingerprint{
		WindowUpdate:      p.HTTP2.WindowUpdate,
		PseudoHeaderOrder: append([]string(nil), p.HTTP2.PseudoHeaderOrder...),
	}
	for _, pf := range p.HTTP2.PriorityFrames {
		fp.PriorityFrames = append(fp.PriorityFrames, http2.StreamPriorityFrame{
			StreamID: pf.StreamID,
			Priority: http2.StreamPriority{
				StreamDep: pf.Priority.StreamDep,
				Exclusive: pf.Priority.Exclusive,
				Weight:    pf.Priority.Weight,
			},
		})
	}
	for _, s := range p.HTTP2.Settings {
		fp.Settings = append(fp.Settings, http2.Setting{ID: http2.SettingID(s.ID), Val: s.Value})
	}
	if p.HTTP2.HeaderPriority != nil {
		fp.HeaderPriority = &http2.StreamPriority{
			StreamDep: p.HTTP2.HeaderPriority.StreamDep,
			Exclusive: p.HTTP2.HeaderPriority.Exclusive,
			Weight:    p.HTTP2.HeaderPriority.Weight,
		}
	}
	if p.Headers != nil {
		fp.HeaderOrder = append([]string(nil), p.Headers.Order...)
	}
	return fp
}

// dial establishes one TLS connection whose ClientHello matches the preset,
// tunnelling through the configured HTTP proxy when present.
func (rt *roundTripper) dial(ctx context.Context, network, addr string, snap dialSnapshot, alpn []string) (net.Conn, error) {
	raw, err := rt.dialRaw(ctx, network, addr, snap.proxy)
	if err != nil {
		return nil, err
	}

	specOpts := tlsutls.NewOptions(&snap.preset.Profile)
	specOpts.PermuteExtensions = snap.permute
	if alpn != nil {
		specOpts.ALPN = alpn
	}
	dopts := &tlsutls.DialOptions{
		Spec:               specOpts,
		InsecureSkipVerify: snap.insecure,
		RootCAs:            snap.rootCAs,
		NetDial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return raw, nil // already connected (directly or via proxy tunnel)
		},
	}
	conn, err := tlsutls.Dial(ctx, network, addr, snap.preset, dopts)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// For the h2 transport the connection must actually have negotiated h2.
	neg := conn.ConnectionState().NegotiatedProtocol
	if alpn == nil && neg != "h2" {
		conn.Close()
		return nil, &protocolFallbackError{addr: addr}
	}
	return conn, nil
}

// dialRaw connects to addr, tunnelling through the HTTP proxy with CONNECT
// when one is configured.
func proxyHostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func (rt *roundTripper) dialRaw(ctx context.Context, network, addr string, proxy *url.URL) (net.Conn, error) {
	if proxy == nil || proxy.Scheme == "" {
		d := &net.Dialer{}
		return d.DialContext(ctx, network, addr)
	}
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, fmt.Errorf("client: unsupported proxy scheme %q (only http/https)", proxy.Scheme)
	}
	// CONNECT tunnel through the proxy. https proxies are reached over TLS,
	// so the CONNECT and the tunnelled traffic are not sent in cleartext.
	pc, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("client: dial proxy %s: %w", proxy.Host, err)
	}
	if proxy.Scheme == "https" {
		tlsConfig := &tls.Config{ServerName: proxyHostname(proxy.Host)}
		tlsConn := tls.Client(pc, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			pc.Close()
			return nil, fmt.Errorf("client: proxy TLS handshake: %w", err)
		}
		pc = tlsConn
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if proxy.User != nil {
		// Basic proxy authentication: http(s)://user:password@host:port
		pass, _ := proxy.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(proxy.User.Username() + ":" + pass))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "\r\n"
	if _, err := pc.Write([]byte(req)); err != nil {
		pc.Close()
		return nil, fmt.Errorf("client: proxy CONNECT write: %w", err)
	}
	br := bufio.NewReader(pc)
	status, err := br.ReadString('\n')
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("client: proxy CONNECT read: %w", err)
	}
	// Consume headers until the blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			pc.Close()
			return nil, fmt.Errorf("client: proxy CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" || err == io.EOF {
			break
		}
	}
	if !strings.Contains(status, " 200 ") {
		pc.Close()
		return nil, fmt.Errorf("client: proxy CONNECT failed: %s", strings.TrimSpace(status))
	}
	// Any bytes the bufio read past the header must be handed back to the
	// TLS layer.
	return &prefixedConn{Conn: pc, r: br}, nil
}

// prefixedConn replays bytes buffered by a bufio.Reader before passing reads
// through to the underlying connection.
type prefixedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
