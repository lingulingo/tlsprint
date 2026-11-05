// Package client provides a ready-to-use HTTP client whose TLS fingerprints
// (and optional HTTP/2 transport behaviour) come from tlsprint presets.
//
// The API mirrors the ergonomics of the reference browser-impersonation
// clients: create a client, choose a preset with SetBrowser, then fire
// requests either directly on the client or through the fluent R() builder.
//
//	client := client.NewClient()
//	client.SetBrowser("chrome-141") // a preset name, or a *preset.Preset
//	client.SetProxy("http://127.0.0.1:8080")
//
//	resp, err := client.R().
//	    SetQueryParam("q", "tls fingerprint").
//	    Get("https://httpbin.org/get")
//	fmt.Println(resp.StatusCode(), resp.String())
//
//	resp, err = client.R().SetBody(map[string]any{"a": 1}).Post("https://httpbin.org/post")
//
// Transport notes:
//
//   - Every TLS connection is dialed through the uTLS adapter with the
//     preset's ClientHello (cipher order, extensions, GREASE, ...). The wire
//     fingerprint is verified by tests against loopback captures.
//   - By default HTTP/2 is attempted first (when the preset is HTTP/2 aware)
//     with automatic fallback to HTTP/1.1 when the server does not support
//     it. Use ForceHTTP1() or UseHTTP2() to pin a protocol.
//   - Extension order is taken from the preset by default, so the wire JA3
//     equals the preset's JA3. SetPermuteExtensions(true) instead shuffles it
//     on every new connection, which is what real Chrome does; JA4 is
//     unaffected either way.
//   - Header *values* and ordering follow the preset's header profile; the
//     forked tlsprint/http2 transport reproduces the exact SETTINGS order,
//     the initial WINDOW_UPDATE, the request pseudo/header order and the
//     stream priority from the preset's HTTP/2 fingerprint. (Priority frames
//     carried by presets are also forwarded.)
package client

import (
	"crypto/x509"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lingulingo/tlsprint/preset"
)

// DefaultTimeout is applied when no timeout is configured.
const DefaultTimeout = 30 * time.Second

// Client is a fingerprinting HTTP client. It is safe for concurrent use.
type Client struct {
	mu sync.Mutex

	preset      *preset.Preset
	timeout     time.Duration
	baseURL     string
	proxyURL    *url.URL
	insecure    bool
	rootCAs     *x509.CertPool
	forceProto  string // "", "h1", "h2"
	noRedirect  bool
	redirectMax int // 0 = Go default policy
	withJar     bool
	permute     bool

	// defaultHeaders are applied to every request (canonical keys).
	defaultHeaders http.Header
	// explicitHeaders are header names the user set explicitly (via
	// SetHeader/SetHeaders); switching preset does not clobber these.
	explicitHeaders map[string]bool

	httpClient *http.Client
	rt         *roundTripper
}

// Option configures a Client at construction time.
type Option func(*Client)

// NewClient returns a client with a sensible default preset set ("chrome" —
// the newest curated chrome). Use SetBrowser to pick another one.
func NewClient(opts ...Option) *Client {
	c := &Client{
		timeout:         DefaultTimeout,
		defaultHeaders:  make(http.Header),
		explicitHeaders: make(map[string]bool),
		rt:              &roundTripper{noH2: make(map[string]bool)},
	}
	c.rt.owner = c
	for _, o := range opts {
		o(c)
	}
	if c.preset == nil {
		if reg, err := preset.Builtin(); err == nil {
			c.preset = reg.Lookup("chrome")
		}
	}
	c.applyPresetDefaultsLocked()
	c.rebuildHTTPClientLocked()
	return c
}

// WithTimeout sets the per-request timeout (default 30s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.SetTimeout(d) }
}

// WithProxy sets an HTTP(S) proxy URL ("http://host:port"). HTTPS targets are
// reached through CONNECT tunnelling; the TLS handshake still uses the preset
// fingerprint inside the tunnel.
func WithProxy(rawURL string) Option {
	return func(c *Client) { _ = c.SetProxy(rawURL) }
}

// WithInsecureSkipVerify disables TLS certificate verification (testing
// only).
func WithInsecureSkipVerify(b bool) Option {
	return func(c *Client) { c.insecure = b }
}

// WithRootCAs replaces the trusted root pool used for certificate checks.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(c *Client) { c.rootCAs = pool }
}

// WithPreset preselects the fingerprint preset at construction time.
func WithPreset(p *preset.Preset) Option {
	return func(c *Client) { c.preset = p }
}

// WithPermuteExtensions enables extension-order randomization for every new
// connection; see Client.SetPermuteExtensions.
func WithPermuteExtensions() Option {
	return func(c *Client) { c.permute = true }
}

// SetBrowser chooses the fingerprint preset. nameOrPreset may be a preset
// name string (see preset.Registry.Lookup) or a *preset.Preset.
func (c *Client) SetBrowser(nameOrPreset any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch v := nameOrPreset.(type) {
	case *preset.Preset:
		if v == nil {
			return fmt.Errorf("client: nil preset")
		}
		c.preset = v
	case string:
		p := preset.MustBuiltin().Lookup(v)
		if p == nil {
			return fmt.Errorf("client: unknown preset %q", v)
		}
		c.preset = p
	default:
		return fmt.Errorf("client: SetBrowser expects a preset name or *preset.Preset, got %T", nameOrPreset)
	}
	c.applyPresetDefaultsLocked()
	c.rt.invalidate()
	return nil
}

// SetPreset is an alias of SetBrowser for callers who prefer the tlsprint
// vocabulary.
func (c *Client) SetPreset(nameOrPreset any) error { return c.SetBrowser(nameOrPreset) }

// SetRandomBrowser picks a random preset of the given product ("chrome",
// "firefox", ...). "*" or "" means any product.
func (c *Client) SetRandomBrowser(product string) error {
	reg := preset.MustBuiltin()
	var candidates []*preset.Preset
	for _, p := range reg.List() {
		if product == "" || product == "*" || p.Product == product {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("client: no presets for product %q", product)
	}
	return c.SetBrowser(candidates[rand.Intn(len(candidates))])
}

// Preset returns the currently selected fingerprint preset.
func (c *Client) Preset() *preset.Preset {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.preset
}

// R returns a fresh Request builder that inherits the client defaults.
func (c *Client) R() *Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return newRequest(c)
}

// ForceHTTP1 pins HTTP/1.1 (no HTTP/2 attempts).
func (c *Client) ForceHTTP1() *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forceProto = "h1"
	c.rt.invalidate()
	return c
}

// UseHTTP2 pins HTTP/2 (no HTTP/1.1 fallback; the server must support h2).
func (c *Client) UseHTTP2() *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forceProto = "h2"
	c.rt.invalidate()
	return c
}

// UseAutoProtocol re-enables automatic h2-with-h1-fallback (the default).
func (c *Client) UseAutoProtocol() *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forceProto = ""
	c.rt.invalidate()
	return c
}

// SetTimeout sets the per-request timeout.
func (c *Client) SetTimeout(d time.Duration) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
	c.rebuildHTTPClientLocked()
	return c
}

// SetProxy sets an HTTP proxy; pass "" to clear it.
func (c *Client) SetProxy(rawURL string) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rawURL == "" {
		c.proxyURL = nil
	} else if u, err := url.Parse(rawURL); err == nil {
		c.proxyURL = u
	}
	c.rt.invalidate()
	return c
}

// SetInsecureSkipVerify disables TLS certificate verification (testing only).
func (c *Client) SetInsecureSkipVerify(skip bool) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.insecure = skip
	c.rt.invalidate()
	return c
}

// SetRootCAs replaces the trusted root pool.
func (c *Client) SetRootCAs(pool *x509.CertPool) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rootCAs = pool
	c.rt.invalidate()
	return c
}

// SetBaseURL sets a prefix for relative request URLs.
func (c *Client) SetBaseURL(u string) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseURL = u
	return c
}

// SetRedirects configures redirect handling. max == 0 stops following
// redirects (the first response is returned); max > 0 follows up to max
// redirects; max < 0 restores the Go default policy.
func (c *Client) SetRedirects(max int) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case max == 0:
		c.noRedirect = true
	case max < 0:
		c.noRedirect = false
		c.redirectMax = 0
	default:
		c.noRedirect = false
		c.redirectMax = max
	}
	c.rebuildHTTPClientLocked()
	return c
}

// SetHeader sets a default header applied to every request.
func (c *Client) SetHeader(key, value string) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.explicitHeaders == nil {
		c.explicitHeaders = make(map[string]bool)
	}
	c.explicitHeaders[canonicalHeaderKey(key)] = true
	c.defaultHeaders.Set(key, value)
	return c
}

// SetHeaders sets multiple default headers.
func (c *Client) SetHeaders(headers map[string]string) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.explicitHeaders == nil {
		c.explicitHeaders = make(map[string]bool)
	}
	for k, v := range headers {
		c.explicitHeaders[canonicalHeaderKey(k)] = true
		c.defaultHeaders.Set(k, v)
	}
	return c
}

// SetHeaderOrder records the preferred header order. net/http does not expose
// header ordering, so this is kept for API compatibility and future
// HTTP/2-exact transport work; it does not reorder wire headers today.
func (c *Client) SetHeaderOrder(_ ...string) *Client {
	return c
}

// SetPermuteExtensions controls extension-order randomization (curl_cffi's
// `permute_extensions`, and what Chrome itself does).
//
// When true, every new TLS connection shuffles the order of the reorderable
// ClientHello extensions instead of using the preset's captured order. That
// matches what modern Chromium actually does — each connection gets a fresh
// permutation — and stops JA3 from being a stable per-client identifier.
// Wire-order constraints are preserved (GREASE positions, padding last,
// pre_shared_key last).
//
// Off by default, because it intentionally breaks the invariant that the wire
// JA3 equals the preset's JA3. JA4 is unaffected either way: it sorts
// extensions, so the fingerprint it reports is identical. The setting applies
// to connections opened afterwards; pooled connections keep their original
// ClientHello.
func (c *Client) SetPermuteExtensions(on bool) *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.permute = on
	return c
}

// EnableCookieJar turns on automatic cookie storage.
func (c *Client) EnableCookieJar() *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.withJar = true
	c.rebuildHTTPClientLocked()
	return c
}

// DisableCookieJar disables automatic cookie storage.
func (c *Client) DisableCookieJar() *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.withJar = false
	c.rebuildHTTPClientLocked()
	return c
}

// ---- internals ----

func (c *Client) applyPresetDefaultsLocked() {
	if c.preset == nil || c.preset.Headers == nil {
		return
	}
	for name, value := range c.preset.Headers.Values {
		if value == "" {
			continue
		}
		key := canonicalHeaderKey(name)
		if c.explicitHeaders[key] {
			continue // user explicitly overrode this header
		}
		c.defaultHeaders.Set(key, value)
	}
}

// canonicalHeaderKey converts a header name to its canonical form.
func canonicalHeaderKey(name string) string {
	parts := strings.Split(strings.ToLower(name), "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "-")
}

func (c *Client) rebuildHTTPClientLocked() {
	hc := &http.Client{Timeout: c.timeout, Transport: c.rt}
	switch {
	case c.noRedirect:
		hc.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	case c.redirectMax > 0:
		max := c.redirectMax
		hc.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) >= max {
				return fmt.Errorf("client: stopped after %d redirects", max)
			}
			return nil
		}
	}
	if c.withJar {
		if jar, err := cookiejar.New(nil); err == nil {
			hc.Jar = jar
		}
	}
	c.httpClient = hc
}

// CloseIdleConnections closes any idle HTTP/1.1 and HTTP/2 connections held
// by the client's transport, releasing their goroutines and file descriptors.
func (c *Client) CloseIdleConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeTransportsLocked()
}

// Close is an alias of CloseIdleConnections (the client keeps no exclusive
// resources beyond its connection pool).
func (c *Client) Close() { c.CloseIdleConnections() }

// closeTransportsLocked must be called with c.mu held.
func (c *Client) closeTransportsLocked() {
	if c.rt == nil {
		return
	}
	c.rt.mu.Lock()
	defer c.rt.mu.Unlock()
	if c.rt.h1 != nil {
		if t, ok := c.rt.h1.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
	if c.rt.h2 != nil {
		c.rt.h2.CloseIdleConnections()
	}
}

// do executes req through the current http.Client (without locking around the
// round trip itself).
func (c *Client) do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	hc := c.httpClient
	c.mu.Unlock()
	return hc.Do(req)
}
