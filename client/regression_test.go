package client

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestSetResultDecodesCompressedBody guards against SetResult decoding the raw
// (still compressed) wire bytes. Presets send Accept-Encoding themselves, which
// suppresses net/http's transparent decompression, so a compressed 2xx really
// does reach the client encoded.
func TestSetResultDecodesCompressedBody(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_ = json.NewEncoder(gz).Encode(map[string]string{"method": r.Method})
		_ = gz.Close()
	})
	srv := httptest.NewUnstartedServer(h)
	srv.StartTLS()
	defer srv.Close()

	// NewClient applies the default preset, whose Accept-Encoding header is
	// what disables net/http's automatic decompression.
	c := NewClient(WithRootCAs(rootsOf(t, srv)))

	var out struct {
		Method string `json:"method"`
	}
	resp, err := c.R().SetResult(&out).Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("SetResult over a gzip-encoded body: %v", err)
	}
	if !resp.IsSuccess() {
		t.Fatalf("status = %d", resp.StatusCode())
	}
	if out.Method != "GET" {
		t.Fatalf("decoded result method = %q, want GET", out.Method)
	}
	// Response.JSON must agree with SetResult (it uses the decoded body).
	var viaJSON struct {
		Method string `json:"method"`
	}
	if err := resp.JSON(&viaJSON); err != nil {
		t.Fatalf("Response.JSON: %v", err)
	}
	if viaJSON.Method != out.Method {
		t.Fatalf("JSON() = %q but SetResult = %q", viaJSON.Method, out.Method)
	}
}

// TestTopLevelImpersonateAppliesPresetHeaders guards the curl_cffi-style
// top-level API: client.Get(url, Impersonate(preset)) must send that preset's
// header bundle, not the default preset's.
func TestTopLevelImpersonateAppliesPresetHeaders(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"ua": r.Header.Get("User-Agent")})
	}))
	srv.StartTLS()
	defer srv.Close()

	resp, err := Get(srv.URL+"/", Impersonate("firefox-145"), WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatalf("top-level Get with Impersonate: %v", err)
	}
	var got map[string]string
	if err := resp.JSON(&got); err != nil {
		t.Fatal(err)
	}
	ua := got["ua"]
	if !strings.Contains(ua, "Firefox/145") {
		t.Fatalf("top-level Impersonate(firefox-145) sent UA %q, want a Firefox/145 UA", ua)
	}
	if strings.Contains(ua, "Chrome/") {
		t.Fatalf("UA still carries the default chrome preset: %q", ua)
	}
}

// startRecordingProxy accepts a single plain-HTTP (non-CONNECT) proxy request,
// reports its request line, and answers 200.
func startRecordingProxy(t *testing.T) (addr string, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	ch := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		if err != nil {
			ch <- ""
			return
		}
		ch <- strings.TrimSpace(line)
		for { // drain request headers
			l, err := br.ReadString('\n')
			if err != nil || strings.TrimSpace(l) == "" {
				break
			}
		}
		body := "proxied"
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	return ln.Addr().String(), ch
}

// TestProxyUsedForPlainHTTPTarget guards against plain http:// targets
// bypassing a configured proxy (they used to be dialled directly).
func TestProxyUsedForPlainHTTPTarget(t *testing.T) {
	addr, got := startRecordingProxy(t)
	c := NewClient(WithProxy("http://" + addr))
	defer c.CloseIdleConnections()

	// .invalid never resolves, so an unproxied attempt cannot succeed.
	const target = "http://tlsprint-proxy-probe.invalid/data"
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("http target through proxy: %v (proxy was bypassed?)", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("status = %d, want 200 from the proxy", resp.StatusCode())
	}
	select {
	case line := <-got:
		if !strings.HasPrefix(line, "GET "+target+" ") {
			t.Fatalf("proxy saw request line %q, want absolute-form %q", line, "GET "+target+" HTTP/1.1")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy was never contacted")
	}
}

// TestSetBaseURLReachesRequests guards against Client.baseURL never being
// snapshotted into the Request: relative URLs used to be resolved with an empty
// prefix, failing with `unsupported protocol scheme ""`.
func TestSetBaseURLReachesRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	defer srv.Close()

	c := NewClient().SetBaseURL(srv.URL)
	defer c.Close()

	// The fluent builder and the direct verbs must both honour the prefix.
	resp, err := c.R().Get("/from-builder")
	if err != nil {
		t.Fatalf("builder Get with base URL: %v", err)
	}
	if got := resp.String(); got != "path=/from-builder" {
		t.Fatalf("builder response = %q", got)
	}

	resp, err = c.Get("/from-verb")
	if err != nil {
		t.Fatalf("direct Get with base URL: %v", err)
	}
	if got := resp.String(); got != "path=/from-verb" {
		t.Fatalf("direct response = %q", got)
	}

	// An absolute URL is still used as-is.
	resp, err = c.Get(srv.URL + "/absolute")
	if err != nil {
		t.Fatalf("absolute Get: %v", err)
	}
	if got := resp.String(); got != "path=/absolute" {
		t.Fatalf("absolute response = %q", got)
	}
}

// TestSetCookieAccumulates guards against each SetCookie emitting its own
// Cookie header: servers only read the first one, so additional cookies were
// silently dropped.
func TestSetCookieAccumulates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%d|%s", len(r.Header.Values("Cookie")), strings.Join(r.Header.Values("Cookie"), " / "))
	}))
	defer srv.Close()

	c := NewClient()
	defer c.Close()
	resp, err := c.Get(srv.URL+"/c",
		Cookie("a", "1"),
		Cookie("b", "2"),
		Cookie("c", "3"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := resp.String(), "1|a=1; b=2; c=3"; got != want {
		t.Fatalf("cookie headers = %q, want %q", got, want)
	}
}
