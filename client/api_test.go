package client

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/lingulingo/tlsprint/preset"
)

// echo is the decoded body of the API echo handler below.
type echo struct {
	Method string              `json:"method"`
	Path   string              `json:"path"`
	Query  string              `json:"query"`
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
}

func (e echo) header(name string) string {
	for k, vs := range e.Header {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// startAPI starts a plain-HTTP server that echoes the request back as JSON.
// Plain HTTP is enough for the request/response API surface: the preset's
// header defaults still apply, and no TLS handshake is needed.
func startAPI(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/echo", http.StatusFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		status := http.StatusOK
		if q := r.URL.Query().Get("status"); q != "" {
			if n, err := strconv.Atoi(q); err == nil {
				status = n
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", "1")
		http.SetCookie(w, &http.Cookie{Name: "srv", Value: "c1", Path: "/"})
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(echo{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Header: r.Header,
			Body:   string(body),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func decodeEcho(t *testing.T, resp *Response) echo {
	t.Helper()
	var e echo
	if err := resp.JSON(&e); err != nil {
		t.Fatalf("decode echo: %v (body %q)", err, resp.String())
	}
	return e
}

// TestPackageLevelVerbs covers the curl_cffi-style module-level helpers.
func TestPackageLevelVerbs(t *testing.T) {
	srv := startAPI(t)
	p := preset.MustBuiltin().Lookup("chrome-156")
	if p == nil {
		t.Fatal("chrome-156 preset missing")
	}

	verbs := []struct {
		name string
		call func(string, ...any) (*Response, error)
		want string
	}{
		{"Get", Get, http.MethodGet},
		{"Post", Post, http.MethodPost},
		{"Put", Put, http.MethodPut},
		{"Patch", Patch, http.MethodPatch},
		{"Delete", Delete, http.MethodDelete},
		{"Head", Head, http.MethodHead},
		{"Options", Options, http.MethodOptions},
	}
	for _, v := range verbs {
		v := v
		t.Run(v.name, func(t *testing.T) {
			resp, err := v.call(srv.URL+"/ping", Impersonate("chrome-156"))
			if err != nil {
				t.Fatalf("%s: %v", v.name, err)
			}
			if resp.StatusCode() != http.StatusOK {
				t.Fatalf("%s: status %d", v.name, resp.StatusCode())
			}
			if v.want == http.MethodHead {
				return // HEAD has no body to echo
			}
			e := decodeEcho(t, resp)
			if e.Method != v.want {
				t.Fatalf("%s: server saw %s", v.name, e.Method)
			}
			if got, want := e.header("User-Agent"), p.UserAgent(); got != want {
				t.Fatalf("%s: UA = %q, want preset UA %q", v.name, got, want)
			}
		})
	}

	t.Run("Do", func(t *testing.T) {
		resp, err := Do(http.MethodTrace, srv.URL+"/trace", WithBrowser("chrome-156"))
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if e := decodeEcho(t, resp); e.Method != http.MethodTrace {
			t.Fatalf("Do: server saw %s", e.Method)
		}
	})
}

// TestClientLevelVerbs covers the pool-reusing direct verbs.
func TestClientLevelVerbs(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()
	if err := c.SetBrowser("chrome-156"); err != nil {
		t.Fatalf("SetBrowser: %v", err)
	}
	defer c.Close()

	verbs := []struct {
		name string
		call func(string, ...ReqOption) (*Response, error)
		want string
	}{
		{"Get", c.Get, http.MethodGet},
		{"Post", c.Post, http.MethodPost},
		{"Put", c.Put, http.MethodPut},
		{"Patch", c.Patch, http.MethodPatch},
		{"Delete", c.Delete, http.MethodDelete},
		{"Options", c.Options, http.MethodOptions},
	}
	for _, v := range verbs {
		resp, err := v.call(srv.URL + "/ping")
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if e := decodeEcho(t, resp); e.Method != v.want {
			t.Fatalf("%s: server saw %s", v.name, e.Method)
		}
	}

	resp, err := c.Head(srv.URL + "/ping")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("Head: status %d", resp.StatusCode())
	}

	resp, err = c.Do(http.MethodPatch, srv.URL+"/ping")
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if e := decodeEcho(t, resp); e.Method != http.MethodPatch {
		t.Fatalf("Do: server saw %s", e.Method)
	}
}

// TestReqOptionBodyVariants covers every encodeBody branch through the
// functional-option API.
func TestReqOptionBodyVariants(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	cases := []struct {
		name        string
		body        any
		wantType    string
		wantContain string
	}{
		{"string", "raw-payload", "", "raw-payload"},
		{"bytes", []byte("bytes-payload"), "", "bytes-payload"},
		{"reader", strings.NewReader("reader-payload"), "", "reader-payload"},
		{"map", map[string]string{"a": "1", "b": "2"}, "application/x-www-form-urlencoded", "a=1"},
		{"values", url.Values{"k": []string{"v"}}, "application/x-www-form-urlencoded", "k=v"},
		{"struct", struct {
			Name string `json:"name"`
		}{"tlsprint"}, "application/json", `"name":"tlsprint"`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			resp, err := c.Post(srv.URL+"/echo", Body(tc.body))
			if err != nil {
				t.Fatalf("%v", err)
			}
			e := decodeEcho(t, resp)
			if !strings.Contains(e.Body, tc.wantContain) {
				t.Fatalf("body = %q, want to contain %q", e.Body, tc.wantContain)
			}
			if tc.wantType != "" {
				if got := e.header("Content-Type"); !strings.HasPrefix(got, tc.wantType) {
					t.Fatalf("Content-Type = %q, want prefix %q", got, tc.wantType)
				}
			}
		})
	}

	// An explicit Content-Type is not overwritten by the encoder default.
	resp, err := c.Post(srv.URL+"/echo",
		Header("Content-Type", "application/vnd.custom+json"),
		Body(map[string]any{"x": 1}))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if got := decodeEcho(t, resp).header("Content-Type"); got != "application/vnd.custom+json" {
		t.Fatalf("Content-Type = %q, want the caller's value", got)
	}
}

// TestReqOptionHeadersQueriesCookies covers the request-header, query and cookie
// options.
func TestReqOptionHeadersQueriesCookies(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	resp, err := c.Get(srv.URL+"/q",
		Header("X-One", "1"),
		Headers(map[string]string{"X-Two": "2", "X-Three": "3"}),
		Query("q", "tls"),
		Queries(map[string]string{"lang": "go", "page": "2"}),
		Cookie("sid", "abc"),
		Cookie("theme", "dark"),
	)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	e := decodeEcho(t, resp)
	for name, want := range map[string]string{"X-One": "1", "X-Two": "2", "X-Three": "3"} {
		if got := e.header(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	q, err := url.ParseQuery(e.Query)
	if err != nil {
		t.Fatalf("parse query %q: %v", e.Query, err)
	}
	for name, want := range map[string]string{"q": "tls", "lang": "go", "page": "2"} {
		if got := q.Get(name); got != want {
			t.Fatalf("query %s = %q, want %q (raw %q)", name, got, want, e.Query)
		}
	}
	cookie := e.header("Cookie")
	for _, want := range []string{"sid=abc", "theme=dark"} {
		if !strings.Contains(cookie, want) {
			t.Fatalf("Cookie = %q, want to contain %q", cookie, want)
		}
	}

	// CookieHeader replaces the whole Cookie header (documented behaviour),
	// so combining it with Cookie() keeps only the raw string.
	resp, err = c.Get(srv.URL+"/q", Cookie("sid", "abc"), CookieHeader("raw=1"))
	if err != nil {
		t.Fatalf("CookieHeader: %v", err)
	}
	if got := decodeEcho(t, resp).header("Cookie"); got != "raw=1" {
		t.Fatalf("CookieHeader should replace the header, got %q", got)
	}
}

// TestReqOptionAuth covers both authentication helpers.
func TestReqOptionAuth(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	resp, err := c.Get(srv.URL+"/secure", BasicAuth("user", "pass"))
	if err != nil {
		t.Fatalf("BasicAuth: %v", err)
	}
	if got := decodeEcho(t, resp).header("Authorization"); got != "Basic dXNlcjpwYXNz" {
		t.Fatalf("Authorization = %q", got)
	}

	resp, err = c.Get(srv.URL+"/secure", AuthToken("tok-123"))
	if err != nil {
		t.Fatalf("AuthToken: %v", err)
	}
	if got := decodeEcho(t, resp).header("Authorization"); got != "Bearer tok-123" {
		t.Fatalf("Authorization = %q", got)
	}

	// The builder methods behind the options must reach the wire too.
	resp, err = c.R().SetBasicAuth("u2", "p2").Get(srv.URL + "/secure")
	if err != nil {
		t.Fatalf("SetBasicAuth: %v", err)
	}
	if got := decodeEcho(t, resp).header("Authorization"); got != "Basic dTI6cDI=" {
		t.Fatalf("Authorization = %q", got)
	}

	// Both helpers write the same header, so the last call wins.
	resp, err = c.R().SetBasicAuth("u2", "p2").SetAuthToken("tok-2").Get(srv.URL + "/secure")
	if err != nil {
		t.Fatalf("SetAuthToken after SetBasicAuth: %v", err)
	}
	if got := decodeEcho(t, resp).header("Authorization"); got != "Bearer tok-2" {
		t.Fatalf("Authorization = %q, want the last value written", got)
	}
}

// TestReqOptionResult covers decoding into a caller-supplied target, including
// the rule that non-2xx responses are not decoded.
func TestReqOptionResult(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	var out echo
	resp, err := c.Get(srv.URL+"/echo", Result(&out))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode() != http.StatusOK || out.Method != http.MethodGet {
		t.Fatalf("result not decoded: status %d method %q", resp.StatusCode(), out.Method)
	}

	var skipped echo
	resp, err = c.Get(srv.URL+"/echo?status=500", Result(&skipped))
	if err != nil {
		t.Fatalf("Get 500: %v", err)
	}
	if resp.StatusCode() != http.StatusInternalServerError {
		t.Fatalf("status = %d", resp.StatusCode())
	}
	if skipped.Method != "" {
		t.Fatalf("result decoded on a 500: %+v", skipped)
	}
}

// TestReqOptionContextAndTimeout covers the context and timeout options,
// including a cancelled context.
func TestReqOptionContextAndTimeout(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	resp, err := c.Get(srv.URL+"/echo", Timeout(5*time.Second), Context(context.Background()))
	if err != nil {
		t.Fatalf("Get with context: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Get(srv.URL+"/echo", Context(ctx)); err == nil {
		t.Fatal("expected an error for a cancelled context")
	}

	// The builder form must apply the same deadline.
	if _, err := c.R().SetTimeout(5 * time.Second).Get(srv.URL + "/echo"); err != nil {
		t.Fatalf("SetTimeout: %v", err)
	}
}

// TestRequestPathParams covers {name} and :name substitution.
func TestRequestPathParams(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	resp, err := c.R().SetPathParam("id", "42").Get(srv.URL + "/item/{id}")
	if err != nil {
		t.Fatalf("SetPathParam: %v", err)
	}
	if got := decodeEcho(t, resp).Path; got != "/item/42" {
		t.Fatalf("path = %q, want /item/42", got)
	}

	resp, err = c.R().SetPathParams(map[string]string{"org": "acme", "repo": "tlsprint"}).
		Get(srv.URL + "/:org/:repo")
	if err != nil {
		t.Fatalf("SetPathParams: %v", err)
	}
	if got := decodeEcho(t, resp).Path; got != "/acme/tlsprint" {
		t.Fatalf("path = %q, want /acme/tlsprint", got)
	}
}

// TestRequestFormAndMultipart covers the form encoders on the Request builder.
func TestRequestFormAndMultipart(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	resp, err := c.R().SetFormData(map[string]string{"a": "1", "b": "2"}).Post(srv.URL + "/form")
	if err != nil {
		t.Fatalf("SetFormData: %v", err)
	}
	e := decodeEcho(t, resp)
	if !strings.Contains(e.Body, "a=1") || !strings.Contains(e.Body, "b=2") {
		t.Fatalf("form body = %q", e.Body)
	}
	if got := e.header("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q", got)
	}

	resp, err = c.R().SetMultipartFormData(map[string]string{"field": "value"}).Post(srv.URL + "/upload")
	if err != nil {
		t.Fatalf("SetMultipartFormData: %v", err)
	}
	e = decodeEcho(t, resp)
	if ct := e.header("Content-Type"); !strings.HasPrefix(ct, "multipart/form-data; boundary=") {
		t.Fatalf("Content-Type = %q", ct)
	}
	if !strings.Contains(e.Body, `name="field"`) || !strings.Contains(e.Body, "value") {
		t.Fatalf("multipart body = %q", e.Body)
	}
}

// TestClientSetterChain covers the chainable configuration surface.
func TestClientSetterChain(t *testing.T) {
	srv := startAPI(t)

	c := NewClient()
	if got := c.
		SetTimeout(10*time.Second).
		SetHeader("X-Default", "yes").
		SetHeaders(map[string]string{"X-Extra": "1"}).
		SetHeaderOrder("User-Agent", "Accept").
		SetBaseURL(srv.URL).
		SetRedirects(-1).
		SetPermuteExtensions(true).
		ForceHTTP1().
		UseAutoProtocol().
		SetInsecureSkipVerify(true).
		SetRootCAs(nil).
		SetProxy(""); got != c {
		t.Fatal("setters must return the same *Client for chaining")
	}
	if !c.permute {
		t.Fatal("SetPermuteExtensions(true) did not stick")
	}
	c.SetPermuteExtensions(false)

	// Defaults from SetHeader/SetHeaders reach the wire.
	resp, err := c.Get("/defaults")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	e := decodeEcho(t, resp)
	if e.header("X-Default") != "yes" || e.header("X-Extra") != "1" {
		t.Fatalf("default headers missing: %+v", e.Header)
	}
	if e.Path != "/defaults" {
		t.Fatalf("SetBaseURL: path = %q", e.Path)
	}

	// Cookie jar can be turned on and off.
	c.EnableCookieJar()
	if _, err := c.Get("/set-cookie"); err != nil {
		t.Fatalf("EnableCookieJar: %v", err)
	}
	resp, err = c.Get("/defaults")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := decodeEcho(t, resp).header("Cookie"); !strings.Contains(got, "srv=c1") {
		t.Fatalf("cookie jar did not store the cookie: %q", got)
	}
	c.DisableCookieJar()

	// Redirects: default follows, SetRedirects(0) stops.
	resp, err = c.SetRedirects(0).Get("/redirect")
	if err != nil {
		t.Fatalf("Get redirect: %v", err)
	}
	if resp.StatusCode() != http.StatusFound {
		t.Fatalf("SetRedirects(0) status = %d, want 302", resp.StatusCode())
	}
	c.SetRedirects(-1)
	resp, err = c.Get("/redirect")
	if err != nil {
		t.Fatalf("Get redirect: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("default redirect status = %d, want 200", resp.StatusCode())
	}

	if c.Preset() == nil {
		t.Fatal("Preset() returned nil")
	}
	c.Close()
}

// TestClientSettersValidation covers the error branches of the configuration
// API.
func TestClientSettersValidation(t *testing.T) {
	c := NewClient()

	if err := c.SetBrowser("no-such-preset"); err == nil {
		t.Fatal("SetBrowser with an unknown name must fail")
	}
	if err := c.SetBrowser((*preset.Preset)(nil)); err == nil {
		t.Fatal("SetBrowser(nil preset) must fail")
	}
	if err := c.SetBrowser(42); err == nil {
		t.Fatal("SetBrowser with a wrong type must fail")
	}
	if err := c.SetRandomBrowser("no-such-product"); err == nil {
		t.Fatal("SetRandomBrowser with an unknown product must fail")
	}
	if err := c.SetRandomBrowser("*"); err != nil {
		t.Fatalf("SetRandomBrowser(*): %v", err)
	}
	if err := c.SetRandomBrowser("chrome"); err != nil {
		t.Fatalf("SetRandomBrowser(chrome): %v", err)
	}
	if err := c.SetPreset("firefox"); err != nil {
		t.Fatalf("SetPreset: %v", err)
	}
	if got := c.Preset(); got == nil || got.Product != "firefox" {
		t.Fatalf("SetPreset did not switch the preset: %+v", got)
	}
}

// TestWithOptionsConstructors covers the Client option constructors.
func TestWithOptionsConstructors(t *testing.T) {
	srv := startAPI(t)
	p := preset.MustBuiltin().Lookup("chrome-155")
	if p == nil {
		t.Fatal("chrome-155 preset missing")
	}

	c := NewClient(
		WithTimeout(5*time.Second),
		WithPreset(p),
		WithPermuteExtensions(),
		WithInsecureSkipVerify(true),
		WithRootCAs(nil),
		WithProxy(""),
	)
	defer c.Close()
	if !c.permute {
		t.Fatal("WithPermuteExtensions did not enable permutation")
	}
	if c.Preset().Key != p.Key {
		t.Fatalf("WithPreset: got %s, want %s", c.Preset().Key, p.Key)
	}
	if resp, err := c.Get(srv.URL + "/ping"); err != nil || resp.StatusCode() != http.StatusOK {
		t.Fatalf("Get with options: resp=%v err=%v", resp, err)
	}
}

// TestImpersonateWithPresetObject covers the *preset.Preset branch of
// Impersonate and the nil-safety of the option.
func TestImpersonateWithPresetObject(t *testing.T) {
	srv := startAPI(t)
	p := preset.MustBuiltin().Lookup("TLS_SAFARI_26_0_1_MACOS_18_3")
	if p == nil {
		t.Fatal("safari preset missing")
	}

	resp, err := Get(srv.URL+"/ping", Impersonate(p))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := decodeEcho(t, resp).header("User-Agent"), p.UserAgent(); got != want {
		t.Fatalf("UA = %q, want %q", got, want)
	}

	// Impersonate(nil) must not panic or change the client.
	c := NewClient()
	before := c.Preset()
	Impersonate(nil)(c)
	Impersonate((*preset.Preset)(nil))(c)
	if c.Preset() != before {
		t.Fatal("Impersonate(nil) changed the preset")
	}
}

// TestTLSInsecureAndCustomRoots covers the TLS security setters end to end.
func TestTLSInsecureAndCustomRoots(t *testing.T) {
	srv := startTLSServer(t, true)

	t.Run("custom roots", func(t *testing.T) {
		c := NewClient(WithRootCAs(rootsOf(t, srv)))
		defer c.Close()
		resp, err := c.Get(srv.URL + "/check")
		if err != nil {
			t.Fatalf("Get with custom roots: %v", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode())
		}
	})

	t.Run("insecure skip verify", func(t *testing.T) {
		c := NewClient()
		defer c.Close()
		c.SetInsecureSkipVerify(true)
		if _, err := c.Get(srv.URL + "/check"); err != nil {
			t.Fatalf("Get with skip-verify: %v", err)
		}
	})

	t.Run("untrusted certificate fails", func(t *testing.T) {
		c := NewClient()
		defer c.Close()
		if _, err := c.Get(srv.URL + "/check"); err == nil {
			t.Fatal("expected certificate verification to fail without roots")
		}
	})
}

// TestResponseAccessors covers the Response helper surface.
func TestResponseAccessors(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()
	resp, err := c.Get(srv.URL + "/thing?status=200")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("StatusCode = %d", resp.StatusCode())
	}
	if !strings.Contains(resp.Status(), "200") {
		t.Fatalf("Status = %q", resp.Status())
	}
	if resp.Header().Get("X-Echo") != "1" {
		t.Fatalf("Header missing X-Echo: %v", resp.Header())
	}
	if len(resp.Body()) == 0 || string(resp.Body()) != resp.String() {
		t.Fatal("Body/String mismatch")
	}
	if len(resp.RawBody()) == 0 {
		t.Fatal("RawBody is empty")
	}
	if !strings.HasPrefix(resp.Proto(), "HTTP/1.") && resp.Proto() != "HTTP/2.0" {
		t.Fatalf("Proto = %q", resp.Proto())
	}
	if !strings.Contains(resp.RequestURL(), "/thing") {
		t.Fatalf("RequestURL = %q", resp.RequestURL())
	}
	if !resp.IsSuccess() || resp.IsError() {
		t.Fatalf("IsSuccess/IsError wrong: success=%v error=%v", resp.IsSuccess(), resp.IsError())
	}
	if resp.Time() <= 0 {
		t.Fatalf("Time = %v", resp.Time())
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 || cookies[0].Name != "srv" {
		t.Fatalf("Cookies = %v", cookies)
	}

	var e echo
	if err := resp.JSON(&e); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	errResp, err := c.Get(srv.URL + "/thing?status=503")
	if err != nil {
		t.Fatalf("Get 503: %v", err)
	}
	if !errResp.IsError() || errResp.IsSuccess() {
		t.Fatalf("IsError wrong for 503: success=%v", errResp.IsSuccess())
	}
}

// TestResolveURLErrors covers the URL parsing error path.
func TestResolveURLErrors(t *testing.T) {
	c := NewClient()
	if _, err := c.Get("://bad-url"); err == nil {
		t.Fatal("expected a URL parse error")
	}
}

// TestExecuteHeadersArgument covers the trailing header-map argument of the
// verb helpers.
func TestExecuteHeadersArgument(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()
	resp, err := c.R().Get(srv.URL+"/h", map[string]string{"X-Trailing": "yes"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := decodeEcho(t, resp).header("X-Trailing"); got != "yes" {
		t.Fatalf("trailing header = %q", got)
	}
}

// TestBodyEncodeError covers the encoder error path for an unmarshalable body.
func TestBodyEncodeError(t *testing.T) {
	c := NewClient()
	srv := startAPI(t)
	if _, err := c.Post(srv.URL+"/echo", Body(func() {})); err == nil {
		t.Fatal("expected a JSON encoding error for a func body")
	}
}

// TestProxyUnsupportedScheme covers proxy URL validation.
func TestProxyUnsupportedScheme(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()
	defer c.Close()
	c.SetProxy("socks5://127.0.0.1:1") // not supported by this client
	if _, err := c.Get(srv.URL + "/ping"); err == nil {
		t.Fatal("expected an unsupported-proxy-scheme error")
	}
}

// TestNoPresetError covers the round trip guard for a client without a preset.
func TestNoPresetError(t *testing.T) {
	c := &Client{
		timeout:         DefaultTimeout,
		defaultHeaders:  make(http.Header),
		explicitHeaders: make(map[string]bool),
	}
	c.rt = &roundTripper{noH2: make(map[string]bool), owner: c}
	c.rebuildHTTPClientLocked()
	_, err := c.Get("https://example.invalid/")
	if err == nil {
		t.Fatal("expected an error without a preset")
	}
	if !strings.Contains(err.Error(), "no preset") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestBodyTypeDoc documents and pins the verbatim body encodings: nil, string
// and []byte are sent as-is with no content type.
func TestBodyTypeDoc(t *testing.T) {
	for _, tc := range []struct {
		body any
		want string
	}{
		{nil, ""},
		{"s", "s"},
		{[]byte("b"), "b"},
	} {
		got, ct, err := (&Request{body: tc.body}).encodeBody()
		if err != nil {
			t.Fatalf("encodeBody(%v): %v", tc.body, err)
		}
		if string(got) != tc.want || ct != "" {
			t.Fatalf("encodeBody(%v) = %q/%q", tc.body, got, ct)
		}
	}
}

// TestBuilderVerbs covers the Request-builder verb helpers that the
// functional-option API does not exercise.
func TestBuilderVerbs(t *testing.T) {
	srv := startAPI(t)
	c := NewClient()

	verbs := []struct {
		name string
		call func(string, ...map[string]string) (*Response, error)
		want string
	}{
		{"Put", c.R().Put, http.MethodPut},
		{"Patch", c.R().Patch, http.MethodPatch},
		{"Delete", c.R().Delete, http.MethodDelete},
		{"Options", c.R().Options, http.MethodOptions},
	}
	for _, v := range verbs {
		resp, err := v.call(srv.URL + "/builder")
		if err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		if e := decodeEcho(t, resp); e.Method != v.want {
			t.Fatalf("%s: server saw %s", v.name, e.Method)
		}
	}

	// Head has no body to echo, so only the status is checked.
	resp, err := c.R().Head(srv.URL + "/builder")
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("Head status = %d", resp.StatusCode())
	}

	// Builder header/query setters and the PathParam/FormData options.
	resp, err = c.R().
		SetHeader("X-Builder", "1").
		SetHeaders(map[string]string{"X-Builder-2": "2"}).
		SetQueryParams(map[string]string{"qb": "2"}).
		SetQueryParam("qa", "1").
		SetFormData(map[string]string{"f": "v"}).
		Post(srv.URL + "/builder")
	if err != nil {
		t.Fatalf("builder setters: %v", err)
	}
	e := decodeEcho(t, resp)
	if e.header("X-Builder") != "1" || e.header("X-Builder-2") != "2" {
		t.Fatalf("builder headers missing: %+v", e.Header)
	}
	q, err := url.ParseQuery(e.Query)
	if err != nil {
		t.Fatalf("query %q: %v", e.Query, err)
	}
	if q.Get("qa") != "1" || q.Get("qb") != "2" {
		t.Fatalf("builder query = %q", e.Query)
	}
	if !strings.Contains(e.Body, "f=v") {
		t.Fatalf("FormData option body = %q", e.Body)
	}

	resp, err = c.Post(srv.URL+"/builder/{slug}",
		PathParam("slug", "via-option"), FormData(map[string]string{"g": "w"}))
	if err != nil {
		t.Fatalf("PathParam/FormData options: %v", err)
	}
	e = decodeEcho(t, resp)
	if e.Path != "/builder/via-option" {
		t.Fatalf("PathParam option: path = %q", e.Path)
	}
	if !strings.Contains(e.Body, "g=w") {
		t.Fatalf("FormData option body = %q", e.Body)
	}
}

// TestUseHTTP2Pinned covers UseHTTP2 and its interaction with root CAs: the
// preset must negotiate h2 when the server offers it.
func TestUseHTTP2Pinned(t *testing.T) {
	srv := startTLSServer(t, true)
	c := NewClient(WithRootCAs(rootsOf(t, srv)))
	defer c.Close()
	c.UseHTTP2()
	resp, err := c.Get(srv.URL + "/check")
	if err != nil {
		t.Fatalf("UseHTTP2 Get: %v", err)
	}
	if got := resp.Proto(); got != "HTTP/2.0" {
		t.Fatalf("Proto = %q, want HTTP/2.0", got)
	}
}

// TestDecodeBodyEncodings covers every Content-Encoding branch, the reversed
// multi-encoding chain, and the raw-bytes fallback for unknown or corrupt
// encodings.
func TestDecodeBodyEncodings(t *testing.T) {
	payload := []byte("tlsprint decode body")

	gzipped := func() []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(payload)
		_ = w.Close()
		return buf.Bytes()
	}
	deflated := func() []byte {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		_, _ = w.Write(payload)
		_ = w.Close()
		return buf.Bytes()
	}
	brotlied := func() []byte {
		var buf bytes.Buffer
		w := brotli.NewWriter(&buf)
		_, _ = w.Write(payload)
		_ = w.Close()
		return buf.Bytes()
	}
	zstded := func() []byte {
		var buf bytes.Buffer
		w, err := zstd.NewWriter(&buf)
		if err != nil {
			t.Fatalf("zstd writer: %v", err)
		}
		_, _ = w.Write(payload)
		_ = w.Close()
		return buf.Bytes()
	}

	cases := []struct {
		name     string
		encoding string
		raw      []byte
		want     []byte
	}{
		{"identity", "identity", payload, payload},
		{"gzip", "gzip", gzipped(), payload},
		{"deflate", "deflate", deflated(), payload},
		{"brotli", "br", brotlied(), payload},
		{"zstd", "zstd", zstded(), payload},
		{"chain", "gzip, br", brotlied(), nil}, // br-then-gzip on the wire is bogus
		{"unknown", "snappy", payload, payload},
		{"corrupt gzip", "gzip", []byte("not gzip at all"), []byte("not gzip at all")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := decodeBody(tc.encoding, tc.raw)
			if tc.name == "chain" {
				// A mismatched chain must not lose data: the fallback returns
				// the original bytes.
				if !bytes.Equal(got, tc.raw) {
					t.Fatalf("chain fallback = %q, want the raw bytes", got)
				}
				return
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("decodeBody(%q) = %q, want %q", tc.encoding, got, tc.want)
			}
		})
	}

	// A genuine chain: gzip applied first, then br, decoded in reverse.
	var outer bytes.Buffer
	bw := brotli.NewWriter(&outer)
	_, _ = bw.Write(gzipped())
	_ = bw.Close()
	if got := decodeBody("gzip, br", outer.Bytes()); !bytes.Equal(got, payload) {
		t.Fatalf("chained decode = %q, want %q", got, payload)
	}
}

// TestProxyHostname covers the helper used to derive the CONNECT authority.
func TestProxyHostname(t *testing.T) {
	if got := proxyHostname("example.com:443"); got != "example.com" {
		t.Fatalf("proxyHostname = %q", got)
	}
	if got := proxyHostname("example.com"); got != "example.com" {
		t.Fatalf("proxyHostname without port = %q", got)
	}
}

// TestNewRoundTripper covers the exported-for-tests constructor.
func TestNewRoundTripper(t *testing.T) {
	rt := newRoundTripper()
	if rt == nil || rt.noH2 == nil {
		t.Fatal("newRoundTripper returned an unusable transport")
	}
}
