# 🌀 tlsprint

**English** | [简体中文](README.md)
<p align="center">
  <a href="https://pkg.go.dev/github.com/lingulingo/tlsprint/client"><img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/lingulingo/tlsprint/client.svg"></a>
  <a href="https://github.com/lingulingo/tlsprint/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lingulingo/tlsprint/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.24+-00ADD8.svg">
</p>

**Engine-independent TLS fingerprint library for Go — with a byte-exact,
curl_cffi-style impersonating HTTP client, and zero CGO.**

**Keywords:** Go TLS fingerprint · JA3 · JA4 · uTLS · browser impersonation ·
HTTP/2 fingerprint · anti-bot · Go HTTP client · fingerprint database.

> 📦 **Go Reference** (mirrored to pkg.go.dev):
> [github.com/lingulingo/tlsprint/client](https://pkg.go.dev/github.com/lingulingo/tlsprint/client)

`tlsprint` describes **what a TLS client really puts on the wire** — ciphers,
extension order, groups, signature algorithms, HTTP/2 settings, header order —
as typed, JSON-friendly, engine-independent data. It computes JA3/JA4, parses
and builds raw ClientHello bytes, ships a curated registry of 47 real client
fingerprints, and drives real impersonated connections through uTLS with a
**byte-exact HTTP/2 level**, verified live against `tls.peet.ws`.

> ⚠️ **Disclaimer.** This library is for TLS-protocol research and for testing
> anti-bot fingerprinting. Use it only against systems you own or are allowed
> to test.

> 🛡️ **Usage & ethics.** This library is for TLS-protocol research, authorized
> testing, and defensive security research. **Use it only against systems you
> own or are explicitly authorized to test**, and respect each site's Terms of
> Service. Any use for unauthorized access, bypassing anti-bot protection you
> are not permitted to circumvent, or causing harm is outside the intended
> scope; misuse is your responsibility.

---

## 📦 Installation

```sh
# Core data layer + preset registry (stdlib only)
go get github.com/lingulingo/tlsprint@latest

# uTLS adapter + Dial API (needed by the HTTP client)
go get github.com/lingulingo/tlsprint/utls@latest

# HTTP client (curl_cffi-style Get/Post)
go get github.com/lingulingo/tlsprint/client@latest
# forked byte-exact HTTP/2 transport (pulled in by the client automatically)
# go get github.com/lingulingo/tlsprint/http2@latest
```

Inside this repository the modules are wired together with local `replace`
directives, so `go test ./...` works out of the box. Each module carries a
`replace` to its sibling directory for development only; Go ignores those when
the module is fetched remotely, so consumers resolve the published versions
(see [Publishing](#publishing)).

> **Go version:** the modules target Go **1.24+** (the `http2` fork needs the
> Go 1.24 standard library's HTTP/2 and codec APIs).

---

## 🚀 Quick start

### curl_cffi-style: pass the fingerprint on the call

```go
package main

import (
	"fmt"

	tlsclient "github.com/lingulingo/tlsprint/client"
)

func main() {
	// Module-level convenience — like curl_cffi's requests.get(url, impersonate=...).
	resp, err := tlsclient.Get("https://httpbin.org/get",
		tlsclient.Impersonate("chrome-152"),         // fingerprint preset
		tlsclient.Query("q", "tls fingerprint"),     // query param
		tlsclient.Header("X-Api-Key", "secret"),     // request header
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.StatusCode(), resp.Status()) // 200 200 OK
	fmt.Println(resp.Proto())                     // HTTP/2.0 (or HTTP/1.1)
	fmt.Println(resp.String())

	// POST JSON and auto-decode the 2xx response into a struct.
	var result map[string]any
	resp, err = tlsclient.Post("https://httpbin.org/post",
		tlsclient.Impersonate("chrome-152"),
		tlsclient.Body(map[string]any{"name": "tlsprint"}),
		tlsclient.Result(&result),
	)
	fmt.Println(result)
}
```

`Impersonate` accepts a preset name (`"chrome-152"`, `"firefox-145"`,
`"safari-26-0-1"`, or `"chrome"` = newest) or a `*preset.Preset`. The preset's
browser headers (`user-agent`, `sec-ch-ua`, `accept`, …) are **sent
automatically** — you only override what you need.

### Reusable session / fluent builder

```go
c := tlsclient.NewClient(tlsclient.Impersonate("chrome-152"))
c.SetTimeout(30 * time.Second)
c.SetProxy("http://127.0.0.1:8080")   // optional: HTTP CONNECT proxy
c.EnableCookieJar()                   // optional: automatic cookies

resp, err := c.Get("https://httpbin.org/get", tlsclient.Query("q", "hi"))
// or the fluent builder:
resp, err = c.R().SetQueryParam("q", "hi").Get("https://httpbin.org/get")
```

### Working with the data layer directly

```go
p := preset.MustBuiltin().Lookup("chrome-152")
fmt.Println(p.Key, p.Product, p.Version, p.UserAgent())

s := ja3.FromProfile(&p.TLS)  // canonical JA3 string
fmt.Println(s, ja3.Hash(s))   // + classic md5 id

// From captured bytes (full TLS record, bare handshake or bare body):
ch, err := hello.Parse(capturedBytes)
prof, _ := ch.TLSProfile()    // wire bytes → semantic profile
fmt.Println(ja3.Compute(ch), ja4.Compute(ch))
```

---

## ✨ Highlights

- **Pure Go, zero CGO.** The whole stack (TLS via uTLS, HTTP/2 via a forked
  `x/net/http2`) builds anywhere with just a Go toolchain — no libcurl, no `.so`.
- **Engine-independent data layer.** The root module has **zero third-party
  dependencies** (stdlib only): fingerprints are plain, versioned, JSON data
  that any engine (uTLS, tls-client, your own) can consume.
- **Byte-exact TLS *and* HTTP/2 fingerprints.** JA3/JA4 match the capture, and
  the HTTP/2 SETTINGS order, WINDOW_UPDATE, pseudo/header order and stream
  priority reproduce the real browser (verified on `tls.peet.ws`).
- **Bidirectional codecs.** Not just compute JA3/JA4 — `hello` parses and
  marshals ClientHello bytes byte-for-byte, preserving unknown extensions.
- **50 curated, verifiable presets** (Chrome incl. 155, Firefox, Safari, Edge,
  Opera, curl, OkHttp, WeChat, …). Every preset passes an invariant test that
  its lists re-derive the JA3 of its source capture.
- **curl_cffi-style API** — pass the fingerprint directly on the call — plus a
  fluent `R()` builder for advanced usage.
- **Clean modularity, MIT license, and a reproducible data pipeline.**

---

## 🏗️ Repository layout

One repo, four Go modules. Dependency isolation keeps the core tiny.

| Module | Purpose | Deps |
| --- | --- | --- |
| `tlsprint` (root) | `Profile` model, `iana` registries, `hello` wire codec, `ja3`/`ja4`, `preset` registry, CLI | **stdlib only** |
| `tlsprint/utls` | Profile → uTLS `ClientHelloSpec` + `Dial`/`DialByName` | uTLS |
| `tlsprint/client` | HTTP client (`Get`/`Post`/…) with preset fingerprints | utls + http2 fork |
| `tlsprint/http2` | forked `x/net/http2` transport with a configurable byte-exact fingerprint | x/net |

Root packages: `iana` (identifier registries & GREASE), `hello` (ClientHello
parse/build), `ja3`, `ja4`, `preset` (embedded registry), `cmd/tlsprint` (CLI),
`tools/importproteus` (data regeneration).

---

## 📚 API reference

### Module-level functions (`client`)

| Function | Description |
| --- | --- |
| `Get(url, opts…)` `Post` `Put` `Patch` `Delete` `Head` `Options` | HTTP verbs; each uses a short-lived client |
| `Do(method, url, opts…)` | generic verb |
| `Impersonate(browser) Option` | pick the fingerprint preset (name or `*preset.Preset`) |
| `NewClient(opts …Option) *Client` | reusable session (pooling, cookies, redirects, proxy) |

### Request options

| Option | Effect |
| --- | --- |
| `Header(k, v)` / `Headers(map[string]string)` | request headers (single / dictionary) |
| `Query(k, v)` / `Queries(map)` | query parameters |
| `PathParam(k, v)` | substitute `{name}` in the path |
| `Cookie(name, value)` / `CookieHeader(str)` | cookie / whole Cookie header |
| `Body(any)` / `FormData(map[string]string)` | body (encodes JSON/form automatically) |
| `BasicAuth(u, p)` / `AuthToken(tok)` | Authorization |
| `Result(&v)` | JSON-decode a 2xx response into `v` |
| `Timeout(d)` / `Context(ctx)` | per-request timeout / context |

### Client methods (`client.Client`)

`NewClient` options: `WithTimeout(d)`, `WithProxy(url)`,
`WithInsecureSkipVerify(bool)`, `WithRootCAs(pool)`, `WithPreset(p)`,
`Impersonate(nameOrPreset)`.

Client methods (chainable): `Impersonate`/`SetPreset`/`SetBrowser`,
`SetRandomBrowser`, `Preset`, `R`, `Get/Post/Put/Patch/Delete/Head/Options/Do`,
`SetTimeout`, `SetProxy`, `SetInsecureSkipVerify`, `SetRootCAs`, `SetBaseURL`,
`SetRedirects`, `SetHeader(s)`, `Enable/DisableCookieJar`,
`ForceHTTP1`, `UseHTTP2`, `UseAutoProtocol`.

### Response methods (`client.Response`)

| Method | Description |
| --- | --- |
| `StatusCode() int` / `Status() string` | e.g. `200` / `"200 OK"` |
| `String() string` / `Body() []byte` | decoded response body (gzip/deflate/br/zstd are auto-decompressed) |
| `RawBody() []byte` | the undecoded wire bytes (still compressed) |
| `Header() http.Header` / `Cookies() []*http.Cookie` | headers / Set-Cookie |
| `JSON(v any) error` | decode body into `v` |
| `Proto() string` | `"HTTP/2.0"` or `"HTTP/1.1"` |
| `RequestURL() string` / `Time() time.Duration` | final URL / round-trip time |
| `IsSuccess()` / `IsError()` | 2xx / 4xx–5xx |

> Non-2xx responses are **not** errors — check `resp.IsSuccess()`. Errors are
> only network/transport/encoding failures.
>
> **Automatic decompression**: the body is decoded from the response
> `Content-Encoding` (gzip, deflate, `br`, `zstd`), so `resp.String()` /
> `resp.Body()` / `resp.JSON()` return readable content; use `resp.RawBody()`
> for the original compressed bytes.

### CLI

```sh
go install github.com/lingulingo/tlsprint/cmd/tlsprint@latest
tlsprint list chrome          # list chrome presets
tlsprint show chrome-152      # preset as JSON
tlsprint fp -preset chrome    # canonical JA3 + md5
tlsprint fp -hex 16030300…    # JA3/JA4 of captured bytes
```

---

## 🎯 How tlsprint compares

TLS-fingerprinting libraries fall into two camps: **engine-only** (you get a
TLS stack and hand-wire everything) and **client-only** (you get an HTTP client
but the fingerprint definition is glued to one engine). tlsprint separates
the two: a **standard data layer** plus **optional, byte-exact engines**.

| Concern | uTLS | bogdanfinn/tls-client | proteus / curl_cffi | **tlsprint** |
| --- | --- | --- | --- | --- |
| **Fingerprint model** | ad-hoc, per-engine | embedded in client | stringly-typed config | **typed, versioned, JSON, engine-independent** |
| **Root dependency footprint** | the whole TLS stack | whole engine | CGO libcurl | **stdlib only** |
| **CGO / native build needed** | no | no | **yes (curl)** | **no — pure Go everywhere** |
| **JA1/JA3** | via random hello | string | string | **bidirectional + hash** |
| **JA4** | partial | partial | often missing | **spec-compliant, tested against its canonical vector** |
| **HTTP/2 SETTINGS/priority/header-order fidelity** | n/a | Go default (not byte-exact) | C++/fork | **byte-exact (forked `x/net/http2`)** |
| **Preset registry** | hardcoded parrots | hardcoded | large generated | **50 curated + verifiable (JA3 invariant) + reproducible pipeline** |
| **API ergonomics** | low-level | `NewClient().SetBrowser` | curl_cffi | **curl_cffi-style + fluent builder** |

**Why choose tlsprint:**

1. **It's the standard data layer.** Because the fingerprint is plain data,
   you can persist, diff, version, and regenerate it — and you're not locked
   to one impersonation engine.
2. **Pure Go, zero CGO.** No libcurl, no `.so`/`.dll`, no build headaches —
   `go build` just works.
3. **Byte-exact TLS *and* HTTP/2.** Most Go clients do exact TLS but leave
   HTTP/2 at Go defaults; tlsprint reproduces SETTINGS order, WINDOW_UPDATE,
   pseudo/header order and stream priority too.
4. **Verified, not just asserted.** Presets are tested against their source
   JA3; the connection layer is tested by capturing real ClientHellos and
   comparing the JA3 and `akamai_fingerprint` against `tls.peet.ws`.
5. **A clean, comfortable API.** Fingerprint goes on the call
   (`Impersonate("chrome-152")`); browser headers come automatically.

---

## 🧬 Supported fingerprints

Every preset is a real capture and passes the invariant test that its lists
re-derive the JA3 of the source. Look one up by name (`"chrome-152"`,
`"firefox-145"`, `"curl"` = newest of a product, ...).

| Preset | Product | Platform | Version |
|---|---|---|---|
| `TLS_CHROME_130_MACOS_10_15_7` | chrome | macos | 130 |
| `TLS_CHROME_131` | chrome | windows | 131 |
| `TLS_CHROME_133` | chrome | windows | 133 |
| `TLS_CHROME_135` | chrome | windows | 135 |
| `TLS_CHROME_135_K_ANDROID_10` | chrome | android | 135 |
| `TLS_CHROME_138` | chrome | windows | 138 |
| `TLS_CHROME_140` | chrome | windows | 140 |
| `TLS_CHROME_140_K_ANDROID_10` | chrome | android | 140 |
| `TLS_CHROME_141` | chrome | windows | 141 |
| `TLS_CHROME_141_MACOS_10_15_7` | chrome | macos | 141 |
| `TLS_CHROME_142_MACOS_10_15_7` | chrome | macos | 142 |
| `TLS_CHROME_143_MACOS_15_05` | chrome | macos | 143 |
| `TLS_CHROME_144_MACOS_10_15_7` | chrome | macos | 144 |
| `TLS_CHROME_149_0_7827_197_MACOS_10_15_7` | chrome | macos | 149.0.7827.197 |
| `TLS_CHROME_152_MACOS_10_15_7` | chrome | macos | 152 |
| `TLS_CHROME_153_MACOS_10_15_7` | chrome | macos | 153 |
| `TLS_CHROME_154_MACOS_10_15_7` | chrome | macos | 154 |
| `TLS_CHROME_155_MACOS_10_15_7` | chrome | macos | 155 |
| `TLS_FIREFOX_115` | firefox | windows | 115 |
| `TLS_FIREFOX_126` | firefox | windows | 126 |
| `TLS_FIREFOX_135` | firefox | windows | 135 |
| `TLS_FIREFOX_143` | firefox | windows | 143 |
| `TLS_FIREFOX_145` | firefox | windows | 145 |
| `TLS_FIREFOX_151_WINDOWS` | firefox | windows | 151 |
| `TLS_SAFARI_16_5_1_MACOS_10_15_7` | safari | macos | 16.5.1 |
| `TLS_SAFARI_18_1_MACOS_10_15_7` | safari | macos | 18.1 |
| `TLS_SAFARI_18_4_MACOS_10_15_7` | safari | macos | 18.4 |
| `TLS_SAFARI_18_6_IPHONE_IOS_18_6` | safari | ios | 18.6 |
| `TLS_SAFARI_26_0_MACOS_10_15_7` | safari | macos | 26.0 |
| `TLS_SAFARI_26_0_1_MACOS_18_3` | safari | macos | 26.0.1 |
| `TLS_EDGE_131` | edge | windows | 131 |
| `TLS_EDGE_141` | edge | windows | 141 |
| `TLS_EDGE_144_MACOS_10_15_7` | edge | macos | 144 |
| `TLS_EDGE_150_MACOS_10_15_7` | edge | macos | 150 |
| `TLS_OPR_109` | opera | windows | 109 |
| `TLS_OPR_110` | opera | windows | 110 |
| `TLS_OPR_116` | opera | windows | 116 |
| `TLS_CURL_8_13_0` | curl | — | 8.13.0 |
| `TLS_CURL_8_15_0` | curl | — | 8.15.0 |
| `TLS_CURL_8_16_0` | curl | — | 8.16.0 |
| `TLS_CURL_8_4_0` | curl | — | 8.4.0 |
| `TLS_CURL_8_7_1` | curl | — | 8.7.1 |
| `TLS_CURL_8_9_1` | curl | — | 8.9.1 |
| `TLS_OKHTTP_3_12_12` | okhttp | android | 3.12.12 |
| `TLS_WECHAT_8_0_64_IPHONE_IOS_18_6_2` | wechat | ios | 8.0.64 |
| `TLS_POWERSHELL_7_5_3` | powershell | windows | 7.5.3 |
| `TLS_IE_11` | ie | windows | 11 |
| `TLS_CHARLES_5_0_1_CHROME_142` | charles | windows | 5.0.1 |
| `TLS_REQABLE_2_33_7_CHROME_122` | reqable | windows | 2.33.7 |
| `TLS_FIDDLER_5_0_20253_3311_CHROME_122` | fiddler | windows | 5.0.20253.3311 |

---

## 🔬 HTTP/2 fingerprint fidelity

The `client` uses the forked `tlsprint/http2` transport, whose `Fingerprint`
is derived from the preset's HTTP/2 and header profiles and controls the exact
connection handshake: the **SETTINGS payload order**
(`1:65536;2:0;4:6291456;6:262144`), the initial **WINDOW_UPDATE**
(`15663105`), the request **pseudo-header order** (`m,a,s,p`), the request
**header order** and the **HEADERS-frame priority**.

Verified live: against `tls.peet.ws`, the reported `akamai_fingerprint`
(`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`) and the HEADERS field
order both match the real Chrome 152 capture exactly.

> **Honest limit:** byte-exact HTTP/2 fingerprinting is delivered for the
> curated presets. Active bot challenges that require executing JavaScript
> (e.g. an Akamai sensor page) cannot be solved by any HTTP client — you need
> a headless browser or a challenge solver, and a valid session cookie.

---

## 📂 Data provenance & regeneration

`preset/data` holds fingerprints curated from the curl_cffi/curl-impersonate
`tls_config` lineage plus a hand-added Chrome 152 capture. The values are
observations of wire behaviour; the selection, normalisation and tooling here
are original and MIT-licensed. See `preset/data/README.md` for the full
provenance and how to regenerate:

```sh
go run ./tools/importproteus \
  -in /path/to/proteus_dump.json \
  -allow preset/data/ALLOWLIST.txt \
  -out preset/data/registry.json
```

---

## 🧪 Development

```sh
make test         # root module
make vet          # go vet (root)
make test-utls    # utls (TLS adapter / Dial)
make test-client  # client (HTTP client)
make test-http2   # http2 fork (fingerprint frame test)
```

All packages pass `go vet` and golden-vector tests; the invariant
`ja3.FromProfile(p.TLS) == p.TLS.JA3` holds for every preset in the registry.

---

## 🗺️ Roadmap / limits

- **Preset coverage** is 50 curated entries; the pipeline can import hundreds
  more (incl. mobile variants) on demand.
- **Active JS challenges** (Akamai sensor, Cloudflare managed challenge) need
  a browser/solver layer — out of scope for an HTTP client.
- The **`http2` fork** is vendored; it tracks `golang.org/x/net/http2` and
  should be rebased on upstream updates (see `http2/NOTICE`).

---

## 📤 Publishing

This repository is published at **github.com/lingulingo/tlsprint** with a
versioned tag per module:

- root: `v1.0.0`
- `utls/`: `utls/v1.0.0`
- `client/`: `client/v1.0.0`
- `http2/`: `http2/v1.0.0`

The submodules declare their sibling dependencies at the matching version
(`require github.com/lingulingo/tlsprint v1.0.0`, etc.) and carry a
development-only `replace` to the local sibling, which Go ignores when the
module is fetched. `go get github.com/lingulingo/tlsprint/client@v1.0.0`
resolves them for consumers.

---

## 📄 License

MIT — see [LICENSE](LICENSE). The `http2` fork is derived from
`golang.org/x/net/http2` (BSD-3-Clause, The Go Authors; see `http2/NOTICE`).
Browser/product names and trademarks belong to their respective owners and are
used only to describe observed traffic.


---

## ⭐ Support the project

If **tlsprint** helped you — saved you an HTTP client, made your scraper look
like a real browser, or you simply enjoy clean Go fingerprinting — please give
it a **star** ⭐!

- ⭐ **Star the repo** — it's free and signals to others that it's useful.
- 🐞 **Report bugs / request presets** via Issues. New browser fingerprints are
  the fastest way to help.
- 🤝 **Open a PR** — more presets, better HTTP/2 fidelity, docs.

Every star keeps this project alive. Thank you!
