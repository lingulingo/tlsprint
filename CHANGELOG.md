# Changelog

All notable changes to tlsprint are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [v1.0.4] - 2026-09-28

模块标签：`v1.0.4`（根模块，含 preset 数据）、`utls/v1.0.1`、`client/v1.0.4`。
`utls` 与 `client` 本次只上抬了对根模块的依赖（`v1.0.0` → `v1.0.4`）——预设数据内嵌在
根模块里，不这样抬，`client`/`utls` 的使用者拿到的仍是旧的 47 个预设。

### Added

- **Presets**: `TLS_CHROME_153_MACOS_10_15_7` 和 `TLS_CHROME_154_MACOS_10_15_7`，
  来自 `tls.peet.ws` 抓包（注册表现共 49 个；`Lookup("chrome")` 现在解析到 154）。
  两者都由 JA3 不变量测试覆盖，并已加入 `utls` 的线上字节级回环测试。

  Chrome 153/154 在**传输层与 152 完全相同**：同样的 15 个 cipher、同样的 17 个扩展
  集合、同样的 `supported_groups`/`supported_versions`/签名算法，JA4
  （`t13d1517h2_8daaf6152771_cb7bf5808d99`）与 Akamai HTTP/2 指纹
  （`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`）逐字节一致。真正随版本变化的
  只有 **Client Hints**：版本号，以及 Chrome 每个版本伪随机轮换的 grease 品牌名
  （152 = `"Not?A_Brand";v="24"`、153 = `"Not_A Brand";v="8"`、
  154 = `"Not A(Brand";v="99"`）——只能抓，无法推导。

  和所有 Chrome 预设一样，线上**扩展顺序只是一个抽样**：Chrome 每次连接都会打乱，
  所以 JA3 会变，而 JA4 / peetprint 稳定。

## [v1.0.3] - 2026-09-10

模块标签：`http2/v1.0.1`、`client/v1.0.3`（`client` 现在依赖 `http2 v1.0.1`）。

### Fixed

- **http2** (fork): the receive window enforced locally is now aligned with the
  window a `Fingerprint` advertises on the wire. A preset that advertises a
  wider stream window than the transport's 4 MiB default (Chrome 6 MiB, curl
  8.4 10 MiB, OkHttp 16 MiB — 29 of the 47 curated presets) let a fully
  compliant server overflow the client's own accounting, tearing the connection
  down with a spurious `FLOW_CONTROL_ERROR` partway through any body larger than
  ~4 MiB. The connection-level window is aligned the same way. Covered by
  `TestFingerprintAdvertisedWindowIsEnforcedLocally` (8 MiB body across five
  advertised windows).
- **client**: `SetResult` decoded the raw, still-compressed response body rather
  than the decompressed one, so it failed with `invalid character '\x1f'` on any
  gzip/br/zstd-encoded 2xx. Presets send `Accept-Encoding` themselves, which
  suppresses net/http's transparent decompression. It now decodes the same bytes
  as `Response.JSON`.
- **client**: the top-level `client.Get(..., Impersonate("firefox-145"))` form
  sent the *default* preset's headers (e.g. Chrome's User-Agent) on top of the
  requested preset's TLS fingerprint, because `Impersonate` assigned the preset
  without re-applying header defaults or rebuilding the transports. It now
  routes through `SetBrowser`, so headers and connections follow the preset.
- **client**: plain `http://` targets silently bypassed a configured proxy and
  were dialled directly. They now go through net/http's proxy support
  (absolute-form request line), while `https://` targets keep the existing
  CONNECT tunnel. A cleartext target therefore requires a plaintext proxy; an
  `https://` proxy combined with an `http://` target now reports an explicit
  error instead of quietly connecting directly.

## [v1.0.2] - 2026-09-03

### Fixed

- **client**: HTTP proxies now support **username:password** in the URL
  (`http://user:pass@host:port`). The tunnelled CONNECT request includes the
  `Proxy-Authorization` header (Basic auth). Verified with an authenticated
  CONNECT-proxy integration test.

## [v1.0.1] - 2026-09-03

### Fixed

- **client**: the response body is now decompressed automatically from the
  `Content-Encoding` header (gzip, deflate, `br`, `zstd`), so
  `Response.String()/Body()/JSON()` return readable content. `RawBody()` keeps
  the original compressed bytes. Fixes `invalid character '\x8f'` when parsing
  a brotli-encoded JSON response (e.g. TikTok) without manual decoding.

## [v1.0.0]

Initial open-source release.

### Added

- **Core model** (`tlsprint` root package): `Profile`, `TLSProfile`,
  `HTTP2Profile`, `HeaderProfile` with JSON round-tripping and validation.
- **Registries** (`tlsprint/iana`): name↔id tables for TLS extensions, cipher
  suites, named groups, signature algorithms, versions and HTTP/2 settings,
  plus RFC 8701 GREASE semantics (`IsGrease`, `GreaseMarker`, `NextGrease`).
- **Wire codec** (`tlsprint/hello`): byte-faithful ClientHello parse and
  construction (record / bare-handshake / bare-body auto-detection), strict
  decoders and encoders for well-known extensions, profile extraction.
- **Codecs**:
  - `tlsprint/ja3` — canonical JA3 strings and md5 hashes (GREASE-free per
    ecosystem convention), parse and format helpers.
  - `tlsprint/ja4` — JA4 fingerprints implemented against the FoxIO JA4
    specification, validated with the spec's canonical example vector
    (`t13d1516h2_8daaf6152771_e5627efa2ab1`).
- **Preset registry** (`tlsprint/preset`): 46 curated fingerprints embedded
  from `preset/data/registry.json`, lookup by exact/normalised name or by
  product, with a data-provenance statement and the JA3-re-derivation
  invariant enforced in tests.
- **uTLS adapter** (`tlsprint/utls`, separate Go module): profile → uTLS
  `ClientHelloSpec` conversion with documented GREASE/ALPN/key-share options,
  pinned against `github.com/refraction-networking/utls v1.8.2`.
- **TLS dial API** (`tlsprint/utls`): `Dial` / `DialByName` apply a preset
  fingerprint and complete a real TLS handshake (custom dialer, root pool and
  verification options included). Loopback integration tests capture the
  ClientHello actually sent and assert its canonical JA3 equals the preset's.
- **Chrome 152 preset** (`TLS_CHROME_152_MACOS_10_15_7`): added from a real
  `tls.peet.ws` capture — cipher order, groups (incl. X25519MLKEM768),
  versions, signature algorithms (with a leading GREASE), HTTP/2 settings and
  header defaults; verified end-to-end against `tls.peet.ws` (server-reported
  JA3 matches) and a real Akamai-protected site.
- **Unknown-extension raw payloads** (`tlsprint.TLSProfile.ExtraExtensions`):
  profiles can carry opaque bodies for extension types the semantic model does
  not decode (e.g. Chrome's 0xCA34), so engines can reproduce them exactly.
- **Handshake compatibility fixes** (`tlsprint/utls`), validated against a
  real Akamai-protected site:
  - GREASE markers inside payload lists (supported_groups, supported_versions)
    are now emitted as randomized GREASE values rather than literal
    placeholders, which strict servers reject as invalid identifiers.
  - Extensions that profiles list but carry no payload — SCT (18) and the
    ALPS codepoints (17513 / 17613) — are omitted instead of being marshaled
    as malformed zero-length bodies (a fatal `decode_error` on Akamai).
  - `psk_key_exchange_modes` defaults to `psk_dhe_ke` (Chrome's value) when a
    profile records the extension but not the modes.
  - ECH is emitted as Chrome's GREASE ECH (`BoringGREASEECH`) when no ECH
    configs are present.
  - ALPS (17513 / 17613), SCT (18) and post_handshake_auth (49) are now
    emitted with their correct wire forms (previously omitted); unknown
    extension types carry their raw `ExtraExtensions` payload when one exists,
    and are omitted otherwise rather than emitting a malformed empty body.
- **JA4**: GREASE values in the signature-algorithm list are now ignored, per
  the JA4 spec (Chrome prefaces sigalgs with a GREASE value).
- **HTTP/2 fingerprinting (option C)** — forked `tlsprint/http2` transport
  (based on `golang.org/x/net/http2`) with a configurable connection
  fingerprint: exact SETTINGS parameter order, the initial WINDOW_UPDATE, the
  request pseudo-header order (`m,a,s,p`), the request header order, and the
  stream priority on the HEADERS frame. The `client` applies these from the
  preset's HTTP/2/header profiles. Verified live against `tls.peet.ws`:
  the reported `akamai_fingerprint` and the HEADERS field order match the real
  Chrome 152 capture exactly.
- **Client header defaults**: `SetBrowser` now also applies the preset's
  declared header values (sec-ch-ua, accept, ...) as default request headers,
  refreshed on preset switch, unless the user set them explicitly.
- **curl_cffi-style API**: module-level `client.Get/Post/...` with the
  fingerprint passed on the call (`Impersonate("chrome-152")`) plus reusable
  session verbs and request options (`Header/Headers/Query/Cookie/Body/...`).
- **Automatic response decompression** (`client`): `Body`/`String`/`JSON` now
  decode the response based on `Content-Encoding` (gzip, deflate, br, zstd)
  transparently; `RawBody()` exposes the original compressed bytes.
- **Release-readiness fixes** (from an independent adversarial review):
  - Newest-preset resolution now compares versions numerically
    (`Lookup("curl")` correctly returns 8.16.0, not 8.9.1).
  - `Client` is genuinely safe for concurrent use: `baseURL` is snapshotted
    into each request; added `Close`/`CloseIdleConnections` and the module-level
    helpers recycle their connection pool.
  - `ja3.Compute`/`FromProfile` no longer panic on nil.
  - `TLSProfile.Validate` now enforces real structural invariants (duplicate
    ids, empty ciphers/extensions) and adds `ValidateStrict`.
  - HTTP/2 h1 fallback only retries idempotent requests with a replayable body.
  - The preset's HTTP/2 PRIORITY frames are forwarded to the wire.
  - `https://` proxies are dialed over TLS (and unknown schemes are rejected)
    instead of silently downgrading to plaintext.
  - Removed a duplicate SETTINGS field in the http2 fork; client package docs
    updated to reflect the implemented HTTP/2 fingerprinting.
- **CLI** (`cmd/tlsprint`): `list`, `show`, `fp` subcommands.
- **HTTP client** (`tlsprint/client`, separate Go module): resty/proteus-style
  `NewClient().SetBrowser(...)` + fluent `R()` builder with Get/Post/Put/Patch/
  Delete/Head, query/path params, headers, auth, JSON/form/multipart bodies,
  result decoding, cookies, redirects, CONNECT proxies and timeouts. TLS
  fingerprinting is applied per connection through the uTLS adapter; HTTP/2 is
  attempted first with automatic HTTP/1.1 fallback (`ForceHTTP1()`/`UseHTTP2()`
  to pin). Covered by loopback integration tests (h2, h1 fallback, forms,
  redirects, cookies).
- **Tooling** (`tools/importproteus`): reproducible converter from a reference
  preset export to the canonical registry data.
- **Docs**: English and Chinese README, data provenance, contribution and
  security guides, CI workflow.
