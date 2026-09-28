# tlsprint

[English](README.en.md) | **简体中文**
<p align="center">
  <a href="https://pkg.go.dev/github.com/lingulingo/tlsprint/client"><img alt="Go Reference" src="https://pkg.go.dev/badge/github.com/lingulingo/tlsprint/client.svg"></a>
  <a href="https://github.com/lingulingo/tlsprint/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lingulingo/tlsprint/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.24+-00ADD8.svg">
</p>

**引擎无关的 Go TLS 指纹库 —— 附可直接使用的浏览器模拟 HTTP 客户端。**

`tlsprint` 是 TLS 客户端指纹的"标准数据层"：用类型化、可版本化、可 JSON
往返的结构描述客户端在网络上发送的内容（密码套件、扩展顺序、群组、签名算法、
HTTP/2 行为、Header 顺序），支持 JA3/JA4 指纹计算、原始 ClientHello 的
解析/构造，并内置一份精选的真实浏览器指纹注册表。核心模块**零第三方依赖**。

**关键词：** Go TLS 指纹 · JA3 · JA4 · uTLS · 浏览器模拟(impersonation) · HTTP/2 指纹 ·
反爬虫 / 反机器人 · Go HTTP 客户端 · 指纹数据库。

> 📦 **Go Reference（自动镜像到 pkg.go.dev）:**
> [github.com/lingulingo/tlsprint/client](https://pkg.go.dev/github.com/lingulingo/tlsprint/client)


数据层之上还有两个可选、依赖隔离的模块，让指纹真正可用：

- `tlsprint/utls` —— 把 Profile 接入 [uTLS](https://github.com/refraction-networking/utls)
  引擎，并提供一个 `Dial` 一键拨号（应用指纹 + 完成 TLS 握手）；
- `tlsprint/client` —— resty/proteus 风格的 HTTP 客户端：
  `NewClient().SetBrowser("chrome-141")` 后直接 `c.R().Get(url)` / `.Post(url)`。

> ⚠️ 免责声明：本库仅用于 TLS 协议研究与反机器人指纹测试，请只对你有权
> 测试的系统使用。

> 🛡️ **使用与伦理**：本库仅用于 TLS 协议研究、授权测试与防御向安全研究。**请只对你拥有或明确获准测试的系统使用**，并遵守目标站点的服务条款。任何利用本库进行未授权访问、规避你有权使用的系统以外的反爬机制、或造成危害的行为，均不在本库意图范围内；滥用后果由使用者自行承担。

## 安装

```sh
# 数据层 + 预设注册表（仅标准库）
go get github.com/lingulingo/tlsprint@latest

# uTLS 适配 + Dial API（HTTP 客户端依赖它）
go get github.com/lingulingo/tlsprint/utls@latest

# HTTP 客户端（Get/Post 便捷封装）
go get github.com/lingulingo/tlsprint/client@latest
```

仓库内部已用 `replace` 把三个模块串好，直接 `go test ./...` 即可跑。发布到
你自己的命名空间时，把三个 `go.mod` 里的模块路径一并替换（见
[发布说明](#发布说明)）。

---

## 使用 HTTP 客户端

最高层入口是 `github.com/lingulingo/tlsprint/client`，API 风格对齐
resty/proteus。

### 快速开始（curl_cffi 风格）

指纹直接传在调用里，preset 的浏览器头（user-agent、sec-ch-ua、accept…）自动带上：

```go
package main

import (
	"fmt"

	tlsclient "github.com/lingulingo/tlsprint/client"
)

func main() {
	// 模块级便捷函数，类似 curl_cffi 的 requests.get(url, impersonate=...)。
	resp, err := tlsclient.Get("https://httpbin.org/get",
		tlsclient.Impersonate("chrome-152"),        // 指纹 preset
		tlsclient.Query("q", "tls fingerprint"),     // 查询参数
		tlsclient.Header("X-Api-Key", "secret"),     // 请求头
	)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.StatusCode(), resp.Status()) // 200 200 OK
	fmt.Println(resp.Proto())                     // HTTP/2.0（或 HTTP/1.1）
	fmt.Println(resp.String())

	// POST JSON 并自动反序列化 2xx 响应。
	var result map[string]any
	resp, err = tlsclient.Post("https://httpbin.org/post",
		tlsclient.Impersonate("chrome-152"),
		tlsclient.Body(map[string]any{"name": "tlsprint"}),
		tlsclient.Result(&result),
	)
	fmt.Println(result)
}
```

`Impersonate` 接受 preset 名（`"chrome-152"`、`"firefox-145"`、`"chrome"`=最新）
或 `*preset.Preset`。请求选项有 `Header/Headers`、`Query/Queries`、
`PathParam`、`Cookie/CookieHeader`、`Body/FormData`、`BasicAuth/AuthToken`、
`Result`、`Timeout`、`Context`。

### 可复用会话 / 流式构建器

需要长连接会话（连接池、cookie、重定向、自定义代理）时创建 `Client`，再用它的
直接动词或 `R()` 构建器：

```go
c := tlsclient.NewClient(tlsclient.Impersonate("chrome-152"))
c.SetTimeout(30 * time.Second)
c.SetProxy("http://127.0.0.1:8080")   // 可选 CONNECT 代理
c.EnableCookieJar()                   // 可选 cookie

resp, err := c.Get("https://httpbin.org/get", tlsclient.Query("q", "hi"))
// 或流式构建器：
resp, err = c.R().SetQueryParam("q", "hi").Get("https://httpbin.org/get")
```
### Client 对外接口

`client.NewClient(opts ...Option) *Client`，可选构造参数：

| Option | 作用 |
| --- | --- |
| `WithTimeout(d)` | 单请求超时（默认 `DefaultTimeout` = 30 s） |
| `WithProxy(rawURL)` | HTTP 代理（CONNECT 隧道） |
| `WithInsecureSkipVerify(bool)` | 关闭证书校验（仅测试） |
| `WithRootCAs(*x509.CertPool)` | 自定义信任根 |
| `WithPreset(*preset.Preset)` | 初始指纹 preset |

Client 方法（`Set*` 均可链式调用，并发安全）：

| 方法 | 说明 |
| --- | --- |
| `SetBrowser(nameOrPreset any) error` | 选择 preset：名字（`"chrome-141"`、`"chrome"`、`"TLS_CHROME_141"`）或 `*preset.Preset`；会同步刷新默认 User-Agent |
| `SetPreset(nameOrPreset any) error` | `SetBrowser` 的别名 |
| `SetRandomBrowser(product string) error` | 随机选某产品的 preset（`"*"` = 全部） |
| `Preset() *preset.Preset` | 当前 preset |
| `R() *Request` | 新建链式请求构建器（继承 client 默认值） |
| `SetTimeout(d)` / `SetProxy(rawURL)` | 请求超时 / HTTP 代理（传 "" 清除） |
| `SetInsecureSkipVerify(bool)` / `SetRootCAs(pool)` | TLS 校验控制 |
| `SetBaseURL(u)` | 相对 URL 的前缀 |
| `SetRedirects(max)` | 0 = 不跟随；>0 = 最多跟随 n 次；<0 = Go 默认 |
| `SetHeader(k, v)` / `SetHeaders(map)` | 每次请求的默认头 |
| `SetHeaderOrder(keys...)` | 预留：记录头顺序（net/http 暂不暴露写序，见路线图） |
| `EnableCookieJar()` / `DisableCookieJar()` | 自动 Cookie 管理 |
| `ForceHTTP1()` / `UseHTTP2()` / `UseAutoProtocol()` | 固定 HTTP/1.1、固定 HTTP/2、自动（默认） |

Request 构建器方法（`c.R()` 返回 `*Request`，链式，一次性使用）：

| 方法 | 说明 |
| --- | --- |
| `Get/Post/Put/Patch/Delete/Head/Options(url, headers?)` | HTTP 动词 → `(*Response, error)`; 每个动词后可选跟一个 `map[string]string` 请求头字典 |
| `Execute(method, url)` | 通用动词 |
| `SetQueryParam(k, v)` / `SetQueryParams(map)` | 查询参数（合并进 URL） |
| `SetPathParam(k, v)` / `SetPathParams(map)` | 替换路径中的 `{name}` / `:name` |
| `SetHeader(k, v)` / `SetHeaders(map)` | 请求头 |
| `SetBasicAuth(u, p)` / `SetAuthToken(tok)` | Authorization |
| `SetCookie(name, value)` | Cookie 头 |
| `SetBody(body any)` | 请求体（见编码表） |
| `SetFormData(map[string]string)` | form 请求体 |
| `SetMultipartFormData(map[string]string)` | multipart/form-data 请求体 |
| `SetResult(v any)` | 2xx 响应体 JSON 解码进 `v` |
| `SetContext(ctx)` / `SetTimeout(d)` | 请求上下文 / 单请求超时 |

Response 方法（`*Response`，body 已读入内存）：

| 方法 | 说明 |
| --- | --- |
| `StatusCode() int` / `Status() string` | 如 `200` / `"200 OK"` |
| `String() string` / `Body() []byte` | 响应体 |
| `Header() http.Header` / `Cookies() []*http.Cookie` | 响应头 / Set-Cookie |
| `JSON(v any) error` | 解码 body 到 `v` |
| `Proto() string` | 如 `"HTTP/2.0"`、`"HTTP/1.1"` |
| `RequestURL() string` | 最终 URL（重定向/参数后） |
| `Time() time.Duration` | 单次往返耗时 |
| `IsSuccess()` / `IsError()` | 2xx / 4xx–5xx 判断 |

> 说明：4xx/5xx 不是 error——请用 `resp.IsSuccess()` 或 `StatusCode()` 判断；
> 只有网络/传输/编码失败才返回 error。某些服务器不支持 h2 时可
> `ForceHTTP1()`；用 `SetRedirects(0)` 停止跟随重定向。
>
> preset 还支持按「产品+版本」引用（`"chrome-152"`、`"firefox-145"`、
> `"safari-26-0-1"`）或按产品（`"chrome"` = 最新）。可运行示例在
> `client/examples/browser`：`go run ./examples/browser -preset chrome-152`。

### HTTP 客户端是如何带上指纹的

- 每个 TLS 连接都通过 `tlsprint/utls` 用 preset 的 ClientHello 拨号（密码套件
  顺序、扩展顺序、supported groups、签名算法、GREASE……）。回环测试会抓取真实
  握手的 ClientHello 并断言其规范 JA3 等于 preset。
- 协议选择：preset 描述 HTTP/2 行为时优先尝试 h2，服务器不支持则安全回退
  HTTP/1.1（只有"请求尚未发出"的阶段失败才回退，避免重复发送）；同 host
  会记住协议偏好。
- 默认请求头来自 preset（User-Agent 等）；切换 preset 自动刷新，除非你手动
  覆盖过 User-Agent。

> **HTTP/2 已做到逐字节精确。** `client` 使用分叉的 `tlsprint/http2` 传输层，
> 其 `Fingerprint` 会从 preset 的 HTTP/2 与 header 指纹还原连接指纹：精确的
> SETTINGS 参数顺序、初始 WINDOW_UPDATE、请求伪头顺序、请求 header 顺序、以及
> HEADERS 帧上的流优先级。已对 `tls.peet.ws` 实测：服务端上报的
> `akamai_fingerprint`（`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`）
> 与 HEADERS 字段顺序都跟真实 Chrome 152 抓包完全一致。

---

## 亮点

- **标准化的类型化指纹模型** `Profile`：有序标识符列表 + 明确的 GREASE 语义、
  JSON 往返、校验；取代参考项目里散乱的字符串型配置。
- **真实可用的编解码**：JA3 字符串 / md5、按 [JA4 规范](https://github.com/FoxIO-LLC/ja4)
  实现并用规范自带样例向量验证的 JA4、以及字节级保真的 ClientHello **解析 ⇄
  构造**（未知扩展原样保留）。
- **精选指纹注册表**：46 个真实 profile（Chrome / Firefox / Safari / Edge /
  Opera / curl / OkHttp / WeChat / Charles / Reqable / Fiddler / IE /
  PowerShell），内嵌、带版本与出处，测试保证每个 profile 的列表能反推出其源
  抓包的 JA3。
- **拿来即用的 HTTP 客户端**：指纹真的上线——client/utls 的测试用本地回环
  TLS 服务器真实握手并抓包，断言线上 ClientHello 的规范 JA3 与 preset 一致。
- **分层干净**：根模块只依赖 Go 标准库；引擎/传输相关依赖都放在各自的可选
  子模块里。

## 为什么还要一个指纹库？

这类项目要么 fork 了整个 TLS 栈（uTLS），要么把指纹配置格式和某个引擎绑死。
本库把"指纹本身"抽成引擎无关的标准形态：

| 关注点 | 参考项目做法 | tlsprint |
| --- | --- | --- |
| 指纹数据模型 | 字符串型配置（`JA3`/`ExtensionOrder`/`Curves` 字段） | 类型化有序列表 + 明确 GREASE 处理 |
| GREASE | 每个引擎各自隐式规则 | 显式标记 + 符合规范的编解码 |
| JA4 | 常常缺失或近似 | 按规范实现并以官方样例向量测试 |
| 依赖 | 需要引擎（CGO/uTLS…） | 根模块仅标准库 |
| 注册表 | Python 生成、庞大平铺 | 精选 46 条 + 可复现导入工具 |

## 仓库结构

一个仓库、三个 Go module。根模块**零第三方依赖**；两个子模块分别引入
uTLS 与 HTTP 协议栈。

| Module | 用途 |
| --- | --- |
| `github.com/lingulingo/tlsprint`（根） | `Profile` 模型、`iana` 注册表、`hello` 线格式编解码、`ja3`/`ja4`、`preset` 注册表、CLI |
| `github.com/lingulingo/tlsprint/utls` | Profile → uTLS `ClientHelloSpec` + `Dial`/`DialByName` |
| `github.com/lingulingo/tlsprint/client` | HTTP 客户端：带 preset 指纹的 `Get`/`Post`/... |

根模块内部包：

| 路径 | 说明 |
| --- | --- |
| 根包 | `Profile`/`TLSProfile`/`HTTP2Profile`/`HeaderProfile` + 校验 |
| `tlsprint/iana` | 标识符注册表与 GREASE 语义（扩展/密码套件/曲线/签名算法/版本/H2 settings） |
| `tlsprint/hello` | ClientHello 线格式解析/构造 |
| `tlsprint/ja3` | JA3 规范字符串与 md5 |
| `tlsprint/ja4` | JA4 指纹 |
| `tlsprint/preset` | 精选指纹注册表（数据内嵌于 `preset/data`） |
| `cmd/tlsprint` | CLI |
| `tools/importproteus` | 数据再生成工具 |

## 底层用法

以下全部是纯数据/编解码（仅标准库），引擎无关。

### 查询指纹预设

```go
reg := preset.MustBuiltin()
p := reg.Lookup("chrome-141") // 也支持 "TLS_CHROME_141"、"chrome"(取最新)…
fmt.Println(p.Key, p.Product, p.Version, p.UserAgent())
fmt.Println(reg.Products())   // 全部产品
```

### 计算指纹

```go
s := ja3.FromProfile(&p.TLS) // 由 profile 列表推规范 JA3
fmt.Println(s, ja3.Hash(s))  // hash = 经典 md5 指纹 id

// 从抓包字节算（整条 record / 裸 handshake / 裸 body 均可）：
ch, err := hello.Parse(capturedBytes)
wireProfile, _ := ch.TLSProfile()   // 字节 → 语义 profile
fmt.Println(ja3.Compute(ch))        // GREASE 感知的规范 JA3
j4, err := ja4.Compute(ch)          // JA4
fmt.Println(j4)
```

### 解析/构造原始 ClientHello（字节级往返一致）

```go
ch := &hello.ClientHello{
	LegacyVersion:      0x0303,
	CompressionMethods: []byte{0},
	CipherSuites:       []uint16{0x1301, 0x1302, 0x1303},
	Extensions: []hello.Extension{
		{Type: iana.ExtSupportedVersions, Data: hello.EncodeSupportedVersions([]uint16{0x0304, 0x0303})},
	},
}
wire, _ := ch.MarshalRecord(0)
parsed, _, _ := hello.ParseRecord(wire) // 与 wire 完全一致
```

### 直接构造 Profile

```go
prof := &tlsprint.Profile{TLS: tlsprint.TLSProfile{
	CipherSuites:        []uint16{0x1301, 0x1302, 0x1303},
	Extensions:          []uint16{iana.ExtSupportedVersions, iana.ExtSignatureAlgorithms},
	SupportedVersions:   []uint16{iana.VersionTLS13, iana.VersionTLS12},
	SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401},
}}
_ = prof.Validate() // 结构校验
// Profile 是纯数据：可直接 JSON 序列化
```

---

## 底层接入 uTLS

适配层在独立子模块中，核心库保持无依赖：

```sh
cd utls && go mod tidy
```

**方式一：Profile → uTLS `ClientHelloSpec`**

```go
spec, _ := tlsutls.FromPreset(reg.Lookup("chrome-141"))
conn := utls.UClient(rawConn, &utls.Config{ServerName: "example.com"}, utls.HelloCustom)
conn.ApplyPreset(spec)
// conn.Handshake() ...
```

**方式二：一键拨号（应用指纹 + 完成握手）**

```go
conn, _ := tlsutls.Dial(ctx, "tcp", "example.com:443", p, nil)
// 或直接按名字：
conn, _ = tlsutls.DialByName(ctx, "tcp", "example.com:443", "chrome-141",
	&tlsutls.DialOptions{ServerName: "example.com"})
defer conn.Close()
```

`DialOptions` 提供 `ServerName` / `RootCAs` / `InsecureSkipVerify`(仅测试) /
`NetDial`(自定义拨号，如代理) / `Spec`(转换选项：GREASE/ALPN/keyshare)。
适配层固定对接 `github.com/refraction-networking/utls v1.8.2`。

> **会话恢复说明**：带会话恢复的抓包里含 `pre_shared_key` 扩展，但其内容与会话
> 绑定。适配层默认在全新握手上省略它（空 PSK 是协议非法的），需要时可用
> `Options.IncludeSessionExtensions` 强制保留。

---

## GREASE 模型

- 真实流量携带**随机 GREASE 值**；指纹服务发布的规范 JA3/JA4 字符串是
  **去 GREASE** 的。
- `iana.GreaseMarker` 在源数据知道 GREASE 位置时显式记录（`supported_groups`
  / `supported_versions`）；编解码按规范剥离 GREASE，构造器可把标记展开为随机值。
- `utls` 适配把标记转成 uTLS `GREASE_PLACEHOLDER`，并可通过 `Options.GREASE`
  注入 Chromium 风格 GREASE（默认对未禁用的 preset 开启）。

## CLI

```sh
go install github.com/lingulingo/tlsprint/cmd/tlsprint@latest

tlsprint list chrome          # 列出 chrome 预设
tlsprint show chrome-141      # 输出 preset 的 JSON
tlsprint fp -preset chrome    # preset 的规范 JA3 + md5
tlsprint fp -hex 16030300bb010000b703030000...  # 抓包字节的 JA3/JA4
```

## tlsprint 与市面上的开源对比

TLS 指纹库大致分两类：**只有引擎**（给你一个 TLS 栈，其余自己接）和**只有客户端**
（给你 HTTP 客户端，但指纹定义和某个引擎绑死）。tlsprint 把两者分开：一个
**标准数据层** + 一组**可选、字节精确的引擎**。

| 关注点 | uTLS | bogdanfinn/tls-client | proteus / curl_cffi | **tlsprint** |
| --- | --- | --- | --- | --- |
| **指纹模型** | 逐引擎、临时 | 内嵌在客户端里 | 字符串型配置 | **类型化、可版本化、JSON、引擎无关** |
| **根模块依赖** | 整个 TLS 栈 | 整个引擎 | CGO libcurl | **仅标准库** |
| **是否需要 CGO/原生库** | 否 | 否 | **要（curl）** | **全程纯 Go，无需** |
| **JA3** | 随机 hello | 字符串 | 字符串 | **可双向 + md5** |
| **JA4** | 部分 | 部分 | 常缺失 | **符合规范，用其官方样例向量测试** |
| **HTTP/2 SETTINGS/优先级/头顺序** | 无 | Go 默认（非逐字节） | C++/fork | **逐字节（fork 的 `x/net/http2`）** |
| **预设注册表** | 硬编码 parrot | 硬编码 | 大型生成 | **49 个精选 + 可验证（JA3 不变量）+ 可复现管线** |
| **API 手感** | 底层 | `NewClient().SetBrowser` | curl_cffi | **curl_cffi 风格 + 流式构建器** |

**为什么选 tlsprint：**
1. **它是标准数据层**——指纹是纯数据，可持久化、可 diff、可版本化、可再生成，且不被某一模拟引擎绑定。
2. **纯 Go、零 CGO**——无需 libcurl/`.so`，`go build` 直接出。
3. **TLS 与 HTTP/2 都字节精确**——多数 Go 客户端只做到 TLS 精确，HTTP/2 走 Go 默认；tlsprint 连 SETTINGS 顺序、WINDOW_UPDATE、伪头/头顺序、流优先级都还原。
4. **验证而非断言**——预设经源 JA3 校验；连接层用本地抓包比对真实握手与 `tls.peet.ws` 的 `akamai_fingerprint`。
5. **API 舒服**——指纹直接传在调用里（`Impersonate("chrome-152")`），浏览器头自动带上。

> 诚实限制：逐字节 HTTP/2 指纹针对精选预设生效；需要执行 JS 的活动 bot 挑战
> （如 Akamai sensor、Cloudflare 托管挑战）任何 HTTP 客户端都解不了，需要无头
> 浏览器/求解器 + 有效会话 cookie。

## 支持的指纹

以下每个预设都来自真实抓包,并通过不变量测试(列表能反推出源 JA3)。可按名字查询
(`"chrome-152"`、`"firefox-145"`、`"curl"` = 各产品最新款...)。

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

## 数据出处与再生成

`preset/data` 中精选的指纹来自 curl_cffi/curl-impersonate `tls_config`
谱系的参考 preset 集。数值是观测到的线上行为；本仓库的选取、规范化与工具
为原创且 MIT 许可。详见 `preset/data/README.md` 与再生成命令：

```sh
go run ./tools/importproteus \
  -in /path/to/proteus_dump.json \
  -allow preset/data/ALLOWLIST.txt \
  -out preset/data/registry.json
```

## 开发

```sh
make test         # 根模块测试
make vet          # go vet（根模块）
make test-utls    # utls 模块测试
make test-client  # client 模块测试
```

全量测试含黄金向量（JA4 规范样例、真实 Chrome JA3），并验证整个注册表满足
`ja3.FromProfile(p.TLS) == p.TLS.JA3`；`utls`/`client` 模块另含回环抓包集成
测试，断言线上指纹与 preset 一致。

## 发布说明

当前三个模块路径均为占位符（`github.com/lingulingo/tlsprint`、`.../utls`、
`.../client`）。首次打 tag 前请把三个 `go.mod` 里的模块路径替换成你自己的
命名空间后推送；子模块分别打 `utls/v0.1.0`、`client/v0.1.0` 之类的标签，
`go get` 才能解析。

## 许可

MIT —— 见 [LICENSE](LICENSE)。浏览器/产品名称与商标归各自所有者所有，此处
仅用于描述被观测的流量特征。


---

## ⭐ 支持这个项目

如果 **tlsprint** 帮到了你——不管是省了你一个 HTTP 客户端、让你的爬虫更像真实
浏览器,还是单纯喜欢干净的 Go 指纹库——请给它点个 **star** ⭐!

- ⭐ **Star 本仓库**——免费,但能让更多人看到它有用。
- 🐞 **提 Issue**——报 bug、要新的指纹预设。
- 🤝 **提 PR**——更多预设、更好的 HTTP/2 保真度、文档。

每个 star 都是我坚持更新的动力,谢谢!🙌
