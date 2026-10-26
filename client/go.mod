module github.com/lingulingo/tlsprint/client

go 1.25.0

require (
	github.com/andybalholm/brotli v1.0.6
	github.com/klauspost/compress v1.17.4
	github.com/lingulingo/tlsprint v1.0.6
	github.com/lingulingo/tlsprint/http2 v1.0.1
	github.com/lingulingo/tlsprint/utls v1.0.3
)

require (
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

replace github.com/lingulingo/tlsprint => ../

replace github.com/lingulingo/tlsprint/http2 => ../http2

replace github.com/lingulingo/tlsprint/utls => ../utls
