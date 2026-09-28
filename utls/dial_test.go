package utls

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/ja3"
	"github.com/lingulingo/tlsprint/preset"
)

// TestDialAppliesFingerprint starts a real TLS server on 127.0.0.1, dials it
// with the preset fingerprint via Dial, captures the ClientHello bytes the
// client actually put on the wire, and asserts that the canonical JA3 of
// those bytes equals the JA3 of the preset profile — i.e. the public dial API
// really fingerprints the connection.
func TestDialAppliesFingerprint(t *testing.T) {
	for _, name := range []string{
		"TLS_CHROME_141",
		"TLS_CHROME_153_MACOS_10_15_7",
		"TLS_CHROME_154_MACOS_10_15_7",
		"TLS_FIREFOX_145",
		"TLS_SAFARI_26_0_1_MACOS_18_3",
		"TLS_CURL_8_16_0",
		"TLS_EDGE_150_MACOS_10_15_7",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := preset.MustBuiltin().Lookup(name)
			if p == nil {
				t.Fatalf("preset %q not found", name)
			}
			// On a fresh connection the adapter drops session-resumption
			// extensions (pre_shared_key/early_data) that the capture-based
			// profile lists, so derive the wire expectation the same way.
			prof := p.TLS
			var kept []uint16
			for _, typ := range prof.Extensions {
				if typ == 41 || typ == 42 {
					continue // session-resumption extensions
				}
				kept = append(kept, typ)
			}
			prof.Extensions = kept
			expected := ja3.FromProfile(&prof)

			addr, serverCfg := startCaptureServer(t, "h2", "http/1.1")

			roots := x509.NewCertPool()
			roots.AddCert(serverCfg.leaf)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			conn, err := Dial(ctx, "tcp", addr, p, &DialOptions{
				ServerName: "localhost",
				RootCAs:    roots,
			})
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer conn.Close()

			if conn.ConnectionState().NegotiatedProtocol != "h2" {
				t.Fatalf("negotiated protocol = %q, want h2", conn.ConnectionState().NegotiatedProtocol)
			}
			if conn.ConnectionState().Version < tls.VersionTLS12 {
				t.Fatalf("tls version = %#x", conn.ConnectionState().Version)
			}

			captured := <-serverCfg.captured
			ch, err := hello.Parse(captured)
			if err != nil {
				t.Fatalf("parse captured client hello: %v", err)
			}
			got := ja3.Compute(ch)
			if got != expected {
				t.Fatalf("wire JA3 mismatch\n  got:      %s\n  expected: %s", got, expected)
			}
		})
	}
}

func TestDialByNameAndInsecure(t *testing.T) {
	addr, serverCfg := startCaptureServer(t, "h2", "http/1.1")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// DialByName against an IP address, no root pool: uses insecure mode and
	// derives SNI from the address host.
	conn, err := DialByName(ctx, "tcp", addr, "chrome-141", &DialOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("DialByName: %v", err)
	}
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("re-handshake: %v", err)
	}
	<-serverCfg.captured
}

// ---- loopback TLS server with ClientHello capture ----

type captureServer struct {
	cert     tls.Certificate
	leaf     *x509.Certificate
	captured chan []byte
	err      chan error
}

// startCaptureServer runs a TLS server on 127.0.0.1:0 whose handshake handler
// captures the raw first TLS record (the ClientHello) of every accepted
// connection. It returns the listener address and the capture handle.
func startCaptureServer(t *testing.T, nextProtos ...string) (string, *captureServer) {
	t.Helper()

	cert, leaf := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	cs := &captureServer{cert: cert, leaf: leaf, captured: make(chan []byte, 8), err: make(chan error, 8)}
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
	}

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				captured, err := readClientHelloRecord(raw)
				if err != nil {
					return
				}
				cs.captured <- captured
				// Hand the captured record back to the TLS server (as a
				// prefix) so it can complete the handshake.
				conn := tls.Server(&replayConn{Conn: raw, prefix: captured}, srvCfg)
				if err := conn.Handshake(); err != nil {
					cs.err <- err
				}
			}(raw)
		}
	}()
	return ln.Addr().String(), cs
}

// readClientHelloRecord reads the first TLS record (the ClientHello) from a
// connection and returns its raw bytes including the record header.
func readClientHelloRecord(conn net.Conn) ([]byte, error) {
	r := bufio.NewReader(conn)
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 0x16 {
		return nil, io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length < 4 || length > 1<<14 {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out := append(header[:], body...)
	return out, nil
}

// replayConn serves a captured byte prefix (the ClientHello record we read
// for fingerprinting) before falling through to the real connection, so a
// TLS server can consume bytes that were already read.
type replayConn struct {
	net.Conn
	prefix []byte
	off    int
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.off < len(c.prefix) {
		n := copy(p, c.prefix[c.off:])
		c.off += n
		return n, nil
	}
	return c.Conn.Read(p)
}

func selfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, leaf
}
