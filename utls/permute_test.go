package utls

import (
	"context"
	"crypto/x509"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	tlsprint "github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/hello"
	"github.com/lingulingo/tlsprint/iana"
	"github.com/lingulingo/tlsprint/ja3"
	"github.com/lingulingo/tlsprint/ja4"
	"github.com/lingulingo/tlsprint/preset"
	utls "github.com/refraction-networking/utls"
)

// chromePreset returns a preset from the built-in registry by name.
func chromePreset(t *testing.T, name string) *preset.Preset {
	t.Helper()
	p := preset.MustBuiltin().Lookup(name)
	if p == nil {
		t.Fatalf("preset %q not found", name)
	}
	return p
}

// specSignature renders the ordered extension identities of a built
// ClientHelloSpec so two specs can be compared for order and multiset without
// depending on per-connection randomization (GREASE values, key shares).
func specSignature(spec *utls.ClientHelloSpec) []string {
	out := make([]string, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		name := reflect.TypeOf(ext).String()
		if g, ok := ext.(*utls.GenericExtension); ok {
			name += "(id=" + strconv.Itoa(int(g.Id)) + ")"
		}
		out = append(out, name)
	}
	return out
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

func typeStrings(types []uint16) []string {
	out := make([]string, 0, len(types))
	for _, typ := range types {
		out = append(out, strconv.Itoa(int(typ)))
	}
	return out
}

// TestPermuteTypesKeepsPinnedPositions checks the wire-order constraints the
// permutation must never break: GREASE stays where Chrome put it, padding
// stays last, pre_shared_key stays at the tail, and nothing is duplicated or
// lost.
func TestPermuteTypesKeepsPinnedPositions(t *testing.T) {
	// A Chrome-shaped list: GREASE first, ordinary extensions, padding, and
	// pre_shared_key last (RFC 8446 §4.2.11 requires PSK to be last).
	base := []uint16{
		iana.GreaseMarker, iana.ExtServerName, iana.ExtALPN,
		iana.ExtSupportedGroups, iana.ExtSupportedVersions,
		iana.ExtSignatureAlgorithms, iana.ExtPSKKeyExchangeModes,
		iana.ExtPadding, iana.ExtPreSharedKey,
	}
	const padAt, pskAt = 7, 8

	orders := map[string]bool{}
	for round := 0; round < 200; round++ {
		types := append([]uint16(nil), base...)
		if err := permuteTypes(types); err != nil {
			t.Fatalf("permuteTypes: %v", err)
		}

		if got, want := sortedCopy(typeStrings(types)), sortedCopy(typeStrings(base)); !slices.Equal(got, want) {
			t.Fatalf("round %d: multiset changed\n got %v\nwant %v", round, got, want)
		}
		if types[0] != iana.GreaseMarker {
			t.Fatalf("round %d: GREASE moved away from the front: %v", round, types)
		}
		if types[padAt] != iana.ExtPadding {
			t.Fatalf("round %d: padding left its position: %v", round, types)
		}
		if types[pskAt] != iana.ExtPreSharedKey {
			t.Fatalf("round %d: pre_shared_key is no longer last: %v", round, types)
		}
		orders[strings.Join(typeStrings(types[1:padAt]), ",")] = true
	}

	if len(orders) < 2 {
		t.Fatal("200 rounds produced a single permutation; the shuffle is not random")
	}
}

// TestPermuteTypesTooSmall covers degenerate inputs: fewer than two reorderable
// entries means the list is left untouched.
func TestPermuteTypesTooSmall(t *testing.T) {
	for _, types := range [][]uint16{
		{},
		{iana.ExtServerName},
		{iana.GreaseMarker, iana.ExtPadding, iana.ExtPreSharedKey},
	} {
		in := append([]uint16(nil), types...)
		if err := permuteTypes(in); err != nil {
			t.Fatalf("permuteTypes(%v): %v", types, err)
		}
		if !slices.Equal(in, types) {
			t.Fatalf("small list reordered: %v -> %v", types, in)
		}
	}
}

// TestFromProfilePermuteExtensions drives the adapter end to end: enabling
// PermuteExtensions must keep the exact same extension *set* while producing
// more than one order, with GREASE still first.
func TestFromProfilePermuteExtensions(t *testing.T) {
	p := chromePreset(t, "chrome-156")

	base, err := FromProfile(&p.TLS, &Options{GREASE: true, ALPN: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatalf("FromProfile baseline: %v", err)
	}
	baseSigs := specSignature(base)
	for _, sig := range baseSigs {
		if strings.Contains(sig, "PreSharedKey") {
			t.Fatalf("baseline unexpectedly carries pre_shared_key: %v", baseSigs)
		}
	}
	greaseType := reflect.TypeOf(&utls.UtlsGREASEExtension{}).String()

	seen := map[string]bool{strings.Join(baseSigs, "|"): true}
	for round := 0; round < 40; round++ {
		spec, err := FromProfile(&p.TLS, &Options{
			GREASE: true, ALPN: []string{"h2", "http/1.1"}, PermuteExtensions: true,
		})
		if err != nil {
			t.Fatalf("round %d: FromProfile: %v", round, err)
		}
		sigs := specSignature(spec)
		if got, want := sortedCopy(sigs), sortedCopy(baseSigs); !slices.Equal(got, want) {
			t.Fatalf("round %d: extension set changed\n got %v\nwant %v", round, got, want)
		}
		if sigs[0] != greaseType {
			t.Fatalf("round %d: GREASE is not first: %v", round, sigs)
		}
		seen[strings.Join(sigs, "|")] = true
	}
	if len(seen) < 2 {
		t.Fatal("40 rounds produced a single extension order; permutation had no effect")
	}
}

// clientHelloFor builds a ClientHello from a profile and fills in a decodable
// ALPN body. A TLSProfile records ALPN only as an extension *type*, while JA4
// needs the protocol list; replacing the body in place keeps the extension
// order intact.
func clientHelloFor(t *testing.T, p *tlsprint.TLSProfile) *hello.ClientHello {
	t.Helper()
	ch, err := hello.ToClientHello(p)
	if err != nil {
		t.Fatalf("ToClientHello: %v", err)
	}
	if _, ok := ch.FindExtension(iana.ExtALPN); ok {
		ch.SetExtension(iana.ExtALPN, hello.EncodeALPN([]string{"h2", "http/1.1"}))
	}
	return ch
}

// TestPermutationKeepsJA4AndBreaksJA3 pins the trade-off that makes the option
// usable: permuting the extension order changes JA3 (order-dependent) but
// leaves JA4 unchanged (it sorts extensions, and the set is identical).
func TestPermutationKeepsJA4AndBreaksJA3(t *testing.T) {
	p := chromePreset(t, "chrome-156")

	baseCH := clientHelloFor(t, &p.TLS)
	baseJA3 := ja3.FromProfile(&p.TLS)
	baseJA4, err := ja4.Compute(baseCH)
	if err != nil {
		t.Fatalf("ja4 baseline: %v", err)
	}

	variants := map[string]bool{}
	for round := 0; round < 40; round++ {
		prof := p.TLS
		prof.Extensions = append([]uint16(nil), p.TLS.Extensions...)
		if err := permuteTypes(prof.Extensions); err != nil {
			t.Fatalf("permuteTypes: %v", err)
		}

		ch := clientHelloFor(t, &prof)
		gotJA4, err := ja4.Compute(ch)
		if err != nil {
			t.Fatalf("round %d: ja4: %v", round, err)
		}
		if gotJA4.String() != baseJA4.String() {
			t.Fatalf("round %d: JA4 changed under permutation\n got %s\nwant %s",
				round, gotJA4.String(), baseJA4.String())
		}
		variants[ja3.FromProfile(&prof)] = true
	}

	if len(variants) < 2 {
		t.Fatal("JA3 never varied across 40 permutations; it is not order-dependent here")
	}
	if len(variants) == 1 && variants[baseJA3] {
		t.Fatal("JA3 did not change under permutation")
	}
}

// TestFromProfilePermuteDoesNotMutateProfile ensures the adapter still treats
// the caller's profile as read-only when permuting.
func TestFromProfilePermuteDoesNotMutateProfile(t *testing.T) {
	p := chromePreset(t, "chrome-156")
	before := append([]uint16(nil), p.TLS.Extensions...)
	for i := 0; i < 5; i++ {
		if _, err := FromProfile(&p.TLS, &Options{GREASE: true, PermuteExtensions: true}); err != nil {
			t.Fatalf("FromProfile: %v", err)
		}
	}
	if !slices.Equal(before, p.TLS.Extensions) {
		t.Fatalf("FromProfile mutated the profile's extension list: %v -> %v", before, p.TLS.Extensions)
	}
}

// TestPermuteOptionsDefaultOff pins the compatibility guarantee: permutation is
// never enabled implicitly.
func TestPermuteOptionsDefaultOff(t *testing.T) {
	var prof tlsprint.Profile
	if NewOptions(&prof).PermuteExtensions {
		t.Fatal("NewOptions enabled PermuteExtensions by default")
	}
	if NewOptions(nil).PermuteExtensions {
		t.Fatal("NewOptions(nil) enabled PermuteExtensions by default")
	}
}

// TestDialPermuteExtensionsKeepsJA4 proves the option reaches the wire: every
// connection sends a different extension order (so JA3 varies) while the JA4
// and the extension set stay identical to the preset's.
func TestDialPermuteExtensionsKeepsJA4(t *testing.T) {
	p := chromePreset(t, "chrome-156")
	addr, srv := startCaptureServer(t, "h2", "http/1.1")
	roots := x509.NewCertPool()
	roots.AddCert(srv.leaf)

	dial := func(spec *Options) (string, string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := Dial(ctx, "tcp", addr, p, &DialOptions{
			Spec: spec, ServerName: "localhost", RootCAs: roots,
		})
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()
		captured := <-srv.captured
		ch, err := hello.Parse(captured)
		if err != nil {
			t.Fatalf("parse captured ClientHello: %v", err)
		}
		j4, err := ja4.Compute(ch)
		if err != nil {
			t.Fatalf("ja4.Compute: %v", err)
		}
		return ja3.Compute(ch), j4.String()
	}

	baseJA3, baseJA4 := dial(nil)

	variants := map[string]bool{baseJA3: true}
	for i := 0; i < 6; i++ {
		gotJA3, gotJA4 := dial(&Options{GREASE: true, PermuteExtensions: true})
		if gotJA4 != baseJA4 {
			t.Fatalf("connection %d: JA4 changed under permutation\n got %s\nwant %s",
				i, gotJA4, baseJA4)
		}
		variants[gotJA3] = true
	}
	if len(variants) < 2 {
		t.Fatal("6 permuted connections sent an identical JA3; permutation is not reaching the wire")
	}
}
