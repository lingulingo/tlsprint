package preset

import (
	"encoding/json"
	"testing"

	"github.com/lingulingo/tlsprint/ja3"
)

// TestBuiltinInvariants checks the embedded curated collection:
//   - every preset validates,
//   - every preset whose TLS profile declares a JA3 provenance string can
//     re-derive exactly that JA3 from its own ordered lists (so the lists and
//     the capture agree),
//   - registry lookups behave.
func TestBuiltinInvariants(t *testing.T) {
	reg, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	presets := reg.List()
	if len(presets) == 0 {
		t.Fatal("builtin registry is empty")
	}
	t.Logf("builtin registry: %d presets across %d products", len(presets), len(reg.Products()))

	failures := 0
	for _, p := range presets {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: invalid: %v", p.Key, err)
			failures++
			continue
		}
		if p.TLS.JA3 == "" {
			continue
		}
		got := ja3.FromProfile(&p.TLS)
		if got != p.TLS.JA3 {
			// The only tolerated divergence is GREASE placement: some
			// sources record GREASE positions in the group/version lists
			// that their own JA3 string omits. ja3 already strips GREASE, so
			// any other difference is a genuine inconsistency.
			t.Errorf("%s: ja3 mismatch\n  stored: %s\n  derived: %s", p.Key, p.TLS.JA3, got)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d presets failed invariants", failures)
	}
}

func TestBuiltinLookup(t *testing.T) {
	reg := MustBuiltin()

	cases := []struct{ query string }{
		{"TLS_CHROME_141"},
		{"tls_chrome_141"},
		{"tls-chrome-141"},
		{"chrome"},
		{"TLS_CURL_8_16_0"},
		{"safari-26-0-1-macos-18-3"},
	}
	for _, tc := range cases {
		if reg.Lookup(tc.query) == nil {
			t.Errorf("Lookup(%q) = nil", tc.query)
		}
	}
	if reg.Lookup("definitely-not-a-preset") != nil {
		t.Error("Lookup returned a preset for a bogus name")
	}
}

func TestBuiltinLookupProductVersions(t *testing.T) {
	reg := MustBuiltin()
	chrome := reg.Lookup("chrome")
	if chrome == nil {
		t.Fatal("no chrome preset")
	}
	if chrome.Product != "chrome" {
		t.Fatalf("product = %q", chrome.Product)
	}
}

func TestPresetJSONRoundTrip(t *testing.T) {
	reg := MustBuiltin()
	for _, p := range reg.List() {
		if p.Product != "chrome" && p.Product != "safari" && p.Product != "firefox" {
			continue
		}
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("%s: marshal: %v", p.Key, err)
		}
		var got Preset
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s: unmarshal: %v", p.Key, err)
		}
		if got.Key != p.Key {
			t.Fatalf("%s: key changed to %q", p.Key, got.Key)
		}
		if len(got.TLS.CipherSuites) != len(p.TLS.CipherSuites) {
			t.Fatalf("%s: cipher suites changed", p.Key)
		}
		for i := range p.TLS.CipherSuites {
			if got.TLS.CipherSuites[i] != p.TLS.CipherSuites[i] {
				t.Fatalf("%s: cipher[%d] changed", p.Key, i)
			}
		}
		if (got.HTTP2 == nil) != (p.HTTP2 == nil) {
			t.Fatalf("%s: http2 presence changed", p.Key)
		}
	}
}

func TestNewRegistryDuplicate(t *testing.T) {
	a := &Preset{Key: "X"}
	if _, err := NewRegistry([]*Preset{a, a}); err == nil {
		t.Fatal("expected duplicate-key error")
	}
}

func TestLookupNewestVersion(t *testing.T) {
	reg := MustBuiltin()
	cases := map[string]string{
		"chrome":  "155", // numeric max beats "149.0.7827.197"
		"firefox": "151",
		"safari":  "26.0.1",
		"edge":    "150",
		"opera":   "116",
		"curl":    "8.16.0", // lexicographic compare would wrongly pick 8.9.1
	}
	for product, want := range cases {
		p := reg.Lookup(product)
		if p == nil {
			t.Fatalf("Lookup(%q) = nil", product)
		}
		if p.Version != want {
			t.Errorf("Lookup(%q).Version = %q, want %q", product, p.Version, want)
		}
	}
}

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"8.4.0", "8.16.0", -1},
		{"8.16.0", "8.4.0", 1},
		{"152", "149.0.7827.197", 1},
		{"1.2.3", "1.2.3", 0},
		{"1.0", "1", 0},
		{"11", "9", 1},
	}
	for _, c := range cases {
		if got := compareVersion(c.a, c.b); got != c.want {
			t.Errorf("compareVersion(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
