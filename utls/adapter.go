// Package utls bridges tlsprint profiles to uTLS
// (github.com/refraction-networking/utls), so you can drive a real TLS
// connection whose ClientHello fingerprint comes from a tlsprint profile.
//
// This package lives in its own Go module (tlsprint/utls) so that the core
// tlsprint module stays dependency-free: importing the adapter pulls in uTLS
// and its dependencies, but importing tlsprint itself does not.
//
// # Design notes
//
// uTLS builds ClientHellos from ClientHelloSpec values: ordered extension
// instances plus cipher/version lists. A tlsprint TLSProfile describes the
// same ClientHello at the level of identifier lists, so conversion is mostly
// mechanical — every extension type in the profile's ordered list maps to the
// corresponding uTLS extension instance, and the semantic lists (groups,
// versions, signature algorithms, ...) populate their payloads.
//
// Some extensions cannot be fully described by a static profile and are
// filled by the engine at dial time (server name from tls.Config.ServerName,
// key shares generated for the negotiated group, GREASE randomized per
// connection, ...). The mapping in this package follows the same conventions
// as uTLS's own browser presets for those cases, and Options lets you take
// control of the choices that matter (GREASE, ALPN, key shares).
package utls

import (
	"crypto/rand"
	"fmt"
	"math/big"

	tlsprint "github.com/lingulingo/tlsprint"
	"github.com/lingulingo/tlsprint/iana"
	"github.com/lingulingo/tlsprint/preset"
	utls "github.com/refraction-networking/utls"
)

// Options customizes the profile → uTLS conversion.
type Options struct {
	// ALPN lists the protocols offered by the ALPN extension. When nil, the
	// default is ["h2", "http/1.1"] (h2 only if unset in HTTP2-aware
	// profiles it stays as the default; see NewOptions).
	ALPN []string

	// GREASE enables Chromium-style GREASE injection: a GREASE cipher suite
	// placeholder in front of the cipher list, a GREASE extension at the
	// front of the extension list, and (when the profile carries a padding
	// extension) a second GREASE extension right before the padding — the
	// pattern of modern Chromium clients. GREASE markers that the profile
	// itself records (supported_groups / supported_versions) are always
	// translated to uTLS placeholders.
	GREASE bool

	// Keyshares overrides the key_share extension contents. When nil, the
	// first one or two keyshare-capable groups of the profile's
	// supported_groups list are used (mirroring what Chromium-family clients
	// send). The entries are written as uTLS KeyShare values with empty key
	// data; uTLS generates real key material for supported groups at
	// handshake time.
	Keyshares []uint16

	// NextProtos, when non-empty, is written into the ApplicationSettings
	// (ALPS) extension if the profile carries one.
	NextProtos []string

	// IncludeSessionExtensions, when true, keeps extensions whose presence
	// depends on TLS session resumption (pre_shared_key, early_data) in the
	// ClientHello even though the profile carries no session payload.
	//
	// Off by default: a captured fingerprint that contains pre_shared_key was
	// recorded on a resumption connection, and sending an empty PSK
	// extension on a fresh handshake is protocol-invalid. Dropping it
	// reproduces what the client actually sends without a session.
	IncludeSessionExtensions bool

	// PermuteExtensions randomizes the order of the reorderable extensions on
	// every ClientHello, which is what modern Chromium clients do: they
	// shuffle extension order per connection, so the JA3 of one Chrome session
	// is only one member of a large family.
	//
	// Off by default. A tlsprint preset records one concrete captured order,
	// and keeping it makes the wire JA3 equal the preset's JA3 — the property
	// the preset invariant tests assert. Turning this on deliberately gives up
	// that equality: JA3 becomes a random member of the permutation family,
	// while JA4 (which sorts extensions) stays identical to the preset's,
	// because the extension *set* does not change.
	//
	// Wire-order constraints are preserved regardless: GREASE extension types
	// keep their positions, padding stays last, and pre_shared_key/early_data
	// (when IncludeSessionExtensions keeps them) stay at the tail.
	PermuteExtensions bool
}

// NewOptions returns options derived from the profile: GREASE follows the
// Chromium convention unless the profile disables it, and ALPN defaults to
// h2 + http/1.1 when the profile describes HTTP/2 behaviour, else
// http/1.1 only.
func NewOptions(p *tlsprint.Profile) *Options {
	o := &Options{}
	if p != nil && !p.TLS.DisableGrease {
		o.GREASE = true
	}
	if p != nil && p.HTTP2 == nil {
		o.ALPN = []string{"http/1.1"}
	} else {
		o.ALPN = []string{"h2", "http/1.1"}
	}
	return o
}

// FromProfile converts a semantic TLS profile into a uTLS ClientHelloSpec.
// The profile's ordered extension list drives the extension order; payload
// lists fill the corresponding uTLS extension instances.
func FromProfile(p *tlsprint.TLSProfile, opts *Options) (*utls.ClientHelloSpec, error) {
	if p == nil {
		return nil, fmt.Errorf("utls: nil profile")
	}
	if opts == nil {
		opts = &Options{}
	}

	spec := &utls.ClientHelloSpec{
		CipherSuites:       append([]uint16(nil), p.CipherSuites...),
		CompressionMethods: []byte{0},
	}
	spec.TLSVersMin, spec.TLSVersMax = versionRange(p)

	if opts.GREASE {
		spec.CipherSuites = append([]uint16{utls.GREASE_PLACEHOLDER}, spec.CipherSuites...)
	}

	alpn := opts.ALPN
	if alpn == nil {
		alpn = []string{"h2", "http/1.1"}
	}

	// Map the profile's extension order to uTLS extension instances,
	// remembering where the padding extension sits (Chrome puts its second
	// GREASE extension right before padding).
	//
	// Session-resumption extensions (pre_shared_key 41 / early_data 42) are
	// omitted on a fresh handshake: the profile records their *type* but no
	// session payload, and an empty body is protocol-invalid. Everything
	// else the profile lists is emitted — extension types with a dedicated
	// uTLS instance (incl. ALPS and SCT) via that instance, and unknown types
	// via their raw ExtraExtensions payload when present.
	// Order the profile's extension types first (optionally permuted the way
	// Chromium does), then instantiate them in that order. Building instances
	// after ordering keeps the permutation independent of how each extension
	// is materialized.
	types := make([]uint16, 0, len(p.Extensions))
	for _, typ := range p.Extensions {
		if iana.IsGrease(typ) {
			types = append(types, typ)
			continue
		}
		if !opts.IncludeSessionExtensions && (typ == iana.ExtPreSharedKey || typ == iana.ExtEarlyData) {
			continue
		}
		types = append(types, typ)
	}
	if opts.PermuteExtensions {
		if err := permuteTypes(types); err != nil {
			return nil, err
		}
	}

	padIdx := -1
	var exts []utls.TLSExtension
	for _, typ := range types {
		if iana.IsGrease(typ) {
			exts = append(exts, &utls.UtlsGREASEExtension{})
			continue
		}
		if typ == iana.ExtPadding {
			padIdx = len(exts)
		}
		ext, err := buildExtension(typ, p, opts, alpn)
		if err != nil {
			return nil, err
		}
		if ext == nil {
			continue // unknown type with no payload: omit rather than emit an empty body
		}
		exts = append(exts, ext)
	}

	if opts.GREASE {
		grease := &utls.UtlsGREASEExtension{}
		exts = append([]utls.TLSExtension{grease}, exts...)
		if padIdx >= 0 {
			// Chrome's second GREASE extension (before padding) carries a
			// single zero-byte body; the first one has an empty body.
			second := &utls.UtlsGREASEExtension{Body: []byte{0}}
			at := padIdx + 1 // account for the GREASE just prepended
			exts = append(exts[:at], append([]utls.TLSExtension{second}, exts[at:]...)...)
		}
	}
	spec.Extensions = exts

	// Key shares: uTLS requires a key_share extension for TLS 1.3. If the
	// profile carries one in its order list the mapping above produced a
	// KeyShareExtension with empty shares when the group list was empty;
	// fill it now.
	fillKeyShares(spec, p, opts)

	return spec, nil
}

// FromPreset converts a curated preset into a uTLS ClientHelloSpec using the
// NewOptions defaults (Chromium-style GREASE unless the profile disables it,
// ALPN h2+http/1.1).
func FromPreset(p *preset.Preset) (*utls.ClientHelloSpec, error) {
	if p == nil {
		return nil, fmt.Errorf("utls: nil preset")
	}
	return FromProfile(&p.TLS, NewOptions(&p.Profile))
}

func buildExtension(typ uint16, p *tlsprint.TLSProfile, opts *Options, alpn []string) (utls.TLSExtension, error) {
	switch typ {
	case iana.ExtServerName:
		return &utls.SNIExtension{}, nil
	case iana.ExtStatusRequest:
		return &utls.StatusRequestExtension{}, nil
	case iana.ExtSupportedGroups:
		return &utls.SupportedCurvesExtension{Curves: toCurves(p.SupportedGroups)}, nil
	case iana.ExtECPointFormats:
		formats := p.ECFormats
		if len(formats) == 0 {
			formats = []byte{0}
		}
		return &utls.SupportedPointsExtension{SupportedPoints: formats}, nil
	case iana.ExtSignatureAlgorithms:
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: toSigSchemes(randomizeGrease(p.SignatureAlgorithms))}, nil
	case iana.ExtSignatureAlgorithmsCert:
		return &utls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: toSigSchemes(randomizeGrease(p.SignatureAlgorithmsCert))}, nil
	case iana.ExtALPN:
		return &utls.ALPNExtension{AlpnProtocols: append([]string(nil), alpn...)}, nil
	case iana.ExtSignedCertificateTimestamp:
		// Chrome sends this with an empty body; uTLS's SCTExtension writes
		// exactly that, which strict servers accept.
		return &utls.SCTExtension{}, nil
	case iana.ExtPadding:
		return &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle}, nil
	case iana.ExtExtendedMasterSecret:
		return &utls.ExtendedMasterSecretExtension{}, nil
	case iana.ExtCompressCertificate:
		return &utls.UtlsCompressCertExtension{Algorithms: toCertCompression(p.CertCompression)}, nil
	case iana.ExtRecordSizeLimit:
		return &utls.FakeRecordSizeLimitExtension{Limit: p.RecordSizeLimit}, nil
	case iana.ExtDelegatedCredentials:
		return &utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: toSigSchemes(randomizeGrease(p.DelegatedCredentials))}, nil
	case iana.ExtSessionTicket:
		return &utls.SessionTicketExtension{}, nil
	case iana.ExtSupportedVersions:
		return &utls.SupportedVersionsExtension{Versions: randomizeGrease(p.SupportedVersions)}, nil
	case iana.ExtPSKKeyExchangeModes:
		modes := p.PSKKeyExchangeModes
		if len(modes) == 0 {
			modes = []uint8{1} // psk_dhe_ke — what Chrome-family clients send
		}
		return &utls.PSKKeyExchangeModesExtension{Modes: append([]uint8(nil), modes...)}, nil
	case iana.ExtKeyShare:
		return &utls.KeyShareExtension{KeyShares: keysharesFromGroups(p.SupportedGroups, opts)}, nil
	case iana.ExtApplicationSettings: // 0x4469 — original ALPS codepoint
		protos := alpsProtocols(opts)
		return &utls.ApplicationSettingsExtension{SupportedProtocols: append([]string(nil), protos...)}, nil
	case 17613: // 0x44CD — the ALPS codepoint used by modern Chrome (since ~v130)
		protos := alpsProtocols(opts)
		return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: append([]string(nil), protos...)}, nil
	case iana.ExtEncryptedClientHello: // 0xFE0D — ECH
		// The profile records the extension type but not ECH configs; the
		// closest faithful behaviour for a non-ECH session is Chrome's
		// "grease ECH" (what uTLS's own Chrome presets emit).
		return utls.BoringGREASEECH(), nil
	case iana.ExtRenegotiationInfo:
		return &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient}, nil
	default:
		// Unknown extension handling:
		//   - if the profile carries a raw payload (ExtraExtensions), emit it
		//     as-is (e.g. Chrome's 0xCA34 wallet blob);
		//   - if the type is a known empty-body flag (post_handshake_auth),
		//     emit it with an empty body (that is its correct wire form);
		//   - otherwise omit it entirely — emitting an empty body for an
		//     unknown type yields a malformed ClientHello that strict servers
		//     (e.g. Akamai) reject.
		if d, ok := p.ExtraExtensions[typ]; ok && len(d) > 0 {
			return &utls.GenericExtension{Id: typ, Data: d}, nil
		}
		if typ == 49 { // post_handshake_auth — empty body is the valid flag
			return &utls.GenericExtension{Id: typ}, nil
		}
		return nil, nil
	}
}

// alpsProtocols returns the protocols advertised by the ALPS extension:
// NextProtos when set, else the ALPN list when it is h2-capable, else h2.
func alpsProtocols(opts *Options) []string {
	if len(opts.NextProtos) > 0 {
		return opts.NextProtos
	}
	return []string{"h2"}
}

func versionRange(p *tlsprint.TLSProfile) (minV, maxV uint16) {
	// Defaults when the profile carries no supported_versions payload.
	minV, maxV = iana.VersionTLS10, iana.VersionTLS12
	if len(p.SupportedVersions) == 0 {
		return minV, maxV
	}
	minV, maxV = iana.VersionTLS13, iana.VersionTLS10
	for _, v := range p.SupportedVersions {
		if iana.IsGrease(v) || v < iana.VersionTLS10 || v > iana.VersionTLS13 {
			continue
		}
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	if maxV < minV {
		return iana.VersionTLS10, iana.VersionTLS12
	}
	return minV, maxV
}

func toCurves(groups []uint16) []utls.CurveID {
	out := make([]utls.CurveID, 0, len(groups))
	for _, g := range groups {
		if g == iana.GreaseMarker {
			// Browsers send a *random* GREASE value here, not the literal
			// placeholder; strict servers decode an invalid named-group value
			// as a fatal error.
			out = append(out, utls.CurveID(nextGrease()))
			continue
		}
		out = append(out, utls.CurveID(g))
	}
	return out
}

// randomizeGrease replaces every GreaseMarker in a list with a random GREASE
// value. It is applied to payload lists (supported_versions, ...) where uTLS
// does not substitute placeholders on its own.
func randomizeGrease(list []uint16) []uint16 {
	out := append([]uint16(nil), list...)
	for i, v := range out {
		if v == iana.GreaseMarker {
			out[i] = nextGrease()
		}
	}
	return out
}

func nextGrease() uint16 {
	if g, err := iana.NextGrease(rand.Reader); err == nil {
		return g
	}
	return iana.GreaseMarker
}

// permuteTypes randomizes the position of the reorderable extension types in
// place, keeping the wire-order constraints that servers (and RFC 8446)
// enforce:
//
//   - GREASE extension types keep their positions — Chromium sends one first
//     and one immediately before padding, and that placement is itself part of
//     the fingerprint;
//   - padding stays last (RFC 7685);
//   - pre_shared_key and early_data keep their tail position (RFC 8446
//     §4.2.11 requires pre_shared_key to be the last extension).
//
// Everything else may legally appear anywhere, so those entries are the ones
// shuffled. A list with fewer than two such entries is left alone.
func permuteTypes(types []uint16) error {
	idx := make([]int, 0, len(types))
	for i, typ := range types {
		switch {
		case iana.IsGrease(typ),
			typ == iana.ExtPadding,
			typ == iana.ExtPreSharedKey,
			typ == iana.ExtEarlyData:
			continue
		}
		idx = append(idx, i)
	}
	if len(idx) < 2 {
		return nil
	}

	// Fisher-Yates over the reorderable slots only: the shuffled values are
	// dealt back into exactly those slots, so pinned entries never move.
	vals := make([]uint16, len(idx))
	for i, at := range idx {
		vals[i] = types[at]
	}
	for i := len(vals) - 1; i > 0; i-- {
		j, err := randIndex(i + 1)
		if err != nil {
			return err
		}
		vals[i], vals[j] = vals[j], vals[i]
	}
	for i, at := range idx {
		types[at] = vals[i]
	}
	return nil
}

// randIndex returns a uniformly random integer in [0, n).
func randIndex(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

func toSigSchemes(algs []uint16) []utls.SignatureScheme {
	out := make([]utls.SignatureScheme, 0, len(algs))
	for _, a := range algs {
		out = append(out, utls.SignatureScheme(a))
	}
	return out
}

func toCertCompression(algs []uint16) []utls.CertCompressionAlgo {
	out := make([]utls.CertCompressionAlgo, 0, len(algs))
	for _, a := range algs {
		out = append(out, utls.CertCompressionAlgo(a))
	}
	return out
}

// keysharesFromGroups picks the key_share entries for a profile: the first
// one or two keyshare-capable groups of supported_groups, or the option
// override.
func keysharesFromGroups(groups []uint16, opts *Options) []utls.KeyShare {
	chosen := opts.Keyshares
	if chosen == nil {
		for _, g := range groups {
			if iana.IsGrease(g) {
				continue
			}
			if !keyshareCapable(g) {
				continue
			}
			chosen = append(chosen, g)
			if len(chosen) == 2 {
				break
			}
		}
	}
	out := make([]utls.KeyShare, 0, len(chosen))
	for _, g := range chosen {
		out = append(out, utls.KeyShare{Group: utls.CurveID(g)})
	}
	return out
}

// keyshareCapable lists the groups that are usable in a TLS 1.3 key_share.
func keyshareCapable(g uint16) bool {
	switch g {
	case iana.GroupX25519, iana.GroupX25519MLKEM768, iana.GroupSecp256r1,
		iana.GroupSecp384r1, iana.GroupSecp521r1, iana.GroupX448, 0x11eb:
		return true
	}
	return false
}

func fillKeyShares(spec *utls.ClientHelloSpec, p *tlsprint.TLSProfile, opts *Options) {
	for _, e := range spec.Extensions {
		if ks, ok := e.(*utls.KeyShareExtension); ok && len(ks.KeyShares) == 0 {
			ks.KeyShares = keysharesFromGroups(p.SupportedGroups, opts)
		}
	}
}
