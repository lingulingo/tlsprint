# preset/data

This directory holds the data files of the built-in, curated fingerprint
collection embedded by the `preset` package (`registry.json`, referenced by
`//go:embed`).

## What the data is

Each entry in `registry.json` is a `preset.Preset` — the engine-independent
`tlsprint.Profile` (TLS ClientHello fingerprint + optional HTTP/2 and HTTP
header fingerprints) plus metadata (`key`, product, platform, version,
upstream id). Profiles are observational snapshots of real client traffic:
ordered identifier lists such as cipher suites, extension order, supported
groups and signature algorithms, exactly as the reference captures recorded
them.

## Provenance and licence

The curated profiles were selected from the preset collection of the
open-source reference project lineage that mirrors curl_cffi /
curl-impersonate `tls_config` fingerprints (Chrome, Firefox, Safari, Edge,
Opera, curl, OkHttp, WeChat and proxy tooling, among others). The values are
facts about what those clients put on the wire (protocol identifier lists
and observed header defaults), not creative expression; the selection and
normalisation performed here (see the import tool and `ALLOWLIST.txt`) is
original to tlsprint and MIT-licensed. Upstream identifiers (`id`) and preset
names (`key`, e.g. `TLS_CHROME_141`) are retained so the provenance stays
traceable. Trademarks belong to their respective owners and are used only to
describe the captured traffic.

## Regenerating the data

The reference collection is not a Go dependency of tlsprint (this module is
dependency-free), so regeneration is a two-step, offline-friendly process:

1. Export the reference preset variables to a JSON dump. With a local
   checkout of the reference project and a Go toolchain, the variables are
   plain `Config` structs; export them with a tiny Go program that prints the
   JSON encoding of each `TLS_*` variable together with a `"__name"` key.
   (The exact generation script is documented in
   `tools/importproteus/README.md`.)

2. Convert + curate:

   ```sh
   go run ./tools/importproteus \
     -in /path/to/proteus_dump.json \
     -allow preset/data/ALLOWLIST.txt \
     -out preset/data/registry.json
   ```

`ALLOWLIST.txt` selects which presets ship in the built-in registry and can
override derived metadata. Add hand-authored presets by appending entries to
`registry.json` with `"source": "manual"` style keys (see the registry JSON
schema in `preset/preset.go`).

> **Warning:** step 2 rewrites `registry.json` from scratch. Presets that are
> not on `ALLOWLIST.txt` — including the hand-authored `TLS_CHROME_153_*`
> through `TLS_CHROME_156_*` captures below — are **dropped** when you re-run
> it. Keep a copy of any hand-authored entries, or add them to `ALLOWLIST.txt`
> once the reference dump carries them.
>
> Hand-authored captures currently in the registry: `TLS_CHROME_152_*`,
> `TLS_CHROME_153_*`, `TLS_CHROME_154_*`, `TLS_CHROME_155_*`,
> `TLS_CHROME_156_*` (all from `tls.peet.ws` snapshots).

## Verification

`preset` package tests verify invariants over the shipped data, including
that the canonical JA3 string derivable from each profile matches the JA3
value recorded by the source capture.
