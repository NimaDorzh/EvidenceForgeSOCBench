# EVTX encoder BinXML fix (2026-07-13)

## Symptom

`tests/socbench/test_binary_formats.py::test_evtx_roundtrip_fixture_fields_match`
failed on Linux with `python-evtx==0.8.1`:

```
AttributeError: 'NullTypeNode' object has no attribute 'find_end_of_stream'
```

All three records in `tests/fixtures/eval/good/windows_event_security.xml` failed
identically when calling `record.xml()` on encoded output.

## Root cause

Two interacting issues:

1. **JPCERT 9-byte element headers vs MS-EVEN6 / python-evtx 11-byte layout.**
   The vendored JPCERT `xml2evtx` encoder emits `OpenStartElement` headers as
   `token (1) + data_size (4) + element_name_offset (4)` — 9 bytes. MS-EVEN6
   and `python-evtx`'s `OpenStartElementNode` expect
   `token (1) + dependency_identifier (2) + data_size (4) + element_name_offset (4)`
   — 11 bytes. Feeding JPCERT output through `record.xml()` misaligns every
   subsequent token; value types decode as `NullType` and the walker crashes in
   `find_end_of_stream`.

2. **Non-template BinXML vs `record.xml()` template path.**
   JPCERT encodes raw fragment trees (no `BinXmlTokenTemplateInstance`). Windows
   `wevtutil qe` tolerates this; `python-evtx`'s `record.xml()` always enters the
   template-instance path and misreads `0x41` (`OpenStartElement` with attributes)
   as `0x0C` (`TemplateInstance`).

**Upstream JPCERT has the same 9-byte header behavior** — confirmed by encoding the
fixture with upstream `xml2evtx.py` and hitting the same `NullTypeNode` failure
via `record.xml()`.

Adding the MS-EVEN6 `dependency_identifier` word fixes `python-evtx`'s
`OpenStartElementNode` but **breaks Windows `wevtutil`** (`The data is invalid`).
We keep the JPCERT 9-byte wire format for Windows compatibility and teach our
parser about it instead.

## Fix

| Layer | Change |
|-------|--------|
| Encoder (`_xml2evtx.py`) | Document intentional retention of JPCERT 9-byte headers; no wire-format change. |
| Parser (`evtx.py`) | Add `_JpcertOpenStartElementNode` walker (9-byte headers, inline name chunks, JPCERT-aware child dispatch). `_parse_evtx_with_python_evtx` renders fragments through this walker instead of `record.xml()`. |
| Imports | Lazy `lxml` / `_xml2evtx` / `python-evtx` imports in `evtx.py`; lazy conversion imports in `host_logs.py`. |
| `parse_evtx_event_fields` | Prefer `wevtutil` on Windows; fall back to python-evtx on failure. |

## Parser verification (actually run)

| Tool | Platform | Result |
|------|----------|--------|
| `python-evtx` (custom JPCERT walker) | Linux + Windows | ✅ All 3 fixture records; field maps match source XML |
| `wevtutil qe /f:xml` | Windows 11 26200 | ✅ All 3 fixture records (JPCERT wire format unchanged) |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | — | ❌ Not installed on dev host — follow-up TODO |

## Tests added

- `test_evtx_roundtrip_fixture_fields_match` — asserts all N records via
  `_parse_evtx_with_python_evtx` plus high-level `parse_evtx_event_fields`.
- `test_evtx_corrupted_eof_fails_python_evtx_parse` — break-then-detect: corrupt
  `BinXmlTokenEOF` → parser must not silently succeed.
- `test_socbench_stage_imports_without_binary_format_deps` — subprocess import
  guard blocks `lxml`/`Evtx`; `socbench.stage.bucketize` and
  `socbench.truth.panda` still import.

## Note on prior worklog claim

`docs/worklog/2026-07-12-native-host-logs.md` reported pytest `binary_formats` → 5
passed and wevtutil verification. That did not exercise the committed
`python-evtx` `record.xml()` assertion on Linux; treat this entry as the
authoritative cross-parser verification for the EVTX encoder path.
