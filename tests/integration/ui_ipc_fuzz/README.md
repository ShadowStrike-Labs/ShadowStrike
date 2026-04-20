# UI IPC Frame Fuzz Harness

Smoke-grade fuzz driver for the PhantomHome UI named-pipe frame + payload
decoders. The target surface is the CBOR envelope decoder
(`DecodeEnvelopeCbor`) and every `FromJson` payload parser reachable from
`IPCRouter::Dispatch`; the threat model is a local, interactively-logged-on
attacker who has survived the connect-time token gate and is now sending
crafted frames to the LocalSystem service.

## What it covers

- Hand-crafted hostile corpus exercising known decoder rejection paths:
  empty input, unterminated CBOR, oversize string / bignum / frame, deep
  map nesting, type confusion, invalid major-type bytes.
- Deterministic bit-flip campaign mutating a valid `Hello` envelope so
  regressions in the decoder or any `FromJson` parser are reproducible.
- Exposes an `LLVMFuzzerTestOneInput` entry point so the same TU can be
  linked against libFuzzer / afl++ / any sanitizer-aware engine without
  changes.

## Standalone build

```cmd
vcvars64.bat
cl /nologo /EHa /std:c++20 /Zc:__cplusplus ^
   /DUNICODE /D_UNICODE /DNOMINMAX /DWIN32_LEAN_AND_MEAN ^
   /I include /I include\YARA /I src ^
   tests\integration\ui_ipc_fuzz\IPCFrameFuzz.cpp ^
   /link /out:build\ipc_frame_fuzz.exe advapi32.lib
```

Default run: `ipc_frame_fuzz.exe` — 4096 bit-flip rounds plus the hostile
corpus. Override via `ipc_frame_fuzz.exe <rounds> <seed>`.

## Exit codes

- `0` — all inputs processed cleanly. Hostile frames are expected to be
  rejected by the decoder; the harness only fails on crashes (the OS
  surfaces those as access violation, stack overflow, etc.).
- non-zero — structured exception or CRT abort; investigate.

## Wiring

The harness is self-contained and does not yet register with the main
`Fuzzer.vcxproj` campaign runner nor with `ShadowStrike.vcxproj`.
Adding it to either is a follow-up once the owning agent is free.
