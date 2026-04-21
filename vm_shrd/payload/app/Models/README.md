# ShadowStrike PhantomCortex — Model Store

This directory is the baseline layout for the PhantomCortex ML model store.
At install time `02_install.bat` copies the contents of this directory into
`%ProgramData%\ShadowStrike\Models\` and registers that location in
`HKLM\SOFTWARE\ShadowStrike\PhantomCortex\ModelDirectory`.

PhantomCortex initialises five independent slots.  Each slot is a sub-directory
that follows the atomic-swap layout enforced by `ModelCache`:

```
Models/
├── static/        ← cortex_static        (PE / document static analysis)
├── behavioral/    ← cortex_behavioral    (process + syscall behaviour)
├── memory/        ← cortex_memory        (in-memory payload anomalies)
├── network/       ← cortex_network       (C2 / DGA / exfil)
└── emulation/     ← cortex_emulation     (post-emulation trace classification)
```

Each slot directory accepts the following files:

| File              | Role                                                               |
|-------------------|--------------------------------------------------------------------|
| `current.onnx`    | Active model.  Loaded at service start and used for every inference. |
| `previous.onnx`   | Previous model retained for automatic rollback after a bad swap.   |
| `staging.onnx`    | Transient — appears only during hot-swap.                          |
| `manifest.json`   | Version, SHA-256 integrity hash, training timestamp.               |

## Graceful degradation

If a slot directory contains no `current.onnx`, PhantomCortex logs:

```
[PhantomCortex] No model file found for <Slot> slot — slot will be inactive
```

…and leaves that slot inactive.  Scan traffic continues to flow through
signature-, heuristic-, YARA-, and emulation-based detectors.  **A missing model
is not a fatal error.**  The service remains fully functional and protects the
endpoint with the remaining layers of detection.

## Populating models

Drop production `.onnx` artefacts under the corresponding slot sub-directories
as `current.onnx` and, optionally, author a `manifest.json` describing the
trained model.  A schema compatible with `ModelCache` looks like:

```json
{
    "slot":          "static",
    "version":       { "major": 1, "minor": 0, "patch": 0 },
    "sha256":        "<64-hex SHA-256 of current.onnx>",
    "trained_at":    "2026-04-21T00:00:00Z",
    "training_set":  "<identifier>",
    "notes":         "<freeform>"
}
```

Training pipelines for the five slots live under `PhantomCortex/training/`.
