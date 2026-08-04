# PhantomSensor kernel source contracts

These tests are safe to run on the development host. They do **not** load, install, restart, or communicate with `PhantomSensor.sys`.

Run from the repository root:

```powershell
py tests\kernel_contracts\test_phantom_sensor_scanner_identity.py
```

The suite binds the production source to the non-negotiable scanner-recursion and communication-lifecycle invariants:

- `ShadowStrikePreCreate` captures `FltGetRequestorProcessIdEx(Data)` once and keeps `NULL` as unknown.
- The same operation requestor PID flows through `ScanBridge`; unknown is serialized as PID 0 without a current-worker fallback.
- Accepted scanner I/O has exactly one scanner-identity gate: only recursive user-mode cache/IPC is skipped. In-kernel analysis and the final threat-score verdict remain active.
- `ShadowStrikeScanBridgeIsReady` requires a KEX-ready primary, and synchronous scan transports acquire with fallback disabled.
- Primary scanner identity is pointer-sized and per slot; rejected KEX queues never publish it.
- KEX owns a reference before queue publication and consumes that exact generation/port reference in its worker.
- Opaque callback cookies carry slot plus nonzero generation, preventing delayed Message/Disconnect callbacks from binding to a reused slot.
- Disconnect has one baseline/publication owner; readiness and per-slot PID publication retire exactly once.
- `FltCloseClientPort` has one canonical owner and executes only in PASSIVE finalization. APC-level last release uses a preallocated work item, and shutdown waits for explicit teardown completion.
- Primary selection skips pending/unkeyed slots, while same-PID and different-PID overlapping primaries remain independent.
- Executable models cover stale-cookie reuse, disconnect-before-KEX completion, APC finalizer queue failure with PASSIVE retry, rejected primaries, overlap ordering, and pending-lower/ready-higher selection.

These are structural contracts plus small executable lifecycle specifications—not a substitute for Filter Manager concurrency testing. Before shipping an installer, use the snapshot-only procedure under `vm_shrd/PhantomSensorScannerRecursion`. Its `ScanPathEvidenced` result requires an authoritative scan counter; `ConditionalSmoke` is intentionally weaker and says so.
