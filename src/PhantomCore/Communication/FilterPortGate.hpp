/**
 * @file FilterPortGate.hpp
 * @brief Serializes minifilter communication-port connects process-wide.
 *
 * @par The problem this solves
 * Several subsystems each own a connection to PhantomSensor's communication
 * port - the IPC manager, the file-system filter, the network traffic filter and
 * the file lock manager - and they all establish it while the service is coming
 * up. On the kernel side, @c ShadowStrikeConnectNotify runs with
 * @c ClientPortLock held EXCLUSIVE, and every minifilter callback that needs
 * that lock shared must wait. One connect is a brief pause. Several at once
 * serialize against each other while holding a lock the whole I/O path needs,
 * and the machine stops responding - observed as a grey screen with no bugcheck
 * and no minidump, which is why service startup was deferred to SCM
 * delayed-auto-start to avoid the window entirely.
 *
 * Deferring startup hid the storm rather than removing it: the same pile-up can
 * happen on any restart, and it left the product reporting "service offline" for
 * minutes after install. The concurrency is the actual defect.
 *
 * @par What this does
 * Every connect in the process passes through one gate, so at most one is ever
 * in flight, and consecutive connects are spaced by a short interval to let the
 * driver release the lock and let queued I/O drain between them. Sequential
 * connects are cheap; simultaneous ones are what wedge the system.
 *
 * This is not a retry or timeout wrapper - it does not mask a failure. It
 * removes the contention that made concurrent connects dangerous.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#pragma once

#include <Windows.h>
#include <string>

namespace ShadowStrike::Communication::FilterPortGate {

/// @brief Perform a serialized, spaced FilterConnectCommunicationPort call.
///
/// Semantics are identical to calling FilterConnectCommunicationPort directly;
/// only the timing relative to other connects in this process is controlled.
///
/// @param portName    Communication port name.
/// @param context     Optional connection context passed to the driver.
/// @param contextSize Size of @p context in bytes.
/// @param outPort     Receives the port handle on success.
/// @param callerTag   Short caller name, used only for diagnostics.
/// @return HRESULT from FilterConnectCommunicationPort.
[[nodiscard]] HRESULT Connect(
    const std::wstring& portName,
    const void*         context,
    WORD                contextSize,
    HANDLE*             outPort,
    const char*         callerTag) noexcept;

/// @brief Number of connects made through the gate (diagnostics).
[[nodiscard]] unsigned long ConnectCount() noexcept;

}  // namespace ShadowStrike::Communication::FilterPortGate
