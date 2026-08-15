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

//
// The filter manager's own transport header, obtained from the OS.
//
// This include is part of the contract, not a convenience. Every subsystem named
// above receives frames as
//
//     [FILTER_MESSAGE_HEADER (fltmgr, cleartext)][SHADOWSTRIKE_MESSAGE_HEADER][payload]
//
// and locates the payload as `buffer + sizeof(FILTER_MESSAGE_HEADER)`. That name
// must therefore resolve to the OS structure in every one of them.
//
// It did not. MessageProtocol.h used to typedef our own 40-byte
// SHADOWSTRIKE_MESSAGE_HEADER to FILTER_MESSAGE_HEADER whenever a translation
// unit had not already reached <fltUser.h>, so the payload offset a given .cpp
// computed depended on its include order: 16 bytes if it had the OS definition,
// 40 if it had ours. IPCManager.hpp and NetworkTrafficFilter.cpp each carried an
// explicit include and a comment about the hazard; FileSystemFilter.cpp - the
// on-access scan orchestrator - carried neither. Getting it wrong is not a
// failure, it is a 24-byte displacement read as a structure.
//
// Putting the include here fixes that structurally rather than per-file: this is
// the one header all five filter-port consumers already include, so obtaining
// the OS definition is no longer something a consumer can forget. The alias has
// also been removed outright, so a translation unit that somehow lacks this
// definition now fails to compile instead of computing a wrong offset.
//
#include <fltUser.h>

#include <string>

//
// Transport prefix size, asserted where the OS definition is in scope.
//
// x64: ULONG ReplyLength at 0, ULONGLONG MessageId at 8 (8-byte aligned), 16
// total. Two comments in this repo described it as 12 bytes - which is what it
// would be under pack(1) - and a third asserted only `<= 64`. None of them could
// have caught a wrong value; this does. If the SDK ever changes this structure,
// every offset computed from it must be revisited deliberately.
//
static_assert(sizeof(FILTER_MESSAGE_HEADER) == 16,
              "FILTER_MESSAGE_HEADER must be the OS filter-manager structure (16 bytes on x64). "
              "A different size means this translation unit resolved the name to something "
              "other than the OS type, and every payload offset computed from it is displaced.");
static_assert(offsetof(FILTER_MESSAGE_HEADER, ReplyLength) == 0,
              "FILTER_MESSAGE_HEADER::ReplyLength must be the first field.");
static_assert(offsetof(FILTER_MESSAGE_HEADER, MessageId) == 8,
              "FILTER_MESSAGE_HEADER::MessageId must be at offset 8; it is the value used to "
              "reply, so a displaced read answers the wrong kernel request.");

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
