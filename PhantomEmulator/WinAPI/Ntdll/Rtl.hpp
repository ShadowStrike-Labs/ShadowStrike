/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * Rtl.hpp — Ntdll RTL function handler declarations
 *
 * Emulates the NT Runtime Library functions that malware relies on
 * for heap management, memory manipulation, string operations,
 * system version queries, and decompression. These are non-syscall
 * ntdll exports called directly by user-mode code.
 *
 * Registered handlers:
 *   Heap:    RtlAllocateHeap, RtlFreeHeap, RtlReAllocateHeap,
 *            RtlSizeHeap, RtlCreateHeap, RtlDestroyHeap
 *   Memory:  RtlCopyMemory, RtlMoveMemory, RtlZeroMemory,
 *            RtlFillMemory, RtlCompareMemory
 *   String:  RtlInitUnicodeString, RtlInitAnsiString,
 *            RtlUnicodeStringToAnsiString, RtlAnsiStringToUnicodeString,
 *            RtlFreeUnicodeString, RtlFreeAnsiString
 *   SysInfo: RtlGetVersion, RtlGetNtVersionNumbers
 *   Decomp:  RtlDecompressBuffer (stub — flags packed malware)
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

/// Register all RTL function handlers with the API dispatcher.
/// Called by APIDispatcher::RegisterNtdll() during initialization.
void RegisterRtlHandlers(APIDispatcher& dispatcher) noexcept;

/// Reset internal RTL state (heap tracking, string allocations).
/// Must be called between emulation sessions to prevent state leakage.
void ResetRtlState() noexcept;

} // namespace WinAPI::Ntdll
} // namespace Phantom
