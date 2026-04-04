/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtFile.hpp — Nt* file-system and I/O syscall handlers
 *
 * Covers NtCreateFile, NtReadFile, NtWriteFile, NtClose,
 * NtSetInformationFile, NtQueryInformationFile,
 * NtQueryDirectoryFile, and NtDeviceIoControlFile.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* file / IO handlers with the dispatcher.
void RegisterNtFile(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleNtCreateFile(APIContext& ctx);
bool HandleNtReadFile(APIContext& ctx);
bool HandleNtWriteFile(APIContext& ctx);
bool HandleNtClose(APIContext& ctx);
bool HandleNtSetInformationFile(APIContext& ctx);
bool HandleNtQueryInformationFile(APIContext& ctx);
bool HandleNtQueryDirectoryFile(APIContext& ctx);
bool HandleNtDeviceIoControlFile(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
