/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FileExtAPI.hpp — Kernel32 extended file operation API handlers
 *
 * Covers SetFileTime, GetFileTime, SetFileAttributesA/W,
 * GetFileInformationByHandle, GetFileInformationByHandleEx,
 * FindFirstFileExA/W, GetShortPathNameA/W, GetLongPathNameA/W,
 * GetFullPathNameA/W, CreateDirectoryA/W, RemoveDirectoryA/W,
 * SetEndOfFile, LockFile, UnlockFile.
 *
 * Timestomping (T1070.006), attribute hiding, and file locking
 * are high-value IOCs for defense evasion and ransomware detection.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

void RegisterFileExtAPI(APIDispatcher& dispatcher) noexcept;

bool HandleSetFileTime(APIContext& ctx);
bool HandleGetFileTime(APIContext& ctx);
bool HandleSetFileAttributesA(APIContext& ctx);
bool HandleSetFileAttributesW(APIContext& ctx);
bool HandleGetFileInformationByHandle(APIContext& ctx);
bool HandleGetFileInformationByHandleEx(APIContext& ctx);
bool HandleFindFirstFileExA(APIContext& ctx);
bool HandleFindFirstFileExW(APIContext& ctx);
bool HandleGetShortPathNameA(APIContext& ctx);
bool HandleGetShortPathNameW(APIContext& ctx);
bool HandleGetLongPathNameA(APIContext& ctx);
bool HandleGetLongPathNameW(APIContext& ctx);
bool HandleGetFullPathNameA(APIContext& ctx);
bool HandleGetFullPathNameW(APIContext& ctx);
bool HandleCreateDirectoryA(APIContext& ctx);
bool HandleCreateDirectoryW(APIContext& ctx);
bool HandleRemoveDirectoryA(APIContext& ctx);
bool HandleRemoveDirectoryW(APIContext& ctx);
bool HandleSetEndOfFile(APIContext& ctx);
bool HandleLockFile(APIContext& ctx);
bool HandleUnlockFile(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
