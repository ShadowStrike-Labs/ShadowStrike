/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FileAPI.hpp — Kernel32 file I/O API handlers
 *
 * Covers CreateFileA/W, ReadFile, WriteFile, CloseHandle,
 * DeleteFileA/W, MoveFileA/W, CopyFileA/W, GetFileSize/Ex,
 * SetFilePointer/Ex, GetFileAttributesA/W,
 * FindFirstFileA/W, FindNextFileA/W, FindClose, GetTempPathA/W.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 file I/O handlers with the dispatcher.
void RegisterFileAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleCreateFileA(APIContext& ctx);
bool HandleCreateFileW(APIContext& ctx);
bool HandleReadFile(APIContext& ctx);
bool HandleWriteFile(APIContext& ctx);
bool HandleCloseHandle(APIContext& ctx);
bool HandleDeleteFileA(APIContext& ctx);
bool HandleDeleteFileW(APIContext& ctx);
bool HandleMoveFileA(APIContext& ctx);
bool HandleMoveFileW(APIContext& ctx);
bool HandleCopyFileA(APIContext& ctx);
bool HandleCopyFileW(APIContext& ctx);
bool HandleGetFileSize(APIContext& ctx);
bool HandleGetFileSizeEx(APIContext& ctx);
bool HandleSetFilePointer(APIContext& ctx);
bool HandleSetFilePointerEx(APIContext& ctx);
bool HandleGetFileAttributesA(APIContext& ctx);
bool HandleGetFileAttributesW(APIContext& ctx);
bool HandleFindFirstFileA(APIContext& ctx);
bool HandleFindFirstFileW(APIContext& ctx);
bool HandleFindNextFileA(APIContext& ctx);
bool HandleFindNextFileW(APIContext& ctx);
bool HandleFindClose(APIContext& ctx);
bool HandleGetTempPathA(APIContext& ctx);
bool HandleGetTempPathW(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
