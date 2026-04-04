/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CredentialAPI.hpp — Advapi32 credential and LSA API handlers
 *
 * Covers CredReadA/W, CredEnumerateA/W, CredWriteA/W, CredDeleteA/W,
 * CredFree, LsaOpenPolicy, LsaRetrievePrivateData, LsaStorePrivateData,
 * LsaClose.
 *
 * ENTERPRISE CRITICAL:
 *   - Credential enumeration/read is MITRE ATT&CK T1555 (Credentials
 *     from Password Stores). Infostealers harvest cached credentials
 *     via CredRead/CredEnumerate for browser passwords, RDP creds, etc.
 *   - LsaRetrievePrivateData is the core API abused by Mimikatz-style
 *     tools to extract LSA secrets (service account passwords, cached
 *     domain credentials, DPAPI master keys).
 *   - CredWrite with persistence flags indicates credential planting
 *     for later lateral movement.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Advapi32 {

// Register all credential/LSA handlers with the dispatcher.
void RegisterCredentialAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

// Credential Manager APIs
bool HandleCredReadA(APIContext& ctx);
bool HandleCredReadW(APIContext& ctx);
bool HandleCredEnumerateA(APIContext& ctx);
bool HandleCredEnumerateW(APIContext& ctx);
bool HandleCredWriteA(APIContext& ctx);
bool HandleCredWriteW(APIContext& ctx);
bool HandleCredDeleteA(APIContext& ctx);
bool HandleCredDeleteW(APIContext& ctx);
bool HandleCredFree(APIContext& ctx);

// LSA Policy APIs — Mimikatz attack surface
bool HandleLsaOpenPolicy(APIContext& ctx);
bool HandleLsaRetrievePrivateData(APIContext& ctx);
bool HandleLsaStorePrivateData(APIContext& ctx);
bool HandleLsaClose(APIContext& ctx);

} // namespace WinAPI::Advapi32
} // namespace Phantom
