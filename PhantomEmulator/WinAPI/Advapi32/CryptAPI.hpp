/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * CryptAPI.hpp — Advapi32 cryptographic API handlers
 *
 * Covers CryptAcquireContextA/W, CryptGenRandom, CryptEncrypt,
 * CryptDecrypt, CryptCreateHash, CryptHashData, CryptReleaseContext.
 *
 * All encryption/decryption activity is tracked as a potential ransomware
 * indicator. CryptGenRandom uses a deterministic LCG for reproducible
 * analysis while producing non-zero fill patterns.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Advapi32 {

void RegisterCryptAPI(APIDispatcher& dispatcher) noexcept;

bool HandleCryptAcquireContextA(APIContext& ctx);
bool HandleCryptAcquireContextW(APIContext& ctx);
bool HandleCryptGenRandom(APIContext& ctx);
bool HandleCryptEncrypt(APIContext& ctx);
bool HandleCryptDecrypt(APIContext& ctx);
bool HandleCryptCreateHash(APIContext& ctx);
bool HandleCryptHashData(APIContext& ctx);
bool HandleCryptReleaseContext(APIContext& ctx);

} // namespace WinAPI::Advapi32
} // namespace Phantom
