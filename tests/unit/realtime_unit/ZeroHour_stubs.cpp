/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Test-harness stubs for ZeroHourProtection unit tests.
 *
 * Provides minimal symbol definitions for the 5 ThreatIntelLookup and
 * WhitelistStore methods referenced by ZeroHourProtection but not exercised
 * by the deterministic unit tests. All stubs return safe, uninitialized
 * defaults; they never touch live data stores or external services.
 */

#include "pch.h"
#include "../../../src/PhantomCore/ThreatIntel/ThreatIntelLookup.hpp"
#include "../../../src/PhantomCore/Whitelist/WhiteListStore.hpp"

namespace ShadowStrike {

// ============================================================================
// ThreatIntelLookup stubs
// ============================================================================

namespace ThreatIntel {

bool ThreatIntelLookup::IsInitialized() const noexcept {
    return false;
}

ThreatLookupResult ThreatIntelLookup::LookupSHA256(
    std::string_view /*sha256*/,
    const UnifiedLookupOptions& /*options*/) noexcept
{
    return ThreatLookupResult{};
}

BatchLookupResult ThreatIntelLookup::BatchLookupHashes(
    std::span<const std::string_view> /*hashes*/,
    const UnifiedLookupOptions& /*options*/) noexcept
{
    return BatchLookupResult{};
}

} // namespace ThreatIntel

// ============================================================================
// WhitelistStore stubs
// ============================================================================

namespace Whitelist {

LookupResult WhitelistStore::IsHashWhitelisted(
    const HashValue& /*hash*/,
    const QueryOptions& /*options*/) const noexcept
{
    return LookupResult{};
}

LookupResult WhitelistStore::IsPathWhitelisted(
    std::wstring_view /*path*/,
    const QueryOptions& /*options*/) const noexcept
{
    return LookupResult{};
}

} // namespace Whitelist

} // namespace ShadowStrike
