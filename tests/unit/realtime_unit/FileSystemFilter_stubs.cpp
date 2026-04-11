/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Test-harness shims for FileSystemFilter unit tests.
 *
 * These definitions satisfy cross-module symbols that are not exercised by the
 * deterministic unit tests. They return safe, inert defaults so the harness can
 * validate local contracts without pulling in the full scan, AI, whitelist, and
 * kernel communication stacks.
 */

#include "pch.h"

#include <new>

#include "../../../src/PhantomCore/RealTime/FileSystemFilter.hpp"
#include "../../../src/PhantomCore/Whitelist/WhiteListStore.hpp"
#include "../../../src/PhantomCore/HashStore/HashStore.hpp"
#include "../../../src/PhantomCore/Core/Engine/ScanEngine.hpp"
#include "../../../src/PhantomCore/Core/FileSystem/FileLockManager.hpp"
#include "../../../src/PhantomCore/AI/PhantomCortex.hpp"

namespace ShadowStrike {

namespace Whitelist {

LookupResult WhitelistStore::IsPathWhitelisted(
    std::wstring_view /*path*/,
    const QueryOptions& /*options*/) const noexcept
{
    return LookupResult{};
}

}  // namespace Whitelist

namespace HashStore {

std::optional<SignatureStore::DetectionResult> HashStore::LookupHashString(
    const std::string& /*hashStr*/,
    SignatureStore::HashType /*type*/) const noexcept
{
    return std::nullopt;
}

}  // namespace HashStore

namespace Core::Engine {

EngineResult ScanEngine::ScanFile(
    const std::wstring& /*filePath*/,
    const ScanContext& /*context*/)
{
    return EngineResult{};
}

}  // namespace Core::Engine

namespace Core::FileSystem {

FileLockManager& FileLockManager::Instance() {
    alignas(FileLockManager) static unsigned char storage[sizeof(FileLockManager)]{};
    return *std::launder(reinterpret_cast<FileLockManager*>(storage));
}

FileLockInfo FileLockManager::GetLockInfo(const std::wstring& filePath) const {
    FileLockInfo info;
    info.filePath = filePath;
    info.isLocked = false;
    info.lockCount = 0;
    return info;
}

}  // namespace Core::FileSystem

namespace AI {

PhantomCortex& PhantomCortex::Instance() noexcept {
    alignas(PhantomCortex) static unsigned char storage[sizeof(PhantomCortex)]{};
    return *std::launder(reinterpret_cast<PhantomCortex*>(storage));
}

bool PhantomCortex::IsOperational() const noexcept {
    return false;
}

CortexVerdict PhantomCortex::AnalyzeFile(std::span<const uint8_t> /*fileBytes*/) noexcept {
    return CortexVerdict{};
}

}  // namespace AI

}  // namespace ShadowStrike
