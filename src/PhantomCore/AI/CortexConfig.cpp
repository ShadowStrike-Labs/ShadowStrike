/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike PhantomCortex - CONFIGURATION MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file CortexConfig.cpp
 * @brief Implementation of JSON and Registry-based configuration loading.
 *
 * Reuses:
 *   - JSONUtils (nlohmann wrapper) for JSON parsing / serialization
 *   - RegistryUtils::RegistryKey  for RAII registry access
 *   - FileUtils                   for file I/O and path validation
 *   - StringUtils                 for UTF-8 / UTF-16 conversion
 *
 * ============================================================================
 */

#include "pch.h"
#include "CortexConfig.hpp"

#include <shared_mutex>
#include <filesystem>
#include <algorithm>
#include <string>
#include <cmath>
#include <charconv>

#include "../Utils/Logger.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"

namespace ShadowStrike {
namespace AI {

// ============================================================================
// Anonymous Namespace — Internal Helpers
// ============================================================================

namespace {

    /// Log category for all CortexConfig messages
    constexpr const wchar_t* kLogCategory = L"PhantomCortex";

    /// Registry key path for PhantomCortex configuration
    constexpr const wchar_t* kRegistrySubKey =
        L"SOFTWARE\\ShadowStrike\\PhantomCortex";

    // ----------------------------------------------------------------
    // Path Security
    // ----------------------------------------------------------------

    // Component-level traversal check. Substring matching on the full
    // wstring rejects legitimate names containing ".." (e.g. "foo..bar")
    // and would also flag UNC/extended-length prefixes such as "\\?\".
    // The only sequence we must reject is a path component equal to "..".
    [[nodiscard]] bool ContainsTraversal(const std::filesystem::path& p) noexcept {
        try {
            for (const auto& part : p) {
                // path::iterator yields each component as a path; compare
                // against the wide ".." token.
                if (part.native() == L"..") {
                    return true;
                }
            }
            return false;
        }
        catch (...) {
            // Any iteration failure must be treated as untrusted input.
            return true;
        }
    }

    /// Hard upper bound on a registry-supplied path (defends against an
    /// attacker-populated REG_SZ that could otherwise inflate the working set).
    inline constexpr size_t kMaxRegistryPathLength = 32767;  // NTFS max (\\?\ extended)

    // ----------------------------------------------------------------
    // Threshold Clamping
    // ----------------------------------------------------------------

    [[nodiscard]] float ClampThreshold(float value, const wchar_t* name) noexcept {
        if (std::isnan(value) || std::isinf(value)) {
            SS_LOG_WARN(kLogCategory,
                L"Config '%ls' is NaN/Inf; clamping to 0.5", name);
            return 0.5f;
        }
        if (value < 0.0f) {
            SS_LOG_WARN(kLogCategory,
                L"Config '%ls' (%.4f) below 0.0; clamping to 0.0",
                name, static_cast<double>(value));
            return 0.0f;
        }
        if (value > 1.0f) {
            SS_LOG_WARN(kLogCategory,
                L"Config '%ls' (%.4f) above 1.0; clamping to 1.0",
                name, static_cast<double>(value));
            return 1.0f;
        }
        return value;
    }

    // ----------------------------------------------------------------
    // Full Config Validation
    // ----------------------------------------------------------------

    void ValidateConfig(CortexConfig& cfg) noexcept {
        cfg.staticThreshold     = ClampThreshold(cfg.staticThreshold,     L"staticThreshold");
        cfg.behavioralThreshold = ClampThreshold(cfg.behavioralThreshold, L"behavioralThreshold");
        cfg.memoryThreshold     = ClampThreshold(cfg.memoryThreshold,     L"memoryThreshold");
        cfg.networkThreshold    = ClampThreshold(cfg.networkThreshold,    L"networkThreshold");
        cfg.emulationThreshold  = ClampThreshold(cfg.emulationThreshold,  L"emulationThreshold");
        cfg.ensembleThreshold   = ClampThreshold(cfg.ensembleThreshold,   L"ensembleThreshold");

        if (cfg.maxBatchSize == 0) {
            SS_LOG_WARN(kLogCategory,
                L"maxBatchSize is 0; setting to 1");
            cfg.maxBatchSize = 1;
        }
        if (cfg.maxBatchSize > CortexConstants::MAX_BATCH_SIZE) {
            SS_LOG_WARN(kLogCategory,
                L"maxBatchSize (%u) exceeds maximum (%u); capping",
                cfg.maxBatchSize, CortexConstants::MAX_BATCH_SIZE);
            cfg.maxBatchSize = CortexConstants::MAX_BATCH_SIZE;
        }

        if (cfg.inferenceTimeoutMs == 0) {
            SS_LOG_WARN(kLogCategory,
                L"inferenceTimeoutMs is 0; using default %u",
                CortexConstants::DEFAULT_INFERENCE_TIMEOUT_MS);
            cfg.inferenceTimeoutMs = CortexConstants::DEFAULT_INFERENCE_TIMEOUT_MS;
        }
        if (cfg.inferenceTimeoutMs > CortexConstants::MAX_INFERENCE_TIMEOUT_MS) {
            SS_LOG_WARN(kLogCategory,
                L"inferenceTimeoutMs (%u) exceeds maximum (%u); capping",
                cfg.inferenceTimeoutMs, CortexConstants::MAX_INFERENCE_TIMEOUT_MS);
            cfg.inferenceTimeoutMs = CortexConstants::MAX_INFERENCE_TIMEOUT_MS;
        }

        // Validate model directory exists (if set)
        if (!cfg.modelDirectory.empty()) {
            if (ContainsTraversal(cfg.modelDirectory)) {
                SS_LOG_ERROR(kLogCategory,
                    L"modelDirectory contains path traversal; rejecting: %ls",
                    cfg.modelDirectory.c_str());
                cfg.modelDirectory.clear();
            }
            else {
                try {
                    std::error_code ec;
                    if (!std::filesystem::exists(cfg.modelDirectory, ec) || ec) {
                        SS_LOG_WARN(kLogCategory,
                            L"modelDirectory does not exist: %ls",
                            cfg.modelDirectory.c_str());
                    }
                }
                catch (...) {
                    SS_LOG_WARN(kLogCategory,
                        L"Exception validating modelDirectory: %ls",
                        cfg.modelDirectory.c_str());
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // Safe float parsing from wide string (for Registry REG_SZ floats)
    // ----------------------------------------------------------------

    [[nodiscard]] bool SafeParseFloat(const std::wstring& str, float& out) noexcept {
        try {
            const std::string narrow = Utils::StringUtils::ToNarrow(str);
            if (narrow.empty()) return false;
            float result = 0.0f;
            const auto [ptr, ec] = std::from_chars(
                narrow.data(), narrow.data() + narrow.size(), result);
            if (ec != std::errc{} || ptr != narrow.data() + narrow.size()) {
                return false;
            }
            // Reject NaN / +-Inf at parse time so the caller sees a clean
            // failure rather than a silent clamp inside ValidateConfig().
            if (!std::isfinite(result)) {
                return false;
            }
            out = result;
            return true;
        }
        catch (...) {
            return false;
        }
    }

}  // anonymous namespace

// ============================================================================
// Impl Definition
// ============================================================================

struct CortexConfigManager::Impl {
    CortexConfig             config{};
    mutable std::shared_mutex configMutex;
    bool                     loaded = false;
};

// ============================================================================
// Singleton
// ============================================================================

CortexConfigManager& CortexConfigManager::Instance() noexcept {
    static CortexConfigManager instance;
    return instance;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

CortexConfigManager::CortexConfigManager()
    : m_impl(std::make_unique<Impl>())
{
}

CortexConfigManager::~CortexConfigManager() = default;

// ============================================================================
// GetConfig
// ============================================================================

CortexConfig CortexConfigManager::GetConfig() const noexcept {
    if (!m_impl) return CortexConfig{};

    std::shared_lock lock(m_impl->configMutex);
    return m_impl->config;
}

// ============================================================================
// LoadConfig (JSON file)
// ============================================================================

bool CortexConfigManager::LoadConfig(const std::filesystem::path& configPath) noexcept {
    try {
        if (configPath.empty()) {
            SS_LOG_ERROR(kLogCategory,
                L"LoadConfig called with empty path");
            return false;
        }
        if (ContainsTraversal(configPath)) {
            SS_LOG_ERROR(kLogCategory,
                L"LoadConfig rejected path with traversal: %ls",
                configPath.c_str());
            return false;
        }

        if (!m_impl) {
            SS_LOG_ERROR(kLogCategory,
                L"CortexConfigManager::Impl not initialized");
            return false;
        }

        // Check file existence
        {
            std::error_code ec;
            if (!std::filesystem::exists(configPath, ec) || ec) {
                SS_LOG_ERROR(kLogCategory,
                    L"Config file does not exist: %ls", configPath.c_str());
                return false;
            }
        }

        // Load JSON
        Utils::JSON::Json doc;
        Utils::JSON::Error jsonErr;
        if (!Utils::JSON::LoadFromFile(configPath, doc, &jsonErr)) {
            SS_LOG_ERROR(kLogCategory,
                L"Failed to parse config JSON from %ls: %hs",
                configPath.c_str(), jsonErr.message.c_str());
            return false;
        }

        // Build config from defaults, then overlay JSON values
        CortexConfig cfg{};

        // Model directory
        std::string modelDir;
        if (Utils::JSON::Get<std::string>(doc, "modelDirectory", modelDir)) {
            cfg.modelDirectory = Utils::StringUtils::ToWide(modelDir);
        }

        // Per-model thresholds
        float fval = 0.0f;
        if (Utils::JSON::Get<float>(doc, "staticThreshold", fval))
            cfg.staticThreshold = fval;
        if (Utils::JSON::Get<float>(doc, "behavioralThreshold", fval))
            cfg.behavioralThreshold = fval;
        if (Utils::JSON::Get<float>(doc, "memoryThreshold", fval))
            cfg.memoryThreshold = fval;
        if (Utils::JSON::Get<float>(doc, "networkThreshold", fval))
            cfg.networkThreshold = fval;
        if (Utils::JSON::Get<float>(doc, "emulationThreshold", fval))
            cfg.emulationThreshold = fval;
        if (Utils::JSON::Get<float>(doc, "ensembleThreshold", fval))
            cfg.ensembleThreshold = fval;

        // Hardware
        bool bval = false;
        if (Utils::JSON::Get<bool>(doc, "useGPU", bval))
            cfg.useGPU = bval;
        if (Utils::JSON::Get<bool>(doc, "useAVX512", bval))
            cfg.useAVX512 = bval;

        // Batching and timeout
        uint32_t uval = 0;
        if (Utils::JSON::Get<uint32_t>(doc, "maxBatchSize", uval))
            cfg.maxBatchSize = uval;
        if (Utils::JSON::Get<uint32_t>(doc, "inferenceTimeoutMs", uval))
            cfg.inferenceTimeoutMs = uval;

        // Validate and clamp
        ValidateConfig(cfg);

        // Commit under exclusive lock
        {
            std::unique_lock lock(m_impl->configMutex);
            m_impl->config = cfg;
            m_impl->loaded = true;
        }

        SS_LOG_INFO(kLogCategory,
            L"Configuration loaded from %ls", configPath.c_str());
        SS_LOG_INFO(kLogCategory,
            L"  modelDirectory      = %ls", cfg.modelDirectory.c_str());
        SS_LOG_INFO(kLogCategory,
            L"  staticThreshold     = %.4f", static_cast<double>(cfg.staticThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  behavioralThreshold = %.4f", static_cast<double>(cfg.behavioralThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  memoryThreshold     = %.4f", static_cast<double>(cfg.memoryThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  networkThreshold    = %.4f", static_cast<double>(cfg.networkThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  emulationThreshold  = %.4f", static_cast<double>(cfg.emulationThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  ensembleThreshold   = %.4f", static_cast<double>(cfg.ensembleThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  useGPU=%d useAVX512=%d maxBatch=%u timeoutMs=%u",
            cfg.useGPU ? 1 : 0, cfg.useAVX512 ? 1 : 0,
            cfg.maxBatchSize, cfg.inferenceTimeoutMs);

        return true;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in CortexConfigManager::LoadConfig");
        return false;
    }
}

// ============================================================================
// LoadFromRegistry
// ============================================================================

bool CortexConfigManager::LoadFromRegistry() noexcept {
    try {
        if (!m_impl) {
            SS_LOG_ERROR(kLogCategory,
                L"CortexConfigManager::Impl not initialized");
            return false;
        }

        Utils::RegistryUtils::RegistryKey key;
        Utils::RegistryUtils::Error regErr;
        Utils::RegistryUtils::OpenOptions openOpt;
        openOpt.access = KEY_READ;

        if (!key.Open(HKEY_LOCAL_MACHINE, kRegistrySubKey, openOpt, &regErr)) {
            SS_LOG_ERROR(kLogCategory,
                L"Cannot open registry key %ls (Win32=%lu): %ls",
                kRegistrySubKey, regErr.win32, regErr.message.c_str());
            return false;
        }

        CortexConfig cfg{};  // start with defaults

        // --- REG_SZ values (paths and float-as-string) ---
        auto readRegString = [&](const wchar_t* name, std::wstring& out) {
            Utils::RegistryUtils::Error rErr;
            std::wstring val;
            if (key.ReadString(name, val, &rErr)) {
                out = std::move(val);
                return true;
            }
            return false;
        };

        auto readRegFloat = [&](const wchar_t* name, float& out) {
            std::wstring strVal;
            if (readRegString(name, strVal)) {
                float parsed = 0.0f;
                if (SafeParseFloat(strVal, parsed)) {
                    out = parsed;
                    return true;
                }
                else {
                    SS_LOG_WARN(kLogCategory,
                        L"Registry value '%ls' is not a valid float: %ls",
                        name, strVal.c_str());
                }
            }
            return false;
        };

        // ModelDirectory
        {
            std::wstring dir;
            if (readRegString(L"ModelDirectory", dir)) {
                if (dir.size() > kMaxRegistryPathLength) {
                    SS_LOG_ERROR(kLogCategory,
                        L"Registry ModelDirectory length (%zu) exceeds %zu; rejecting",
                        dir.size(), kMaxRegistryPathLength);
                }
                else if (!dir.empty()) {
                    cfg.modelDirectory = std::filesystem::path(std::move(dir));
                }
            }
        }

        // Thresholds (stored as REG_SZ float strings)
        readRegFloat(L"StaticThreshold",     cfg.staticThreshold);
        readRegFloat(L"BehavioralThreshold", cfg.behavioralThreshold);
        readRegFloat(L"MemoryThreshold",     cfg.memoryThreshold);
        readRegFloat(L"NetworkThreshold",    cfg.networkThreshold);
        readRegFloat(L"EmulationThreshold",  cfg.emulationThreshold);
        readRegFloat(L"EnsembleThreshold",   cfg.ensembleThreshold);

        // --- REG_DWORD values ---
        auto readRegDword = [&](const wchar_t* name, DWORD& out) {
            Utils::RegistryUtils::Error rErr;
            DWORD val = 0;
            if (key.ReadDWord(name, val, &rErr)) {
                out = val;
                return true;
            }
            return false;
        };

        // Booleans (REG_DWORD: 0 or 1)
        {
            DWORD dval = 0;
            if (readRegDword(L"UseGPU", dval))
                cfg.useGPU = (dval != 0);
            if (readRegDword(L"UseAVX512", dval))
                cfg.useAVX512 = (dval != 0);
        }

        // Integers
        {
            DWORD dval = 0;
            if (readRegDword(L"MaxBatchSize", dval))
                cfg.maxBatchSize = static_cast<uint32_t>(dval);
            if (readRegDword(L"InferenceTimeoutMs", dval))
                cfg.inferenceTimeoutMs = static_cast<uint32_t>(dval);
        }

        // Validate and clamp
        ValidateConfig(cfg);

        // Commit under exclusive lock
        {
            std::unique_lock lock(m_impl->configMutex);
            m_impl->config = cfg;
            m_impl->loaded = true;
        }

        SS_LOG_INFO(kLogCategory,
            L"Configuration loaded from registry key %ls", kRegistrySubKey);
        SS_LOG_INFO(kLogCategory,
            L"  modelDirectory      = %ls", cfg.modelDirectory.c_str());
        SS_LOG_INFO(kLogCategory,
            L"  staticThreshold     = %.4f", static_cast<double>(cfg.staticThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  behavioralThreshold = %.4f", static_cast<double>(cfg.behavioralThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  memoryThreshold     = %.4f", static_cast<double>(cfg.memoryThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  networkThreshold    = %.4f", static_cast<double>(cfg.networkThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  emulationThreshold  = %.4f", static_cast<double>(cfg.emulationThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  ensembleThreshold   = %.4f", static_cast<double>(cfg.ensembleThreshold));
        SS_LOG_INFO(kLogCategory,
            L"  useGPU=%d useAVX512=%d maxBatch=%u timeoutMs=%u",
            cfg.useGPU ? 1 : 0, cfg.useAVX512 ? 1 : 0,
            cfg.maxBatchSize, cfg.inferenceTimeoutMs);

        return true;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in CortexConfigManager::LoadFromRegistry");
        return false;
    }
}

// ============================================================================
// SaveConfig (JSON file)
// ============================================================================

bool CortexConfigManager::SaveConfig(
        const std::filesystem::path& configPath) const noexcept {
    try {
        if (!m_impl) {
            SS_LOG_ERROR(kLogCategory,
                L"SaveConfig called before any configuration was loaded");
            return false;
        }
        if (configPath.empty()) {
            SS_LOG_ERROR(kLogCategory,
                L"SaveConfig called with empty path");
            return false;
        }
        if (ContainsTraversal(configPath)) {
            SS_LOG_ERROR(kLogCategory,
                L"SaveConfig rejected path with traversal: %ls",
                configPath.c_str());
            return false;
        }

        // Snapshot config under shared lock
        CortexConfig snapshot;
        {
            std::shared_lock lock(m_impl->configMutex);
            snapshot = m_impl->config;
        }

        // Defense-in-depth: re-validate the snapshot before serializing so
        // a corrupted in-memory state (e.g. a future code path mutating the
        // config without going through Load*) cannot be persisted to disk.
        ValidateConfig(snapshot);

        // Build JSON document. Utils::JSON::Set is [[nodiscard]] — every
        // failure must be propagated; silent type-mismatch corruption of the
        // serialized config is unacceptable.
        Utils::JSON::Json doc;

        bool ok = true;
        ok = ok && Utils::JSON::Set(doc, "modelDirectory",
            Utils::StringUtils::ToNarrow(snapshot.modelDirectory.wstring()));

        ok = ok && Utils::JSON::Set(doc, "staticThreshold",
            static_cast<double>(snapshot.staticThreshold));
        ok = ok && Utils::JSON::Set(doc, "behavioralThreshold",
            static_cast<double>(snapshot.behavioralThreshold));
        ok = ok && Utils::JSON::Set(doc, "memoryThreshold",
            static_cast<double>(snapshot.memoryThreshold));
        ok = ok && Utils::JSON::Set(doc, "networkThreshold",
            static_cast<double>(snapshot.networkThreshold));
        ok = ok && Utils::JSON::Set(doc, "emulationThreshold",
            static_cast<double>(snapshot.emulationThreshold));
        ok = ok && Utils::JSON::Set(doc, "ensembleThreshold",
            static_cast<double>(snapshot.ensembleThreshold));

        ok = ok && Utils::JSON::Set(doc, "useGPU",    snapshot.useGPU);
        ok = ok && Utils::JSON::Set(doc, "useAVX512", snapshot.useAVX512);

        ok = ok && Utils::JSON::Set(doc, "maxBatchSize",
            static_cast<uint32_t>(snapshot.maxBatchSize));
        ok = ok && Utils::JSON::Set(doc, "inferenceTimeoutMs",
            static_cast<uint32_t>(snapshot.inferenceTimeoutMs));

        if (!ok) {
            SS_LOG_ERROR(kLogCategory,
                L"SaveConfig: failed to populate JSON document for %ls",
                configPath.c_str());
            return false;
        }

        // Write to disk
        Utils::JSON::SaveOptions saveOpt;
        saveOpt.pretty        = true;
        saveOpt.indentSpaces  = 4;
        saveOpt.atomicReplace = true;

        Utils::JSON::Error jsonErr;
        if (!Utils::JSON::SaveToFile(configPath, doc, &jsonErr, saveOpt)) {
            SS_LOG_ERROR(kLogCategory,
                L"Failed to save config to %ls: %hs",
                configPath.c_str(), jsonErr.message.c_str());
            return false;
        }

        SS_LOG_INFO(kLogCategory,
            L"Configuration saved to %ls", configPath.c_str());
        return true;
    }
    catch (...) {
        SS_LOG_ERROR(kLogCategory,
            L"Unhandled exception in CortexConfigManager::SaveConfig");
        return false;
    }
}

}  // namespace AI
}  // namespace ShadowStrike
