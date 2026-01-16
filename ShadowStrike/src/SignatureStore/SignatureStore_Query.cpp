// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include"SignatureStore.hpp"

namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // SPECIFIC QUERY METHODS
        // ============================================================================

        std::optional<DetectionResult> SignatureStore::LookupHash(const HashValue& hash) const noexcept {
            if (!m_hashStoreEnabled.load() || !m_hashStore) {
                return std::nullopt;
            }

            return m_hashStore->LookupHash(hash);
        }

        std::optional<DetectionResult> SignatureStore::LookupHashString(
            const std::string& hashStr,
            HashType type
        ) const noexcept {
            if (!m_hashStoreEnabled.load() || !m_hashStore) {
                return std::nullopt;
            }

            return m_hashStore->LookupHashString(hashStr, type);
        }

        std::optional<DetectionResult> SignatureStore::LookupFileHash(
            const std::wstring& filePath,
            HashType type
        ) const noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER
            // ========================================================================

            // VALIDATION 1: Component check
            if (!m_hashStoreEnabled.load(std::memory_order_acquire) || !m_hashStore) {
                return std::nullopt;
            }

            // VALIDATION 2: Path validation
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Empty file path");
                return std::nullopt;
            }

            // VALIDATION 3: Path length check
            constexpr size_t MAX_PATH_LENGTH = 32767;
            if (filePath.length() > MAX_PATH_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Path too long");
                return std::nullopt;
            }

            // VALIDATION 4: Null character injection check
            if (filePath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Path contains null character");
                return std::nullopt;
            }

            // VALIDATION 5: Hash type validation (check if hash length is valid for the type)
            if (GetHashLengthForType(type) == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Invalid hash type");
                return std::nullopt;
            }

            try {
                ShadowStrike::SignatureStore::SignatureBuilder builder;

                // Compute file hash
                auto hash = builder.ComputeFileHash(filePath, type);
                if (!hash.has_value()) {
                    SS_LOG_ERROR(L"SignatureStore", L"Failed to compute file hash for: %s", filePath.c_str());
                    return std::nullopt;
                }

                return m_hashStore->LookupHash(*hash);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash exception: %S", e.what());
                return std::nullopt;
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash unknown exception");
                return std::nullopt;
            }
        }

        std::vector<DetectionResult> SignatureStore::ScanPatterns(
            std::span<const uint8_t> buffer,
            const QueryOptions& options
        ) const noexcept {
            if (!m_patternStoreEnabled.load() || !m_patternStore) {
                return {};
            }

            return m_patternStore->Scan(buffer, options);
        }

        std::vector<YaraMatch> SignatureStore::ScanYara(
            std::span<const uint8_t> buffer,
            const YaraScanOptions& options
        ) const noexcept {
            if (!m_yaraStoreEnabled.load() || !m_yaraStore) {
                return {};
            }

            return m_yaraStore->ScanBuffer(buffer, options);
        }
	}
}