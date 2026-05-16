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
#include"pch.h"
#include"SignatureStore.hpp"

namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // SPECIFIC QUERY METHODS
        // ============================================================================
        //
        // Public query entry points. All methods are noexcept and tolerate every
        // form of caller misuse: closed store, mid-shutdown race, malformed input,
        // adversarial size. A failed query returns the "no match" sentinel
        // (std::nullopt / empty vector); errors are logged but never propagated as
        // exceptions because callers run inside scan threads and inspection callbacks.
        //
        // Lock discipline: each query takes m_globalLock in shared mode for the
        // duration of the underlying component call. Close() takes the same lock
        // exclusively, so either Close() finishes first (we see m_initialized=false
        // and bail) or the query finishes first (Close() blocks until we release).
        // We never call into a component after m_initialized has been cleared.
        // ============================================================================

        namespace {
            // Hash-string queries: an explicit cap that is more than enough for any
            // legal hex representation of supported algorithms (SHA-512 = 128 chars)
            // while preventing megabyte-sized inputs being parsed by the underlying
            // hex decoder.
            constexpr size_t QRY_MAX_HASH_STRING_LENGTH = 256;

            // Buffer DoS cap mirrors ScanBuffer / TitaniumLimits::MAX_SCAN_BUFFER_SIZE.
            // Pattern and YARA scanners both walk the buffer linearly; an attacker
            // could otherwise pin worker threads on 4GB views.
            constexpr size_t QRY_MAX_SCAN_BUFFER = TitaniumLimits::MAX_SCAN_BUFFER_SIZE;

            // Hex-string validator. Accepts only [0-9a-fA-F]; rejects null bytes,
            // whitespace, and any out-of-band character that downstream parsers
            // could interpret as a delimiter.
            [[nodiscard]] inline bool IsValidHexString(const std::string& s) noexcept {
                if (s.empty()) {
                    return false;
                }
                for (char c : s) {
                    const bool ok =
                        (c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
                    if (!ok) {
                        return false;
                    }
                }
                return true;
            }
        } // namespace

        std::optional<DetectionResult> SignatureStore::LookupHash(const HashValue& hash) const noexcept {
            // Validate hash before acquiring the lock — cheap rejects stay lock-free.
            const uint32_t expectedLen = GetHashLengthForType(hash.type);
            if (expectedLen == 0) {
                SS_LOG_DEBUG(L"SignatureStore", L"LookupHash: invalid hash type");
                return std::nullopt;
            }
            if (hash.length == 0 || hash.length != expectedLen) {
                SS_LOG_DEBUG(L"SignatureStore",
                    L"LookupHash: hash length (%u) does not match type-expected (%u)",
                    hash.length, expectedLen);
                return std::nullopt;
            }

            std::shared_lock<std::shared_mutex> lock(m_globalLock);
            if (!m_initialized.load(std::memory_order_acquire)) {
                return std::nullopt;
            }
            if (!m_hashStoreEnabled.load(std::memory_order_acquire) || !m_hashStore) {
                return std::nullopt;
            }

            try {
                return m_hashStore->LookupHash(hash);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupHash exception: %S", e.what());
                return std::nullopt;
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupHash unknown exception");
                return std::nullopt;
            }
        }

        std::optional<DetectionResult> SignatureStore::LookupHashString(
            const std::string& hashStr,
            HashType type
        ) const noexcept {
            // Validate input format strictly before passing to the parser. The
            // downstream LookupHashString eventually decodes hex; feeding it
            // unbounded or non-hex content would either waste cycles or, in the
            // worst case, allow injection of delimiter characters into logs.
            if (hashStr.empty()) {
                return std::nullopt;
            }
            if (hashStr.length() > QRY_MAX_HASH_STRING_LENGTH) {
                SS_LOG_DEBUG(L"SignatureStore",
                    L"LookupHashString: input too long (%zu chars)", hashStr.length());
                return std::nullopt;
            }
            if (!IsValidHexString(hashStr)) {
                SS_LOG_DEBUG(L"SignatureStore",
                    L"LookupHashString: non-hex / null-byte content rejected");
                return std::nullopt;
            }

            // Cross-check length against the declared algorithm: a SHA-256 string
            // must be exactly 64 hex characters, etc. This catches mislabelled or
            // truncated inputs that would otherwise produce a phantom miss.
            const uint32_t expectedLen = GetHashLengthForType(type);
            if (expectedLen == 0) {
                return std::nullopt;
            }
            if (hashStr.length() != static_cast<size_t>(expectedLen) * 2u) {
                SS_LOG_DEBUG(L"SignatureStore",
                    L"LookupHashString: string length (%zu) does not match type (%u bytes => %u hex chars)",
                    hashStr.length(), expectedLen, expectedLen * 2u);
                return std::nullopt;
            }

            std::shared_lock<std::shared_mutex> lock(m_globalLock);
            if (!m_initialized.load(std::memory_order_acquire)) {
                return std::nullopt;
            }
            if (!m_hashStoreEnabled.load(std::memory_order_acquire) || !m_hashStore) {
                return std::nullopt;
            }

            try {
                return m_hashStore->LookupHashString(hashStr, type);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupHashString exception: %S", e.what());
                return std::nullopt;
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupHashString unknown exception");
                return std::nullopt;
            }
        }

        std::optional<DetectionResult> SignatureStore::LookupFileHash(
            const std::wstring& filePath,
            HashType type
        ) const noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER
            // ========================================================================

            // VALIDATION 1: Path validation (no lock needed)
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Empty file path");
                return std::nullopt;
            }

            // VALIDATION 2: Path length check
            constexpr size_t MAX_PATH_LENGTH = 32767;
            if (filePath.length() > MAX_PATH_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Path too long");
                return std::nullopt;
            }

            // VALIDATION 3: Null character injection check
            if (filePath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Path contains null character");
                return std::nullopt;
            }

            // VALIDATION 4: Hash type validation
            if (GetHashLengthForType(type) == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"LookupFileHash: Invalid hash type");
                return std::nullopt;
            }

            try {
                ShadowStrike::SignatureStore::SignatureBuilder builder;

                // Compute file hash (I/O-bound, no lock needed). The builder is
                // responsible for canonicalization, size caps, and mmap TOCTOU
                // mitigations; we do not duplicate them here.
                auto hash = builder.ComputeFileHash(filePath, type);
                if (!hash.has_value()) {
                    SS_LOG_ERROR(L"SignatureStore", L"Failed to compute file hash for: %s", filePath.c_str());
                    return std::nullopt;
                }

                // Lock only for component access
                std::shared_lock<std::shared_mutex> lock(m_globalLock);
                if (!m_initialized.load(std::memory_order_acquire)) {
                    return std::nullopt;
                }
                if (!m_hashStoreEnabled.load(std::memory_order_acquire) || !m_hashStore) {
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
            // Empty buffer => no matches, no work.
            if (buffer.empty()) {
                return {};
            }
            // DoS cap (mirrors TitaniumLimits::MAX_SCAN_BUFFER_SIZE)
            if (buffer.size() > QRY_MAX_SCAN_BUFFER) {
                SS_LOG_WARN(L"SignatureStore",
                    L"ScanPatterns: buffer too large (%zu bytes), refusing scan", buffer.size());
                return {};
            }
            // Defensive: buffer.size() > 0 with buffer.data() == nullptr is
            // technically undefined; guard explicitly because std::span will
            // construct in that state from a malformed caller.
            if (buffer.data() == nullptr) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanPatterns: null buffer with non-zero size");
                return {};
            }

            std::shared_lock<std::shared_mutex> lock(m_globalLock);
            if (!m_initialized.load(std::memory_order_acquire)) {
                return {};
            }
            if (!m_patternStoreEnabled.load(std::memory_order_acquire) || !m_patternStore) {
                return {};
            }

            try {
                return m_patternStore->Scan(buffer, options);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanPatterns exception: %S", e.what());
                return {};
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanPatterns unknown exception");
                return {};
            }
        }

        std::vector<YaraMatch> SignatureStore::ScanYara(
            std::span<const uint8_t> buffer,
            const YaraScanOptions& options
        ) const noexcept {
            if (buffer.empty()) {
                return {};
            }
            if (buffer.size() > QRY_MAX_SCAN_BUFFER) {
                SS_LOG_WARN(L"SignatureStore",
                    L"ScanYara: buffer too large (%zu bytes), refusing scan", buffer.size());
                return {};
            }
            if (buffer.data() == nullptr) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanYara: null buffer with non-zero size");
                return {};
            }

            std::shared_lock<std::shared_mutex> lock(m_globalLock);
            if (!m_initialized.load(std::memory_order_acquire)) {
                return {};
            }
            if (!m_yaraStoreEnabled.load(std::memory_order_acquire) || !m_yaraStore) {
                return {};
            }

            try {
                return m_yaraStore->ScanBuffer(buffer, options);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanYara exception: %S", e.what());
                return {};
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ScanYara unknown exception");
                return {};
            }
        }
	}
}