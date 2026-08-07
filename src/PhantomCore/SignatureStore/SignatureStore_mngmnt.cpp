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
#include"../Utils/FileUtils.hpp"

namespace ShadowStrike {
	namespace SignatureStore {

        namespace {
            // ============================================================================
            // MANAGEMENT INPUT LIMITS
            // ============================================================================
            // Centralized so cross-cutting bounds stay consistent. All limits are
            // intentionally conservative; signature management is an administrative
            // operation, never a hot path.
            constexpr size_t MNG_MAX_NAME_LENGTH      = 1024;
            constexpr size_t MNG_MAX_DESC_LENGTH      = 4096;
            constexpr size_t MNG_MAX_TAGS             = 100;
            constexpr size_t MNG_MAX_TAG_LENGTH       = 256;
            constexpr size_t MNG_MAX_NAMESPACE_LENGTH = 256;
            constexpr size_t MNG_MAX_RULE_NAME_LENGTH = 256;
            constexpr size_t MNG_MAX_PATTERN_LENGTH   = 64ull * 1024;            // 64KB
            constexpr size_t MNG_MAX_RULE_LENGTH      = YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE;  // shared ceiling
            constexpr size_t MNG_MAX_PATH_LENGTH      = 32767;                   // \\?\ ext path
            constexpr uint32_t MNG_MIN_HASH_LEN       = 1;
            constexpr uint32_t MNG_MAX_HASH_LEN       = 64;

            [[nodiscard]] inline bool ContainsNullByte(const std::string& s) noexcept {
                return s.find('\0') != std::string::npos;
            }
            [[nodiscard]] inline bool ContainsNullByte(const std::wstring& s) noexcept {
                return s.find(L'\0') != std::wstring::npos;
            }

            // Validate every tag (count + per-tag length + null-byte injection).
            // Returns Success on accept, populated StoreError on reject.
            [[nodiscard]] StoreError ValidateTags(const std::vector<std::string>& tags) noexcept {
                if (tags.size() > MNG_MAX_TAGS) {
                    return StoreError{ SignatureStoreError::InvalidSignature, 0,
                        "Too many tags" };
                }
                for (const auto& tag : tags) {
                    if (tag.length() > MNG_MAX_TAG_LENGTH) {
                        return StoreError{ SignatureStoreError::InvalidSignature, 0,
                            "Tag too long" };
                    }
                    if (ContainsNullByte(tag)) {
                        return StoreError{ SignatureStoreError::InvalidSignature, 0,
                            "Tag contains null byte" };
                    }
                }
                return StoreError{ SignatureStoreError::Success };
            }

            // Validate an input path used by Import/Export. Performs empty, length,
            // and null-byte injection checks; canonicalization is delegated to the
            // underlying component (each subsystem owns its own I/O semantics).
            [[nodiscard]] StoreError ValidateIoPath(const std::wstring& path,
                const wchar_t* opName) noexcept {
                if (path.empty()) {
                    SS_LOG_ERROR(L"SignatureStore", L"%s: Empty path", opName);
                    return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty path" };
                }
                if (path.length() > MNG_MAX_PATH_LENGTH) {
                    SS_LOG_ERROR(L"SignatureStore", L"%s: Path too long (%zu)",
                        opName, path.length());
                    return StoreError{ SignatureStoreError::InvalidFormat, 0,
                        "Path exceeds maximum length" };
                }
                if (ContainsNullByte(path)) {
                    SS_LOG_ERROR(L"SignatureStore", L"%s: Path contains null character",
                        opName);
                    return StoreError{ SignatureStoreError::InvalidFormat, 0,
                        "Path contains null character" };
                }
                return StoreError{ SignatureStoreError::Success };
            }
        } // namespace

        // ============================================================================
        // SIGNATURE MANAGEMENT (Write Operations)
        // ============================================================================

        StoreError SignatureStore::AddHash(
            const HashValue& hash,
            const std::string& name,
            ThreatLevel threatLevel,
            const std::string& description,
            const std::vector<std::string>& tags
        ) noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - ADD HASH
            // ========================================================================

            // VALIDATION 1: Read-only check
            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"AddHash: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            // Acquire shared lock to prevent Close()/Shutdown() from destroying
            // component pointers between our null check and usage (TOCTOU fix).
            // Close() takes the same mutex exclusively; we either run fully before
            // it or fully after it, never overlapping.
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            // VALIDATION 2: Initialization state under lock (defense-in-depth).
            // Close() does NOT reset component unique_ptrs to null — it only calls
            // their Close() and clears m_initialized. We must therefore reject
            // post-Close operations explicitly, otherwise we would dispatch into a
            // closed sub-store.
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"AddHash: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Store not initialized" };
            }

            // VALIDATION 3: Component availability (under lock)
            if (!m_hashStoreEnabled.load(std::memory_order_acquire) || !m_hashStore) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: HashStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "HashStore not available" };
            }

            // VALIDATION 4: Hash validation
            if (hash.length < MNG_MIN_HASH_LEN || hash.length > MNG_MAX_HASH_LEN) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Invalid hash length (%u)", hash.length);
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash length" };
            }

            // Validate hash type using length check (invalid types return 0) and
            // cross-check that the declared length matches the canonical length
            // expected for the type — prevents persisting truncated/oversized hashes.
            const uint32_t expectedHashLen = GetHashLengthForType(hash.type);
            if (expectedHashLen == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Invalid hash type");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash type" };
            }
            if (hash.length != expectedHashLen) {
                SS_LOG_ERROR(L"SignatureStore",
                    L"AddHash: Hash length (%u) does not match type-expected length (%u)",
                    hash.length, expectedHashLen);
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Hash length mismatch for declared type" };
            }

            // VALIDATION 5: Name validation (length + null-byte injection)
            if (name.empty()) {
                SS_LOG_WARN(L"SignatureStore", L"AddHash: Empty signature name");
                // Allow but log warning
            }
            if (name.length() > MNG_MAX_NAME_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Name too long (%zu chars)", name.length());
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Name too long" };
            }
            if (ContainsNullByte(name)) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Name contains null byte");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Name contains null byte" };
            }

            // VALIDATION 6: Description length + null-byte
            if (description.length() > MNG_MAX_DESC_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Description too long (%zu)",
                    description.length());
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Description too long" };
            }
            if (ContainsNullByte(description)) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Description contains null byte");
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Description contains null byte" };
            }

            // VALIDATION 7: Tag fanout & content validation
            if (auto err = ValidateTags(tags); !err.IsSuccess()) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Tag validation failed: %S",
                    err.message.c_str());
                return err;
            }

            try {
                return m_hashStore->AddHash(hash, name, threatLevel, description, tags);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Exception: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown exception" };
            }
        }

        StoreError SignatureStore::AddPattern(
            const std::string& patternString,
            const std::string& name,
            ThreatLevel threatLevel,
            const std::string& description,
            const std::vector<std::string>& tags
        ) noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - ADD PATTERN
            // ========================================================================

            // VALIDATION 1: Read-only check
            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"AddPattern: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            // Acquire shared lock (TOCTOU fix: prevents Close() from destroying m_patternStore)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            // VALIDATION 2: Initialization state (defense-in-depth)
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"AddPattern: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Store not initialized" };
            }

            // VALIDATION 3: Component availability (under lock)
            if (!m_patternStoreEnabled.load(std::memory_order_acquire) || !m_patternStore) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: PatternStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "PatternStore not available" };
            }

            // VALIDATION 4: Pattern string validation
            if (patternString.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Empty pattern string");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Pattern string cannot be empty" };
            }

            // VALIDATION 5: Pattern length limit
            if (patternString.length() > MNG_MAX_PATTERN_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Pattern too long (%zu bytes)", patternString.length());
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Pattern too long" };
            }
            // NOTE: We deliberately do NOT reject null bytes in patternString. Hex
            // and binary YARA-style patterns legitimately contain 0x00 bytes; the
            // pattern compiler is responsible for syntactic validation.

            // VALIDATION 6: Name validation
            if (name.length() > MNG_MAX_NAME_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Name too long");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Name too long" };
            }
            if (ContainsNullByte(name)) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Name contains null byte");
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Name contains null byte" };
            }

            // VALIDATION 7: Description length + null-byte
            if (description.length() > MNG_MAX_DESC_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Description too long");
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Description too long" };
            }
            if (ContainsNullByte(description)) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Description contains null byte");
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Description contains null byte" };
            }

            // VALIDATION 8: Tag fanout & content validation
            if (auto err = ValidateTags(tags); !err.IsSuccess()) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Tag validation failed: %S",
                    err.message.c_str());
                return err;
            }

            try {
                return m_patternStore->AddPattern(patternString, name, threatLevel, description, tags);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Exception: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown exception" };
            }
        }

        StoreError SignatureStore::AddYaraRule(
            const std::string& ruleSource,
            const std::string& namespace_
        ) noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - ADD YARA RULE
            // ========================================================================

            // VALIDATION 1: Read-only check
            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"AddYaraRule: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            // Acquire shared lock (TOCTOU fix: prevents Close() from destroying m_yaraStore)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            // VALIDATION 2: Initialization state (defense-in-depth)
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"AddYaraRule: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Store not initialized" };
            }

            // VALIDATION 3: Component availability (under lock)
            if (!m_yaraStoreEnabled.load(std::memory_order_acquire) || !m_yaraStore) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: YaraStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "YaraStore not available" };
            }

            // VALIDATION 4: Rule source validation
            if (ruleSource.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: Empty rule source");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule source cannot be empty" };
            }

            // VALIDATION 5: Rule source length limit (DoS protection — YARA parser
            // has exponential edge cases on adversarial input)
            if (ruleSource.length() > MNG_MAX_RULE_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: Rule source too long (%zu bytes)", ruleSource.length());
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule source too long" };
            }
            // NOTE: We do NOT reject NUL bytes in ruleSource: YARA condition
            // strings can legitimately contain "\x00" sequences in hex contexts.
            // The YARA compiler enforces its own grammar.

            // VALIDATION 6: Namespace validation (length + null-byte injection —
            // namespaces are used as identifiers downstream)
            if (namespace_.length() > MNG_MAX_NAMESPACE_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: Namespace too long");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Namespace too long" };
            }
            if (ContainsNullByte(namespace_)) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: Namespace contains null byte");
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Namespace contains null byte" };
            }

            try {
                return m_yaraStore->AddRulesFromSource(ruleSource, namespace_);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Exception: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown exception" };
            }
        }

        StoreError SignatureStore::RemoveHash(const HashValue& hash) noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - REMOVE HASH
            // ========================================================================

            // VALIDATION 1: Read-only check
            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"RemoveHash: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Cannot remove - read-only mode" };
            }

            // Acquire shared lock (TOCTOU fix)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            // VALIDATION 2: Initialization state
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"RemoveHash: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Store not initialized" };
            }

            // VALIDATION 3: Component availability (under lock)
            if (!m_hashStore) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash: HashStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "HashStore not available" };
            }

            // VALIDATION 4: Hash validation
            if (hash.length < MNG_MIN_HASH_LEN || hash.length > MNG_MAX_HASH_LEN) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash: Invalid hash length (%u)", hash.length);
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash length" };
            }

            // Validate hash type and cross-check declared length against canonical
            const uint32_t expectedHashLen = GetHashLengthForType(hash.type);
            if (expectedHashLen == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash: Invalid hash type");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash type" };
            }
            if (hash.length != expectedHashLen) {
                SS_LOG_ERROR(L"SignatureStore",
                    L"RemoveHash: Hash length (%u) does not match type-expected length (%u)",
                    hash.length, expectedHashLen);
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Hash length mismatch for declared type" };
            }

            try {
                return m_hashStore->RemoveHash(hash);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Exception: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown exception" };
            }
        }

        StoreError SignatureStore::RemovePattern(uint64_t signatureId) noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - REMOVE PATTERN
            // ========================================================================

            // VALIDATION 1: Read-only check
            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"RemovePattern: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Cannot remove - read-only mode" };
            }

            // Acquire shared lock (TOCTOU fix)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            // VALIDATION 2: Initialization state
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"RemovePattern: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Store not initialized" };
            }

            // VALIDATION 3: Component availability (under lock)
            if (!m_patternStore) {
                SS_LOG_ERROR(L"SignatureStore", L"RemovePattern: PatternStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "PatternStore not available" };
            }

            // VALIDATION 4: Signature ID note
            // NOTE: Pattern ID 0 is valid in PatternStore (first pattern can have ID 0)
            // Only log warning for debugging, allow the operation
            if (signatureId == 0) {
                SS_LOG_DEBUG(L"SignatureStore", L"RemovePattern: Removing signature ID 0 (valid for first pattern)");
            }

            try {
                return m_patternStore->RemovePattern(signatureId);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"RemovePattern exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Exception: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"RemovePattern unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown exception" };
            }
        }

        StoreError SignatureStore::RemoveYaraRule(const std::string& ruleName) noexcept {
            // ========================================================================
            // TITANIUM VALIDATION LAYER - REMOVE YARA RULE
            // ========================================================================

            // VALIDATION 1: Read-only check
            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"RemoveYaraRule: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Cannot remove - read-only mode" };
            }

            // Acquire shared lock (TOCTOU fix)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            // VALIDATION 2: Initialization state
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"RemoveYaraRule: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Store not initialized" };
            }

            // VALIDATION 3: Component availability (under lock)
            if (!m_yaraStore) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule: YaraStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "YaraStore not available" };
            }

            // VALIDATION 4: Rule name validation
            if (ruleName.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule: Empty rule name");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule name cannot be empty" };
            }

            // VALIDATION 5: Rule name length + null-byte
            if (ruleName.length() > MNG_MAX_RULE_NAME_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule: Rule name too long");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule name too long" };
            }
            if (ContainsNullByte(ruleName)) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule: Rule name contains null byte");
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Rule name contains null byte" };
            }

            try {
                return m_yaraStore->RemoveRule(ruleName, "default");
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Exception: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown exception" };
            }
        }

        // ============================================================================
        // BULK OPERATIONS
        // ============================================================================

        StoreError SignatureStore::ImportHashes(
            const std::wstring& filePath,
            std::function<void(size_t, size_t)> progressCallback
        ) noexcept {
            SS_LOG_INFO(L"SignatureStore", L"ImportHashes: %s", filePath.c_str());

            // Read-only check (Import mutates the store)
            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ImportHashes: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            // Path validation (empty, length cap, null-byte injection)
            if (auto err = ValidateIoPath(filePath, L"ImportHashes"); !err.IsSuccess()) {
                return err;
            }

            // Acquire shared lock (TOCTOU fix: prevents Close() from destroying m_hashStore)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ImportHashes: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Store not initialized" };
            }

            if (!m_hashStore) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "HashStore not available" };
            }

            // Exception-safe import; the user-supplied progress callback is forwarded
            // unchanged (the underlying HashStore wraps callback invocations).
            try {
                return m_hashStore->ImportFromFile(filePath, progressCallback);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportHashes exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Import error: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportHashes unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown import error" };
            }
        }

        StoreError SignatureStore::ImportPatterns(const std::wstring& filePath) noexcept {
            SS_LOG_INFO(L"SignatureStore", L"ImportPatterns: %s", filePath.c_str());

            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ImportPatterns: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            if (auto err = ValidateIoPath(filePath, L"ImportPatterns"); !err.IsSuccess()) {
                return err;
            }

            // Acquire shared lock (TOCTOU fix)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ImportPatterns: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Store not initialized" };
            }

            if (!m_patternStore) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "PatternStore not available" };
            }

            try {
                return m_patternStore->ImportFromYaraFile(filePath);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportPatterns exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Import error: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportPatterns unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown import error" };
            }
        }

        StoreError SignatureStore::ImportYaraRules(
            const std::wstring& filePath,
            const std::string& namespace_
        ) noexcept {
            SS_LOG_INFO(L"SignatureStore", L"ImportYaraRules: %s", filePath.c_str());

            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ImportYaraRules: Store is read-only");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            if (auto err = ValidateIoPath(filePath, L"ImportYaraRules"); !err.IsSuccess()) {
                return err;
            }

            // Namespace can be empty but must not contain null bytes or be oversize
            if (namespace_.length() > MNG_MAX_NAMESPACE_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportYaraRules: Namespace too long");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Namespace too long" };
            }
            if (ContainsNullByte(namespace_)) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportYaraRules: Invalid namespace");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid namespace" };
            }

            // Acquire shared lock (TOCTOU fix)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ImportYaraRules: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Store not initialized" };
            }

            if (!m_yaraStore) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "YaraStore not available" };
            }

            try {
                return m_yaraStore->AddRulesFromFile(filePath, namespace_);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportYaraRules exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Import error: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportYaraRules unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown import error" };
            }
        }

        StoreError SignatureStore::ExportHashes(
            const std::wstring& outputPath,
            HashType typeFilter
        ) const noexcept {
            SS_LOG_INFO(L"SignatureStore", L"ExportHashes: %s", outputPath.c_str());

            if (auto err = ValidateIoPath(outputPath, L"ExportHashes"); !err.IsSuccess()) {
                return err;
            }

            // Reject invalid hash type filters explicitly; underlying store would
            // otherwise return an empty file silently.
            if (GetHashLengthForType(typeFilter) == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportHashes: Invalid hash type filter");
                return StoreError{ SignatureStoreError::InvalidSignature, 0,
                    "Invalid hash type filter" };
            }

            // Acquire shared lock (TOCTOU fix: prevents Close() during export)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ExportHashes: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Store not initialized" };
            }

            if (!m_hashStore) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "HashStore not available" };
            }

            try {
                return m_hashStore->ExportToFile(outputPath, typeFilter);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportHashes exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Export error: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportHashes unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown export error" };
            }
        }

        StoreError SignatureStore::ExportPatterns(const std::wstring& outputPath) const noexcept {
            SS_LOG_INFO(L"SignatureStore", L"ExportPatterns: %s", outputPath.c_str());

            if (auto err = ValidateIoPath(outputPath, L"ExportPatterns"); !err.IsSuccess()) {
                return err;
            }

            // Acquire shared lock (TOCTOU fix: prevents Close() during export)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ExportPatterns: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Store not initialized" };
            }

            if (!m_patternStoreEnabled.load(std::memory_order_acquire) || !m_patternStore) {
                SS_LOG_ERROR(L"SignatureStore", L"PatternStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "PatternStore not available" };
            }

            try {
                // Serialize patterns to JSON and write atomically. The atomic writer
                // routes through Utils::FileUtils which performs temp-file + rename,
                // protecting against partial writes on power loss / abort.
                std::string jsonContent = m_patternStore->ExportToJson();
                if (jsonContent.empty()) {
                    SS_LOG_ERROR(L"SignatureStore", L"ExportPatterns: Failed to export JSON");
                    return StoreError{ SignatureStoreError::Unknown, 0, "JSON export failed" };
                }

                ShadowStrike::Utils::FileUtils::Error fileErr{};
                if (!ShadowStrike::Utils::FileUtils::WriteAllTextUtf8Atomic(outputPath, jsonContent, &fileErr)) {
                    SS_LOG_ERROR(L"SignatureStore",
                        L"ExportPatterns: Failed to write file (win32: %u)", fileErr.win32);
                    return StoreError{
                        SignatureStoreError::InvalidFormat,
                        fileErr.win32,
                        "Failed to write JSON file"
                    };
                }

                SS_LOG_INFO(L"SignatureStore", L"ExportPatterns: Successfully exported to %s",
                    outputPath.c_str());
                return StoreError{ SignatureStoreError::Success };
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportPatterns exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Export error: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportPatterns unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown export error" };
            }
        }

        StoreError SignatureStore::ExportYaraRules(const std::wstring& outputPath) const noexcept {
            SS_LOG_INFO(L"SignatureStore", L"ExportYaraRules: %s", outputPath.c_str());

            if (auto err = ValidateIoPath(outputPath, L"ExportYaraRules"); !err.IsSuccess()) {
                return err;
            }

            // Acquire shared lock (TOCTOU fix: prevents Close() during export)
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureStore", L"ExportYaraRules: Store not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Store not initialized" };
            }

            if (!m_yaraStore) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "YaraStore not available" };
            }

            try {
                return m_yaraStore->ExportCompiled(outputPath);
            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportYaraRules exception: %S", e.what());
                return StoreError{ SignatureStoreError::Unknown, 0, std::string("Export error: ") + e.what() };
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportYaraRules unknown exception");
                return StoreError{ SignatureStoreError::Unknown, 0, "Unknown export error" };
            }
        }
	}
}