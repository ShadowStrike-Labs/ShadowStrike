// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include"SignatureStore.hpp"
#include"../../src/Utils/FileUtils.hpp"

namespace ShadowStrike {
	namespace SignatureStore {

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

            // VALIDATION 2: Component availability
            if (!m_hashStoreEnabled.load(std::memory_order_acquire) || !m_hashStore) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: HashStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "HashStore not available" };
            }

            // VALIDATION 3: Hash validation
            if (hash.length == 0 || hash.length > 64) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Invalid hash length (%u)", hash.length);
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash length" };
            }

            // Validate hash type using length check (invalid types return 0)
            if (GetHashLengthForType(hash.type) == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Invalid hash type");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash type" };
            }

            // VALIDATION 4: Name validation
            if (name.empty()) {
                SS_LOG_WARN(L"SignatureStore", L"AddHash: Empty signature name");
                // Allow but log warning
            }

            // VALIDATION 5: Name length limit
            constexpr size_t MAX_NAME_LENGTH = 1024;
            if (name.length() > MAX_NAME_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddHash: Name too long (%zu chars)", name.length());
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Name too long" };
            }

            // VALIDATION 6: Description length limit
            constexpr size_t MAX_DESC_LENGTH = 4096;
            if (description.length() > MAX_DESC_LENGTH) {
                SS_LOG_WARN(L"SignatureStore", L"AddHash: Description too long, truncating");
                // Will be truncated by underlying store
            }

            // VALIDATION 7: Tags count limit
            constexpr size_t MAX_TAGS = 100;
            if (tags.size() > MAX_TAGS) {
                SS_LOG_WARN(L"SignatureStore", L"AddHash: Too many tags (%zu), only first %zu will be used",
                    tags.size(), MAX_TAGS);
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

            // VALIDATION 2: Component availability
            if (!m_patternStoreEnabled.load(std::memory_order_acquire) || !m_patternStore) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: PatternStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "PatternStore not available" };
            }

            // VALIDATION 3: Pattern string validation
            if (patternString.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Empty pattern string");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Pattern string cannot be empty" };
            }

            // VALIDATION 4: Pattern length limit
            constexpr size_t MAX_PATTERN_LENGTH = 65536;  // 64KB max pattern
            if (patternString.length() > MAX_PATTERN_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Pattern too long (%zu bytes)", patternString.length());
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Pattern too long" };
            }

            // VALIDATION 5: Name validation
            constexpr size_t MAX_NAME_LENGTH = 1024;
            if (name.length() > MAX_NAME_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddPattern: Name too long");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Name too long" };
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

            // VALIDATION 2: Component availability
            if (!m_yaraStoreEnabled.load(std::memory_order_acquire) || !m_yaraStore) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: YaraStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "YaraStore not available" };
            }

            // VALIDATION 3: Rule source validation
            if (ruleSource.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: Empty rule source");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule source cannot be empty" };
            }

            // VALIDATION 4: Rule source length limit
            constexpr size_t MAX_RULE_LENGTH = 10 * 1024 * 1024;  // 10MB max rule
            if (ruleSource.length() > MAX_RULE_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: Rule source too long (%zu bytes)", ruleSource.length());
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule source too long" };
            }

            // VALIDATION 5: Namespace validation
            constexpr size_t MAX_NAMESPACE_LENGTH = 256;
            if (namespace_.length() > MAX_NAMESPACE_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"AddYaraRule: Namespace too long");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Namespace too long" };
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

            // VALIDATION 2: Component availability
            if (!m_hashStore) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash: HashStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "HashStore not available" };
            }

            // VALIDATION 3: Hash validation
            if (hash.length == 0 || hash.length > 64) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash: Invalid hash length (%u)", hash.length);
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash length" };
            }

            // Validate hash type using length check (invalid types return 0)
            if (GetHashLengthForType(hash.type) == 0) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveHash: Invalid hash type");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid hash type" };
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

            // VALIDATION 2: Component availability
            if (!m_patternStore) {
                SS_LOG_ERROR(L"SignatureStore", L"RemovePattern: PatternStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "PatternStore not available" };
            }

            // VALIDATION 3: Signature ID validation (0 is typically invalid)
            if (signatureId == 0) {
                SS_LOG_WARN(L"SignatureStore", L"RemovePattern: Removing signature ID 0 (may be invalid)");
                // Allow but log warning
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

            // VALIDATION 2: Component availability
            if (!m_yaraStore) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule: YaraStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "YaraStore not available" };
            }

            // VALIDATION 3: Rule name validation
            if (ruleName.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule: Empty rule name");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule name cannot be empty" };
            }

            // VALIDATION 4: Rule name length limit
            constexpr size_t MAX_RULE_NAME_LENGTH = 256;
            if (ruleName.length() > MAX_RULE_NAME_LENGTH) {
                SS_LOG_ERROR(L"SignatureStore", L"RemoveYaraRule: Rule name too long");
                return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule name too long" };
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

            // TITANIUM: Path validation
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportHashes: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty file path" };
            }

            // Check for path traversal attacks (null bytes, etc.)
            if (filePath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportHashes: Invalid path (contains null)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid path" };
            }

            if (!m_hashStore) {
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "HashStore not available" };
            }

            // TITANIUM: Exception-safe import with callback protection
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

            // TITANIUM: Path validation
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportPatterns: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty file path" };
            }

            if (filePath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportPatterns: Invalid path (contains null)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid path" };
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

            // TITANIUM: Path and namespace validation
            if (filePath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportYaraRules: Empty file path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty file path" };
            }

            if (filePath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportYaraRules: Invalid path (contains null)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid path" };
            }

            // Namespace can be empty but should not contain null bytes
            if (namespace_.find('\0') != std::string::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ImportYaraRules: Invalid namespace");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid namespace" };
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

            // TITANIUM: Output path validation
            if (outputPath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportHashes: Empty output path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty output path" };
            }

            if (outputPath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportHashes: Invalid path (contains null)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid path" };
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

            // TITANIUM: Output path validation
            if (outputPath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportPatterns: Empty output path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty output path" };
            }

            if (outputPath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportPatterns: Invalid path (contains null)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid path" };
            }

            if (!m_patternStoreEnabled.load() || !m_patternStore) {
                SS_LOG_ERROR(L"SignatureStore", L"PatternStore not available");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "PatternStore not available" };
            }

            try {
                // Get JSON from pattern store
                std::string jsonContent = m_patternStore->ExportToJson();
                if (jsonContent.empty()) {
                    SS_LOG_ERROR(L"SignatureStore", L"ExportPatterns: Failed to export JSON");
                    return StoreError{ SignatureStoreError::Unknown, 0, "JSON export failed" };
                }

                // Write JSON to file atomically
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

            // TITANIUM: Output path validation
            if (outputPath.empty()) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportYaraRules: Empty output path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty output path" };
            }

            if (outputPath.find(L'\0') != std::wstring::npos) {
                SS_LOG_ERROR(L"SignatureStore", L"ExportYaraRules: Invalid path (contains null)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid path" };
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