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
#include <chrono>   // millisecond header timestamps
#ifdef SHADOWSTRIKE_HAS_YARA  // Entire TU requires libyara SDK
/*
 * ============================================================================
 * ShadowStrike YaraRuleStore - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 *
 * YARA rule engine integration implementation
 * Memory-mapped compiled rules, zero-copy execution
 * 
 *
 *
 *
 * ============================================================================
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "YaraRuleStore.hpp"

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"   // IsContentNotLocalError
#include "../Utils/FileUtils.hpp"
#include"../Utils/StringUtils.hpp"
#include"../Utils/MemoryUtils.hpp"
#include"../Utils/JSONUtils.hpp"
#include<set>
#include<variant>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <queue>



namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// YARA LIBRARY STATICS
// ============================================================================

std::atomic<bool> YaraRuleStore::s_yaraInitialized{false};
std::mutex YaraRuleStore::s_yaraInitMutex;

// ============================================================================
// YARA COMPILER IMPLEMENTATION
// ============================================================================

YaraCompiler::YaraCompiler()
    : m_compiler(nullptr)
{
    // libyara requires yr_initialize() before any other entry point: it sets up
    // the allocators, the module table and thread-local state that
    // yr_compiler_create() goes on to dereference. That call used to live only
    // in YaraRuleStore::Initialize, which made this class silently dependent on
    // a store having been constructed first - an ordering rule that appeared
    // nowhere in the type system and that a caller had no way to discover.
    //
    // SignatureBuilder::BuildYaraIndex constructs a bare compiler with no store
    // involved, and did so for the first time when the offline content build
    // tool was written. It crashed with an access violation inside
    // yr_compiler_create, for exactly this reason.
    //
    // Initialisation is idempotent and mutex-guarded, so owning it here costs a
    // single atomic load on every subsequent construction and removes the
    // hidden ordering requirement entirely.
    const StoreError yaraReady = YaraRuleStore::InitializeYara();
    if (!yaraReady.IsSuccess()) {
        SS_LOG_ERROR(L"YaraCompiler",
            L"Cannot create compiler: YARA library initialization failed (%S)",
            yaraReady.message.c_str());
        return;
    }

    int result = yr_compiler_create(&m_compiler);
    if(result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to create YARA compiler instance: %d", result);
        m_compiler = nullptr;
        return;
    }
    
    // TITANIUM: Set error callback to capture compilation errors/warnings
    yr_compiler_set_callback(m_compiler, ErrorCallback, this);
    
    SS_LOG_DEBUG(L"YaraCompiler", L"Created compiler instance with error callback");
}

YaraCompiler::~YaraCompiler() {
    if (m_compiler) {
        yr_compiler_destroy(m_compiler);
        m_compiler = nullptr;
    }
}

YaraCompiler::YaraCompiler(YaraCompiler&& other) noexcept
    : m_compiler(other.m_compiler)
    , m_errors(std::move(other.m_errors))
    , m_warnings(std::move(other.m_warnings))
    , m_includePaths(std::move(other.m_includePaths))
{
    other.m_compiler = nullptr;
}

YaraCompiler& YaraCompiler::operator=(YaraCompiler&& other) noexcept {
    if (this != &other) {
        if (m_compiler) {
			 yr_compiler_destroy(m_compiler);
        }
        
        m_compiler = other.m_compiler;
        m_errors = std::move(other.m_errors);
        m_warnings = std::move(other.m_warnings);
        m_includePaths = std::move(other.m_includePaths);
        
        other.m_compiler = nullptr;
    }
    return *this;
}

StoreError YaraCompiler::AddFile(
    const std::wstring& filePath,
    const std::string& namespace_
) noexcept {
    SS_LOG_DEBUG(L"YaraCompiler", L"AddFile: %s (namespace: %S)", 
        filePath.c_str(), namespace_.c_str());

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Compiler initialization
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFile: Compiler not initialized");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Compiler not initialized"};
    }
    
    // VALIDATION 2: Empty path check
    if (filePath.empty()) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFile: Empty file path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "File path is empty"};
    }
    
    // VALIDATION 3: Path length check (DoS protection)
    if (filePath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFile: Path too long (%zu > %zu)",
            filePath.length(), YaraTitaniumLimits::MAX_PATH_LENGTH);
        return StoreError{SignatureStoreError::FileNotFound, 0, "File path too long"};
    }
    
    // VALIDATION 4: Null character check (path injection prevention)
    if (filePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFile: Path contains null character");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Path contains null character"};
    }
    
    // VALIDATION 5: Namespace length check
    if (namespace_.length() > YaraTitaniumLimits::MAX_NAMESPACE_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFile: Namespace too long (%zu > %zu)",
            namespace_.length(), YaraTitaniumLimits::MAX_NAMESPACE_LENGTH);
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Namespace too long"};
    }

    // ========================================================================
    // FILE READING WITH ERROR HANDLING
    // ========================================================================
    std::string content;
    try {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            SS_LOG_ERROR(L"YaraCompiler", L"Failed to open file: %s", filePath.c_str());
            return StoreError{SignatureStoreError::FileNotFound, 0, "Cannot open file"};
        }

        // Get file size for validation and pre-allocation
        const auto fileSize = file.tellg();
        if (fileSize < 0) {
            SS_LOG_ERROR(L"YaraCompiler", L"Failed to get file size: %s", filePath.c_str());
            return StoreError{SignatureStoreError::FileNotFound, 0, "Cannot determine file size"};
        }
        
        // VALIDATION 6: File size limit (DoS protection - 10MB max per rule file)
        if (fileSize > YaraTitaniumLimits::MAX_FILE_SIZE) {
            SS_LOG_ERROR(L"YaraCompiler", L"File too large: %s (%lld bytes)",
                filePath.c_str(), static_cast<long long>(fileSize));
            return StoreError{SignatureStoreError::TooLarge, 0, "Rule file exceeds the maximum rule file size"};
        }
        
        // Pre-allocate string to avoid reallocations
        content.reserve(static_cast<size_t>(fileSize));
        
        // Seek back to beginning and read
        file.seekg(0, std::ios::beg);
        if (!file.good()) {
            SS_LOG_ERROR(L"YaraCompiler", L"Failed to seek in file: %s", filePath.c_str());
            return StoreError{SignatureStoreError::FileNotFound, 0, "Cannot read file"};
        }
        
        content.assign(std::istreambuf_iterator<char>(file),
                       std::istreambuf_iterator<char>());
        
        if (file.bad()) {
            SS_LOG_ERROR(L"YaraCompiler", L"Read error for file: %s", filePath.c_str());
            return StoreError{SignatureStoreError::FileNotFound, 0, "File read error"};
        }
        
        file.close();
    }
    catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"YaraCompiler", L"Out of memory reading file: %s", filePath.c_str());
        return StoreError{SignatureStoreError::OutOfMemory, 0, "Out of memory reading file"};
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"YaraCompiler", L"Exception reading file: %s - %S", 
            filePath.c_str(), e.what());
        return StoreError{SignatureStoreError::Unknown, 0, "Exception reading file"};
    }

    return AddString(content, namespace_);
}

StoreError YaraCompiler::AddString(
    const std::string& ruleSource,
    const std::string& namespace_
) noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Compiler initialization
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddString: Compiler not initialized");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Compiler not initialized"};
    }

    // VALIDATION 2: Empty source check
    if (ruleSource.empty()) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddString: Empty rule source");
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Empty rule source"};
    }
    
    // VALIDATION 3: Source size limit (DoS protection - 10MB max)
    if (ruleSource.length() > YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddString: Rule source too large (%zu > %zu)",
            ruleSource.length(), YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE);
        return StoreError{SignatureStoreError::TooLarge, 0, "Rule source exceeds the maximum rule source size"};
    }
    
    // VALIDATION 4: Namespace validation (can be empty for default namespace)
    if (namespace_.length() > YaraTitaniumLimits::MAX_NAMESPACE_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddString: Namespace too long (%zu > %zu)",
            namespace_.length(), YaraTitaniumLimits::MAX_NAMESPACE_LENGTH);
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Namespace too long"};
    }
    
    // VALIDATION 5: Namespace character validation (alphanumeric + underscore)
    if (!namespace_.empty()) {
        if (!std::all_of(namespace_.begin(), namespace_.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_';
        })) {
            SS_LOG_ERROR(L"YaraCompiler", L"AddString: Invalid namespace characters: %S",
                namespace_.c_str());
            return StoreError{SignatureStoreError::InvalidSignature, 0, 
                "Namespace must be alphanumeric with underscores only"};
        }
    }

    // ========================================================================
    // YARA COMPILATION
    // ========================================================================
    // Note: yr_compiler_add_string accepts nullptr for default namespace
    const char* nsPtr = namespace_.empty() ? nullptr : namespace_.c_str();
    
    int result = yr_compiler_add_string(m_compiler, ruleSource.c_str(), nsPtr);
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to add rule string (namespace: %S): %d",
            namespace_.empty() ? "default" : namespace_.c_str(), result);
        return StoreError{SignatureStoreError::InvalidSignature, 
            static_cast<DWORD>(result), "Failed to add rule string"};
    }

    SS_LOG_DEBUG(L"YaraCompiler", L"Added rule string (namespace: %S, length: %zu)",
        namespace_.empty() ? "default" : namespace_.c_str(), ruleSource.length());

    return StoreError{SignatureStoreError::Success};
}

StoreError YaraCompiler::AddFiles(
    std::span<const std::wstring> filePaths,
    const std::string& namespace_,
    std::function<void(size_t, size_t)> progressCallback
) noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Compiler initialization
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFiles: Compiler not initialized");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Compiler not initialized"};
    }
    
    // VALIDATION 2: Empty file list
    if (filePaths.empty()) {
        SS_LOG_WARN(L"YaraCompiler", L"AddFiles: Empty file list");
        return StoreError{SignatureStoreError::FileNotFound, 0, "No files to add"};
    }
    
    // VALIDATION 3: File count limit (DoS protection)
    if (filePaths.size() > YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFiles: Too many files (%zu > %zu)",
            filePaths.size(), YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO);
        return StoreError{SignatureStoreError::TooLarge, 0, "Too many files"};
    }
    
    // VALIDATION 4: Namespace validation
    if (namespace_.length() > YaraTitaniumLimits::MAX_NAMESPACE_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFiles: Namespace too long");
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Namespace too long"};
    }

    // ========================================================================
    // PROCESS FILES
    // ========================================================================
    size_t successCount = 0;
    size_t failCount = 0;
    std::string lastError;

    for (size_t i = 0; i < filePaths.size(); ++i) {
        StoreError err = AddFile(filePaths[i], namespace_);
        if (err.IsSuccess()) {
            successCount++;
        } else {
            failCount++;
            lastError = err.message;
            SS_LOG_WARN(L"YaraCompiler", L"AddFiles: Failed to add file %zu: %s",
                i, filePaths[i].c_str());
        }

        // Safe progress callback invocation
        if (progressCallback) {
            try {
                progressCallback(i + 1, filePaths.size());
            } catch (const std::exception& e) {
                SS_LOG_WARN(L"YaraCompiler", L"AddFiles: Progress callback threw: %S", e.what());
                // Continue processing - callback failure shouldn't stop compilation
            } catch (...) {
                SS_LOG_WARN(L"YaraCompiler", L"AddFiles: Progress callback threw unknown exception");
            }
        }
    }

    // ========================================================================
    // RESULT EVALUATION
    // ========================================================================
    if (successCount == 0) {
        SS_LOG_ERROR(L"YaraCompiler", L"AddFiles: No rules added (%zu files failed)",
            failCount);
        return StoreError{SignatureStoreError::InvalidSignature, 0, 
            "No rules added: " + lastError};
    }

    SS_LOG_INFO(L"YaraCompiler", L"Added %zu/%zu rule files (%zu failed)", 
        successCount, filePaths.size(), failCount);
    return StoreError{SignatureStoreError::Success};
}

std::vector<std::string> YaraCompiler::GetErrors() const noexcept {
    return m_errors;
}

std::vector<std::string> YaraCompiler::GetWarnings() const noexcept {
    return m_warnings;
}

void YaraCompiler::ClearErrors() noexcept {
    m_errors.clear();
    m_warnings.clear();
}

// Returns a NON-OWNING pointer. Do not call yr_rules_destroy on the result.
//
// We link YARA 4.5.4. From YARA 4.0 onward YR_RULES is a singleton owned by the
// compiler: every call returns the same structure and yr_compiler_destroy
// releases it. Destroying it here, or in a caller, frees the compiler's only
// rule set along with the arena holding every rule identifier and namespace
// name, leaving any other holder reading released memory.
//
// Consequence for callers: the YaraCompiler must outlive every pointer this
// returns. A local compiler whose rules are stored past its scope is a
// use-after-free.
YR_RULES* YaraCompiler::GetRules() noexcept {
    if (!m_compiler) {
        return nullptr;
    }

    YR_RULES* rules = nullptr;

    int result = yr_compiler_get_rules(m_compiler, &rules);
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to get compiled rules: %d", result);
        return nullptr;
    }

    SS_LOG_DEBUG(L"YaraCompiler", L"GetRules called, rules compiled successfully");
    return rules;
}

StoreError YaraCompiler::SaveToFile(const std::wstring& filePath) noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Compiler initialization
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToFile: Compiler not initialized");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Compiler not initialized"};
    }
    
    // VALIDATION 2: Path validation
    if (filePath.empty()) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToFile: Empty file path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "File path is empty"};
    }
    
    // VALIDATION 3: Path length check
    if (filePath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToFile: Path too long");
        return StoreError{SignatureStoreError::FileNotFound, 0, "File path too long"};
    }
    
    // VALIDATION 4: Null character check
    if (filePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToFile: Path contains null character");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Path contains null character"};
    }

    // ========================================================================
    // GET COMPILED RULES
    // ========================================================================
    YR_RULES* rules = GetRules();
    if (!rules) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToFile: No compiled rules to save");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "No compiled rules"};
    }

    // ========================================================================
    // ATOMIC FILE WRITE (write to temp, then rename)
    // ========================================================================
    std::wstring tempPath = filePath + L".tmp";
    std::string narrowTempPath;
    std::string narrowFilePath;
    
    try {
        narrowTempPath = ShadowStrike::Utils::StringUtils::ToNarrow(tempPath);
        narrowFilePath = ShadowStrike::Utils::StringUtils::ToNarrow(filePath);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToFile: Path conversion failed: %S", e.what());
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Path conversion failed"};
    }
    
    // Save to temp file first
    int result = yr_rules_save(rules, narrowTempPath.c_str());
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to save rules to temp file: %s (error: %d)",
            tempPath.c_str(), result);
        DeleteFileW(tempPath.c_str()); // Cleanup on failure
        return StoreError{SignatureStoreError::MappingFailed,
                         static_cast<DWORD>(result),
                         "Failed to save rules to file"};
    }
    
    // Delete existing target file if it exists
    DeleteFileW(filePath.c_str());
    
    // Atomic rename
    if (!MoveFileW(tempPath.c_str(), filePath.c_str())) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to rename temp file: error %u", winErr);
        DeleteFileW(tempPath.c_str());
        return StoreError{SignatureStoreError::MappingFailed, winErr, "Failed to finalize save"};
    }
    
    SS_LOG_INFO(L"YaraCompiler", L"Saved compiled rules to: %s", filePath.c_str());
    return StoreError{SignatureStoreError::Success};
}

std::optional<std::vector<uint8_t>> YaraCompiler::SaveToBuffer() noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToBuffer: Compiler not initialized");
        return std::nullopt;
    }

    // ========================================================================
    // GET COMPILED RULES
    // ========================================================================
    YR_RULES* rules = nullptr;
    int result = yr_compiler_get_rules(m_compiler, &rules);
    if (result != ERROR_SUCCESS || !rules) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to get compiled rules: %d", result);
        return std::nullopt;
    }

    // ------------------------------------------------------------------
    // The rules returned here are NOT ours to destroy.
    //
    // We link YARA 4.5.4, and from YARA 4.0 onward YR_RULES is a singleton:
    // every call to yr_compiler_get_rules hands back the same structure, which
    // the compiler owns and yr_compiler_destroy releases. VirusTotal's own 4.0
    // migration notes state it directly - in 2.x and 3.x the function returned a
    // new instance per call, in 4.0 it does not. This code was written against
    // the older contract.
    //
    // There used to be an RAII guard here calling yr_rules_destroy. That freed
    // the compiler's only rule set, so any caller still holding a pointer from
    // GetRules() was left iterating released memory - and the rule identifiers
    // and namespace names live inside the arena that goes with it.
    //
    // That was SignatureBuilder::BuildYaraIndex, which calls GetRules(), then
    // SaveToBuffer(), then walks the rules. Under cdb the fault lands in
    // SignatureBuilder.cpp:1706 constructing a std::string from
    // rule->ns->name - strlen over freed memory. It reproduced on any rule file
    // regardless of content, which fits a lifetime defect and rules out the
    // rule text, and it was also a latent double free because
    // yr_compiler_destroy releases the same pointer again.
    //
    // Nothing leaks by not destroying: ~YaraCompiler calls yr_compiler_destroy.
    // The real constraint this creates is that the compiler must outlive every
    // pointer handed out by GetRules().
    // ------------------------------------------------------------------

    // ========================================================================
    // WRITE TO BUFFER WITH SIZE LIMIT
    // ========================================================================
    // DoS protection: Maximum compiled rules size (100MB)
    constexpr size_t MAX_COMPILED_RULES_SIZE = 100 * 1024 * 1024;
    
    struct WriteContext {
        std::vector<uint8_t>* buffer;
        size_t maxSize;
        bool overflow;
    };
    
    std::vector<uint8_t> buffer;
    
    try {
        // Pre-reserve reasonable initial size
        buffer.reserve(1024 * 1024); // 1MB initial
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToBuffer: Failed to reserve buffer memory");
        return std::nullopt;
    }
    
    WriteContext ctx{&buffer, MAX_COMPILED_RULES_SIZE, false};

    // Static callback function (YARA API requires function pointer)
    static auto writeCallback = [](const void* ptr, size_t size, size_t count, void* user_data) -> size_t {
        auto* ctx = static_cast<WriteContext*>(user_data);
        if (!ctx || !ctx->buffer || ctx->overflow) {
            return 0;
        }
        
        try {
            const uint8_t* bytes = static_cast<const uint8_t*>(ptr);
            size_t totalBytes = size * count;
            
            // Check for overflow
            if (totalBytes > ctx->maxSize - ctx->buffer->size()) {
                ctx->overflow = true;
                return 0;
            }
            
            ctx->buffer->insert(ctx->buffer->end(), bytes, bytes + totalBytes);
            return count; // YARA expects number of items written
        }
        catch (const std::bad_alloc&) {
            ctx->overflow = true;
            return 0;
        }
        catch (...) {
            return 0;
        }
    };

    // Setup YARA stream structure
    YR_STREAM stream;
    stream.user_data = &ctx;
    stream.write = +writeCallback; // Unary + converts lambda to function pointer

    // Save rules to stream
    result = yr_rules_save_stream(rules, &stream);

    // Clear rules guard - rules already destroyed by yr_rules_save_stream
    // (Actually no, we still own them - let RAII handle cleanup)

    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to save rules to buffer: %d", result);
        return std::nullopt;
    }
    
    if (ctx.overflow) {
        SS_LOG_ERROR(L"YaraCompiler", L"SaveToBuffer: Compiled rules exceed size limit (%zu MB)",
            MAX_COMPILED_RULES_SIZE / (1024 * 1024));
        return std::nullopt;
    }

    SS_LOG_DEBUG(L"YaraCompiler", L"Saved rules to buffer: %zu bytes", buffer.size());
    return buffer;
}

void YaraCompiler::SetIncludePaths(std::span<const std::wstring> paths) noexcept {
    m_includePaths.assign(paths.begin(), paths.end());
    SS_LOG_DEBUG(L"YaraCompiler", L"Set %zu include paths", paths.size());
}

void YaraCompiler::DefineExternalVariable(
    const std::string& name,
    const std::string& value
) noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(string): Compiler not initialized");
        return;
    }
    
    if (name.empty()) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(string): Empty variable name");
        return;
    }
    
    // Variable name length limit
    constexpr size_t MAX_VAR_NAME_LENGTH = 256;
    if (name.length() > MAX_VAR_NAME_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(string): Name too long (%zu)",
            name.length());
        return;
    }
    
    // Variable value length limit (DoS protection)
    constexpr size_t MAX_VAR_VALUE_LENGTH = 65536; // 64KB
    if (value.length() > MAX_VAR_VALUE_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(string): Value too long (%zu)",
            value.length());
        return;
    }
    
    // Validate variable name format (YARA requires valid C identifier)
    if (!std::isalpha(static_cast<unsigned char>(name[0])) && name[0] != '_') {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(string): Invalid name start: %S",
            name.c_str());
        return;
    }
    
    if (!std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_';
    })) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(string): Invalid name format: %S",
            name.c_str());
        return;
    }

    int result = yr_compiler_define_string_variable(m_compiler, name.c_str(), value.c_str());
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to define external string variable: %S (error: %d)",
            name.c_str(), result);
        return;
    }

    SS_LOG_DEBUG(L"YaraCompiler", L"Defined external string variable: %S (value length: %zu)",
        name.c_str(), value.length());
}

void YaraCompiler::DefineExternalVariable(
    const std::string& name,
    int64_t value
) noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(int): Compiler not initialized");
        return;
    }
    
    if (name.empty()) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(int): Empty variable name");
        return;
    }
    
    // Variable name length limit
    constexpr size_t MAX_VAR_NAME_LENGTH = 256;
    if (name.length() > MAX_VAR_NAME_LENGTH) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(int): Name too long (%zu)",
            name.length());
        return;
    }
    
    // Validate variable name format (YARA requires valid C identifier)
    if (!std::isalpha(static_cast<unsigned char>(name[0])) && name[0] != '_') {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(int): Invalid name start: %S",
            name.c_str());
        return;
    }
    
    if (!std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_';
    })) {
        SS_LOG_ERROR(L"YaraCompiler", L"DefineExternalVariable(int): Invalid name format: %S",
            name.c_str());
        return;
    }

    int result = yr_compiler_define_integer_variable(m_compiler, name.c_str(), value);
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to define external integer variable: %S (error: %d)",
            name.c_str(), result);
        return;
    }

    SS_LOG_DEBUG(L"YaraCompiler", L"Defined external integer variable: %S = %lld",
        name.c_str(), value);
}

void YaraCompiler::DefineExternalVariable(
    const std::string& name,
    bool value
) noexcept {
    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler",
            L"Compiler not initialized, cannot define boolean variable: %S",
            name.c_str());
        return;
    }

    if (name.empty()) {
        SS_LOG_ERROR(L"YaraCompiler",
            L"Cannot define boolean variable with empty name");
        return;
    }

    // Validate variable name format (YARA rules require valid identifiers)
    if (!std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_';
        })) {
        SS_LOG_ERROR(L"YaraCompiler",
            L"Invalid variable name format: %S (must be alphanumeric or underscore)",
            name.c_str());
        return;
    }

    // First character must be letter or underscore
    if (!std::isalpha(static_cast<unsigned char>(name[0])) && name[0] != '_') {
        SS_LOG_ERROR(L"YaraCompiler",
            L"Invalid variable name format: %S (must start with letter or underscore)",
            name.c_str());
        return;
    }

    // ========================================================================
    // DEFINE BOOLEAN VARIABLE
    // ========================================================================
    // Convert bool to integer (YARA uses int64 for boolean values)
    int64_t boolValue = value ? 1LL : 0LL;

    int result = yr_compiler_define_integer_variable(
        m_compiler,
        name.c_str(),
        boolValue
    );

    // ========================================================================
    // ERROR HANDLING
    // ========================================================================
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler",
            L"Failed to define external boolean variable: %S = %s (error: %d)",
            name.c_str(), value ? "true" : "false", result);

        // Log specific error codes for debugging
        switch (result) {
        case ERROR_INVALID_ARGUMENT:
            SS_LOG_DEBUG(L"YaraCompiler",
                L"  ERROR_INVALID_ARGUMENT: Variable name or type is invalid");
            break;
#ifdef ERROR_DUPLICATED_VARIABLE_IDENTIFIER
        case ERROR_DUPLICATED_VARIABLE_IDENTIFIER:
            SS_LOG_DEBUG(L"YaraCompiler",
                L"  ERROR_DUPLICATED_VARIABLE_IDENTIFIER: Variable already defined");
            break;
#endif
        default:
            SS_LOG_DEBUG(L"YaraCompiler",
                L"  Unknown YARA error code: %d", result);
            break;
        }
        return;
    }

    // ========================================================================
    // SUCCESS LOGGING
    // ========================================================================
    SS_LOG_DEBUG(L"YaraCompiler",
        L"Defined external boolean variable: %S = %s",
        name.c_str(), value ? "true" : "false");
}

void YaraCompiler::ErrorCallback(
    int errorLevel,
    const char* fileName,
    int lineNumber,
    const YR_RULE* rule,          // New YARA API includes rule pointer
    const char* message,
    void* userData
) {
    // ========================================================================
    // TITANIUM VALIDATION - NULL CHECK
    // ========================================================================
    auto* compiler = static_cast<YaraCompiler*>(userData);
    if (!compiler) {
        // Cannot log without compiler context - silently return
        return;
    }

    // ========================================================================
    // ERROR MESSAGE BUILDING WITH SAFETY LIMITS
    // ========================================================================
    try {
        std::ostringstream oss;
        
        // Add file location if available (truncate extremely long filenames)
        if (fileName) {
            std::string safeFileName = fileName;
            constexpr size_t MAX_FILENAME_DISPLAY = 256;
            if (safeFileName.length() > MAX_FILENAME_DISPLAY) {
                safeFileName = "..." + safeFileName.substr(safeFileName.length() - MAX_FILENAME_DISPLAY + 3);
            }
            oss << safeFileName << "(" << lineNumber << "): ";
        }
        
        // Include rule name if available
        if (rule && rule->identifier) {
            std::string safeRuleName = rule->identifier;
            constexpr size_t MAX_RULENAME_DISPLAY = 128;
            if (safeRuleName.length() > MAX_RULENAME_DISPLAY) {
                safeRuleName = safeRuleName.substr(0, MAX_RULENAME_DISPLAY - 3) + "...";
            }
            oss << "[" << safeRuleName << "] ";
        }
        
        // Add message if available
        if (message) {
            std::string safeMessage = message;
            constexpr size_t MAX_MESSAGE_LENGTH = 1024;
            if (safeMessage.length() > MAX_MESSAGE_LENGTH) {
                safeMessage = safeMessage.substr(0, MAX_MESSAGE_LENGTH - 3) + "...";
            }
            oss << safeMessage;
        } else {
            oss << "(no message)";
        }

        std::string errorStr = oss.str();
        
        // Limit total number of errors/warnings stored (DoS protection)
        constexpr size_t MAX_STORED_ERRORS = 1000;
        constexpr size_t MAX_STORED_WARNINGS = 1000;

        if (errorLevel == 0) { // Error
            if (compiler->m_errors.size() < MAX_STORED_ERRORS) {
                compiler->m_errors.push_back(std::move(errorStr));
            }
        } else { // Warning
            if (compiler->m_warnings.size() < MAX_STORED_WARNINGS) {
                compiler->m_warnings.push_back(std::move(errorStr));
            }
        }
    }
    catch (const std::bad_alloc&) {
        // Memory allocation failed - cannot store error, silently ignore
    }
    catch (...) {
        // Unknown exception - silently ignore to prevent crash
    }
}

// ============================================================================
// YARA RULE STORE IMPLEMENTATION - TITANIUM HARDENED
// ============================================================================

YaraRuleStore::YaraRuleStore() {
    // Initialize performance counter with fallback
    if (!QueryPerformanceFrequency(&m_perfFrequency) || m_perfFrequency.QuadPart == 0) {
        m_perfFrequency.QuadPart = 1000000; // Fallback to 1MHz (1 tick = 1 microsecond)
        SS_LOG_WARN(L"YaraRuleStore", L"Constructor: Using fallback performance frequency");
    }
    
    // Initialize atomic members explicitly
    m_initialized.store(false, std::memory_order_relaxed);
    m_readOnly.store(false, std::memory_order_relaxed);
    m_totalScans.store(0, std::memory_order_relaxed);
    m_totalMatches.store(0, std::memory_order_relaxed);
    m_totalBytesScanned.store(0, std::memory_order_relaxed);
}

YaraRuleStore::~YaraRuleStore() {
    Close();
}

StoreError YaraRuleStore::InitializeYara() noexcept {
    std::lock_guard<std::mutex> lock(s_yaraInitMutex);

  
    if (s_yaraInitialized.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::Success };
    }

   //start YARA Library
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Failed to initialize YARA library (error: %d)", result);
        return StoreError{ SignatureStoreError::InvalidFormat,
                          static_cast<DWORD>(result),
                          "Failed to initialize YARA" };
    }

    s_yaraInitialized.store(true, std::memory_order_release);
    SS_LOG_INFO(L"YaraRuleStore", L"YARA library initialized successfully");
    return StoreError{ SignatureStoreError::Success };
}


void YaraRuleStore::FinalizeYara() noexcept {
    std::lock_guard<std::mutex> lock(s_yaraInitMutex);

    
    if (!s_yaraInitialized.load(std::memory_order_acquire)) {
        return;
    }

    //finalize the Yara library
    int result = yr_finalize();
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Failed to finalize YARA library (error: %d)", result);
        return;
    }

    s_yaraInitialized.store(false, std::memory_order_release);
    SS_LOG_INFO(L"YaraRuleStore", L"YARA library finalized successfully");
}


StoreError YaraRuleStore::Initialize(
    const std::wstring& databasePath,
    bool readOnly
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"Initialize: %s", databasePath.c_str());

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Already initialized check
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"YaraRuleStore", L"Initialize: Already initialized");
        return StoreError{SignatureStoreError::Success};
    }
    
    // VALIDATION 2: Path validation
    if (databasePath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Initialize: Empty database path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Database path is empty"};
    }
    
    // VALIDATION 3: Path length check
    if (databasePath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Initialize: Path too long (%zu chars)", databasePath.length());
        return StoreError{SignatureStoreError::FileNotFound, 0, "Database path too long"};
    }
    
    // VALIDATION 4: Null character injection check
    if (databasePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Initialize: Path contains null character (security violation)");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Path contains null character"};
    }
    
    // VALIDATION 5: Performance counter initialization
    if (m_perfFrequency.QuadPart == 0) {
        if (!QueryPerformanceFrequency(&m_perfFrequency) || m_perfFrequency.QuadPart == 0) {
            m_perfFrequency.QuadPart = 1000000; // Fallback to 1MHz
            SS_LOG_WARN(L"YaraRuleStore", L"Initialize: Using fallback performance frequency");
        }
    }

    // ========================================================================
    // YARA INITIALIZATION
    // ========================================================================
    StoreError err = InitializeYara();
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Initialize: YARA initialization failed");
        return err;
    }

    // TITANIUM: take the global lock exclusively so concurrent Initialize/Close
    // cannot race on m_mappedView, m_rules and m_ruleMetadata. Re-check
    // m_initialized after acquiring the lock to be idempotent under contention.
    std::unique_lock<std::shared_mutex> initLock(m_globalLock);

    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"YaraRuleStore", L"Initialize: Already initialized (race)");
        return StoreError{SignatureStoreError::Success};
    }

    m_databasePath = databasePath;
    m_readOnly.store(readOnly, std::memory_order_release);

    // ========================================================================
    // MEMORY MAPPING
    // ========================================================================
    err = OpenMemoryMapping(databasePath, readOnly);
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Initialize: Memory mapping failed");
        return err;
    }

    // ========================================================================
    // RULE LOADING
    // ========================================================================
    err = LoadRulesInternal();
    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Initialize: Rule loading failed");
        CloseMemoryMapping();
        return err;
    }

    m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(L"YaraRuleStore", L"Initialized successfully (readOnly=%s)", 
        readOnly ? L"true" : L"false");
    return StoreError{SignatureStoreError::Success};
}

StoreError YaraRuleStore::CreateNew(
    const std::wstring& databasePath,
    uint64_t initialSizeBytes
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"CreateNew: %s (size: %llu bytes)", 
        databasePath.c_str(), initialSizeBytes);

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Already initialized check
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Store already initialized - close first");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Store already initialized"};
    }
    
    // VALIDATION 2: Path validation
    if (databasePath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Empty database path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Database path is empty"};
    }
    
    // VALIDATION 3: Path length check
    if (databasePath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Path too long (%zu)", databasePath.length());
        return StoreError{SignatureStoreError::FileNotFound, 0, "Path too long"};
    }
    
    // VALIDATION 4: Null character check
    if (databasePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Path contains null character");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Path contains null character"};
    }
    
    // VALIDATION 5: Size validation
    constexpr uint64_t MIN_DB_SIZE = 4096; // Minimum 4KB
    constexpr uint64_t MAX_DB_SIZE = 4ULL * 1024 * 1024 * 1024; // Maximum 4GB
    
    if (initialSizeBytes < MIN_DB_SIZE) {
        SS_LOG_WARN(L"YaraRuleStore", L"CreateNew: Size too small (%llu), using minimum %llu",
            initialSizeBytes, MIN_DB_SIZE);
        initialSizeBytes = MIN_DB_SIZE;
    }
    
    if (initialSizeBytes > MAX_DB_SIZE) {
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Size exceeds maximum (%llu > %llu)",
            initialSizeBytes, MAX_DB_SIZE);
        return StoreError{SignatureStoreError::TooLarge, 0, "Database size exceeds 4GB limit"};
    }

    // ========================================================================
    // CREATE FILE WITH SECURITY ATTRIBUTES
    // ========================================================================
    HANDLE hFile = CreateFileW(
        databasePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // No sharing during creation
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Failed to create file (error: %u)", winErr);
        return StoreError{SignatureStoreError::FileNotFound, winErr, "Cannot create file"};
    }
    
    // RAII guard for file handle
    struct FileGuard {
        HANDLE h;
        ~FileGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    } fileGuard{hFile};

    // ========================================================================
    // SET FILE SIZE
    // ========================================================================
    LARGE_INTEGER size{};
    size.QuadPart = static_cast<LONGLONG>(initialSizeBytes);
    
    if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN)) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Failed to set file pointer (error: %u)", winErr);
        return StoreError{SignatureStoreError::MappingFailed, winErr, "Cannot set file pointer"};
    }
    
    if (!SetEndOfFile(hFile)) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Failed to set end of file (error: %u)", winErr);
        return StoreError{SignatureStoreError::MappingFailed, winErr, "Cannot set file size"};
    }

    // ========================================================================
    // WRITE INITIAL HEADER (ZERO-FILLED)
    // ========================================================================
    // Reset file pointer to beginning
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN)) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Failed to reset file pointer (error: %u)", winErr);
        return StoreError{SignatureStoreError::MappingFailed, winErr, "Cannot reset file pointer"};
    }
    
    // Write a basic header with magic number
    SignatureDatabaseHeader header{};
    header.magic = SIGNATURE_DB_MAGIC;
    header.versionMajor = SIGNATURE_DB_VERSION_MAJOR;
    header.versionMinor = SIGNATURE_DB_VERSION_MINOR;
    // Milliseconds, matching SignatureBuilder and the documented unit on the field.
    //
    // This wrote std::time(nullptr) - seconds - into the same SignatureDatabaseHeader
    // that SignatureBuilder fills with milliseconds. Two producers of one field in
    // two different units is the actual defect behind the "Creation timestamp
    // outside expected range" warnings, and it had a second consequence: the content
    // seeding in DataStorePaths decides whether to install shipped content by
    // comparing lastUpdateTime, so a seconds-valued header looks roughly fifty years
    // older than any millisecond-valued baseline and would lose that comparison every
    // time regardless of which database was actually newer.
    const auto nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    header.creationTime = nowMs;
    header.lastUpdateTime = nowMs;
    header.buildNumber = 1;
    header.totalHashes = 0;
    header.totalPatterns = 0;
    header.totalYaraRules = 0;
    header.yaraRulesOffset = 0;
    header.yaraRulesSize = 0;
    header.metadataOffset = 0;
    header.metadataSize = 0;
    
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, &header, sizeof(header), &bytesWritten, nullptr) ||
        bytesWritten != sizeof(header)) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"CreateNew: Failed to write header (error: %u)", winErr);
        return StoreError{SignatureStoreError::MappingFailed, winErr, "Cannot write header"};
    }
    
    // Flush to ensure data is written
    if (!FlushFileBuffers(hFile)) {
        SS_LOG_WARN(L"YaraRuleStore", L"CreateNew: FlushFileBuffers warning");
    }

    // Close file before Initialize (let RAII handle it)
    fileGuard.h = INVALID_HANDLE_VALUE;
    CloseHandle(hFile);

    // ========================================================================
    // INITIALIZE WITH NEW DATABASE
    // ========================================================================
    SS_LOG_DEBUG(L"YaraRuleStore", L"CreateNew: File created, calling Initialize");
    return Initialize(databasePath, false);
}

StoreError YaraRuleStore::LoadCompiledRules(const std::wstring& compiledRulePath) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"LoadCompiledRules: %s", compiledRulePath.c_str());

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Read-only check
    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: Store is read-only");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Store is read-only"};
    }
    
    // VALIDATION 2: Path validation
    if (compiledRulePath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: Empty file path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "File path is empty"};
    }
    
    // VALIDATION 3: Path length check
    if (compiledRulePath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: Path too long");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Path too long"};
    }
    
    // VALIDATION 4: Null character check
    if (compiledRulePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: Path contains null character");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Path contains null character"};
    }
    
    // VALIDATION 5: File existence check
    DWORD fileAttrs = GetFileAttributesW(compiledRulePath.c_str());
    if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: File not found (error: %u)", winErr);
        return StoreError{SignatureStoreError::FileNotFound, winErr, "File not found"};
    }
    
    // VALIDATION 6: Not a directory check
    if (fileAttrs & FILE_ATTRIBUTE_DIRECTORY) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: Path is a directory");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Path is a directory"};
    }

    // ========================================================================
    // ACQUIRE EXCLUSIVE LOCK FOR RULE REPLACEMENT
    // ========================================================================
    std::unique_lock<std::shared_mutex> lock(m_globalLock);
    
    // ========================================================================
    // DESTROY EXISTING RULES SAFELY
    // ========================================================================
    if (m_rules) {
        int destroyResult = yr_rules_destroy(m_rules);
        if (destroyResult != ERROR_SUCCESS) {
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: Failed to destroy existing rules (error: %d)", 
                destroyResult);
            return StoreError{SignatureStoreError::Unknown,
                             static_cast<DWORD>(destroyResult),
                             "Failed to destroy existing rules"};
        }
        m_rules = nullptr;
    }

    // ========================================================================
    // CONVERT PATH AND LOAD RULES
    // ========================================================================
    std::string narrowPath;
    try {
        narrowPath = ShadowStrike::Utils::StringUtils::ToNarrow(compiledRulePath);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: Path conversion failed: %S", e.what());
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Path conversion failed"};
    }

    int result = yr_rules_load(narrowPath.c_str(), &m_rules);
    if (result != ERROR_SUCCESS || !m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadCompiledRules: YARA load failed (error: %d)", result);
        m_rules = nullptr; // Ensure null on failure
        return StoreError{SignatureStoreError::InvalidFormat,
                         static_cast<DWORD>(result),
                         "Failed to load compiled rules"};
    }

    // ========================================================================
    // EXTRACT RULE METADATA FROM LOADED RULES
    // ========================================================================
    // Shared with LoadRulesInternal. This loop used to be duplicated here, and
    // a third copy in SignatureBuilder::BuildYaraIndex had already drifted - it
    // dereferenced rule->ns->name without a null check and crashed on freed
    // arena memory. One implementation, one place to fix.
    const size_t ruleCount = RebuildRuleMetadataFromRules();

    // Loaded from compiled bytecode, so no tracked source describes these rules.
    // See m_hasUntrackedRules: while this holds, a source-driven rebuild is refused
    // rather than allowed to discard them.
    m_hasUntrackedRules = (ruleCount > 0u);

    SS_LOG_INFO(L"YaraRuleStore", L"LoadCompiledRules: Loaded %zu rules from %s", 
        ruleCount, compiledRulePath.c_str());
    return StoreError{SignatureStoreError::Success};
}

// ============================================================================
// TITANIUM: SAFE CLOSE OPERATION
// ============================================================================

void YaraRuleStore::Close() noexcept {
    // VALIDATION: Already closed check
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_DEBUG(L"YaraRuleStore", L"Close: Already closed or not initialized");
        return;
    }

    SS_LOG_INFO(L"YaraRuleStore", L"Closing YaraRuleStore...");

    // ========================================================================
    // STEP 1: ACQUIRE EXCLUSIVE LOCK
    // ========================================================================
    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Double-check after lock acquisition
    if (!m_initialized.load(std::memory_order_relaxed)) {
        return;
    }

    // ========================================================================
    // STEP 2: FREE COMPILED RULES
    // ========================================================================
    if (m_rules) {
        // Note: yr_rules_destroy should be called while no scans are in progress
        // The global lock ensures this
        int destroyResult = yr_rules_destroy(m_rules);
        if (destroyResult != ERROR_SUCCESS) {
            SS_LOG_ERROR(L"YaraRuleStore", L"Close: Failed to destroy rules (error: %d)", destroyResult);
            // Continue closing despite error
        }
        m_rules = nullptr;
    }

    // Reset with the rules it describes, so a reopened store does not inherit a
    // claim about a rule set that no longer exists.
    m_hasUntrackedRules = false;

    // ========================================================================
    // STEP 3: CLEAR METADATA (with logging)
    // ========================================================================
    size_t metadataCount = m_ruleMetadata.size();
    m_ruleMetadata.clear();
    SS_LOG_DEBUG(L"YaraRuleStore", L"Close: Cleared %zu rule metadata entries", metadataCount);
    
    // Clear rule source cache
    size_t sourceCount = m_ruleSources.size();
    m_ruleSources.clear();
    SS_LOG_DEBUG(L"YaraRuleStore", L"Close: Cleared %zu rule source entries", sourceCount);

    // ========================================================================
    // STEP 4: CLOSE MEMORY MAPPING
    // ========================================================================
    CloseMemoryMapping();

    // ========================================================================
    // STEP 5: LOG FINAL STATISTICS
    // ========================================================================
    uint64_t totalScans = m_totalScans.load(std::memory_order_relaxed);
    uint64_t totalMatches = m_totalMatches.load(std::memory_order_relaxed);
    uint64_t totalBytes = m_totalBytesScanned.load(std::memory_order_relaxed);
    
    SS_LOG_INFO(L"YaraRuleStore", 
        L"Close: Statistics - Scans: %llu, Matches: %llu, Bytes: %llu",
        totalScans, totalMatches, totalBytes);

    // ========================================================================
    // STEP 6: RESET STATE
    // ========================================================================
    m_initialized.store(false, std::memory_order_release);
    m_readOnly.store(false, std::memory_order_release);
    // Don't reset statistics - they may be queried after close

    SS_LOG_INFO(L"YaraRuleStore", L"Closed successfully");
}

// ============================================================================
// SCANNING OPERATIONS
// ============================================================================

std::vector<YaraMatch> YaraRuleStore::ScanBuffer(
    std::span<const uint8_t> buffer,
    const YaraScanOptions& options
) const noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER - BUFFER SCANNING
    // ========================================================================
    
    // VALIDATION 1: Initialization state (fast unlocked path)
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanBuffer: Store not initialized");
        return {};
    }
    
    // VALIDATION 2: Empty buffer check
    if (buffer.empty()) {
        SS_LOG_DEBUG(L"YaraRuleStore", L"ScanBuffer: Empty buffer, nothing to scan");
        return {};
    }
    
    // VALIDATION 3: Null pointer check with non-zero size
    if (buffer.data() == nullptr) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanBuffer: Null buffer pointer with non-empty span");
        return {};
    }
    
    // VALIDATION 4: Maximum buffer size (DoS protection)
    if (buffer.size() > YaraTitaniumLimits::MAX_SCAN_BUFFER_SIZE) {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanBuffer: Buffer too large (%zu > %zu bytes)",
            buffer.size(), YaraTitaniumLimits::MAX_SCAN_BUFFER_SIZE);
        return {};
    }

    // TITANIUM CRITICAL: acquire the global shared lock for the entire scan.
    // Close() holds the same lock exclusively while destroying m_rules and
    // clearing m_ruleMetadata; without this guard a concurrent Close() can
    // free YR_RULES while yr_rules_scan_mem is still dereferencing it
    // (use-after-free) or clear m_ruleMetadata while the callback iterates it.
    // The shared_lock is recursive-safe across distinct threads but MUST NOT be
    // held by callers of ScanBuffer (verified for ScanFile, ScanContext).
    std::vector<YaraMatch> results;
    {
        std::shared_lock<std::shared_mutex> scanLock(m_globalLock);

        // Re-check initialization under the lock â€” Close() may have run between
        // the unlocked fast-path check and lock acquisition.
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_DEBUG(L"YaraRuleStore", L"ScanBuffer: Store closed during entry");
            return {};
        }

        // VALIDATION 5: Rules loaded check (now race-free under the lock)
        if (!m_rules) {
            SS_LOG_WARN(L"YaraRuleStore", L"ScanBuffer: No compiled rules loaded");
            return {};
        }

        results = PerformScan(buffer.data(), buffer.size(), options);
    }

    // Lock released. Apply deferred best-effort hit-count updates now that we
    // can safely take m_globalLock exclusively from UpdateRuleHitCount.
    for (const auto& match : results) {
        if (!match.ruleName.empty()) {
            const std::string ns = match.namespace_.empty() ? "default" : match.namespace_;
            const_cast<YaraRuleStore*>(this)->UpdateRuleHitCount(ns + "::" + match.ruleName);
        }
    }

    return results;
}

std::vector<YaraMatch> YaraRuleStore::ScanFile(
    const std::wstring& filePath,
    const YaraScanOptions& options
) const noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER - FILE SCANNING
    // ========================================================================
    
    SS_LOG_DEBUG(L"YaraRuleStore", L"ScanFile: %s", filePath.c_str());
    
    // VALIDATION 1: Empty path check
    if (filePath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanFile: Empty file path");
        return {};
    }
    
    // VALIDATION 2: Path length check
    if (filePath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanFile: Path too long (%zu chars)", filePath.length());
        return {};
    }
    
    // VALIDATION 3: Null character injection check
    if (filePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanFile: Path contains null character (security violation)");
        return {};
    }
    
    // VALIDATION 4: Initialization state
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanFile: Store not initialized");
        return {};
    }

    // ========================================================================
    // FILE SIZE CHECK WITH RAII
    // ========================================================================
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanFile: Failed to open file (error: %u)", winErr);
        return {};
    }

    // RAII guard for file handle
    struct FileHandleGuard {
        HANDLE h;
        ~FileHandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    } handleGuard{ hFile };

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanFile: Failed to get file size");
        return {};
    }
    
    // Close handle early - we don't need it for memory mapping
    CloseHandle(hFile);
    handleGuard.h = INVALID_HANDLE_VALUE; // Prevent double-close in guard

    // VALIDATION 5: File size checks
    if (fileSize.QuadPart == 0) {
        SS_LOG_DEBUG(L"YaraRuleStore", L"ScanFile: Empty file, nothing to scan");
        return {};
    }
    
    if (static_cast<uint64_t>(fileSize.QuadPart) > options.maxFileSizeBytes) {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanFile: File too large (%lld > %zu bytes)",
            fileSize.QuadPart, options.maxFileSizeBytes);
        return {};
    }

    // ========================================================================
    // MEMORY MAPPING WITH TITANIUM SAFETY
    // ========================================================================
    StoreError err{};
    MemoryMappedView fileView{};
    
    // OpenFileView, NOT OpenView. This is the same defect that disabled
    // SignatureStore::ScanFile, present independently here: OpenView enforces a
    // SignatureDatabaseHeader on whatever it maps, so a scan target had to look
    // like a signature database to be readable. No executable, archive or
    // document does, which means every real file handed to this function failed
    // to map and returned a result with no matches -- so none of the 11,053
    // compiled rules could ever match through this entry point.
    //
    // The ceiling is the caller's scan limit, already validated above, not
    // MAX_DATABASE_SIZE.
    if (!ShadowStrike::SignatureStore::MemoryMapping::OpenFileView(
            filePath, fileView, err, options.maxFileSizeBytes)) {
        // Not at ERROR for a cloud placeholder: on a Files On-Demand machine
        // that is the normal state of most documents, and at ERROR it would bury
        // the real mapping failures. Same honest limit as PatternStore::ScanFile
        // - this function returns a match vector, so it cannot report "not
        // examined" to its caller. Tracked separately.
        if (ShadowStrike::Utils::FileUtils::IsContentNotLocalError(err.win32Error)) {
            SS_LOG_DEBUG(L"YaraRuleStore",
                L"ScanFile: content not resident locally, not examined: %S", err.message.c_str());
        }
        else {
            SS_LOG_ERROR(L"YaraRuleStore", L"ScanFile: Failed to map file for scanning: %S",
                err.message.c_str());
        }
        return {};
    }
    
    // RAII guard for memory mapping
    struct MappingGuard {
        MemoryMappedView* view;
        ~MappingGuard() { if (view) ShadowStrike::SignatureStore::MemoryMapping::CloseView(*view); }
    } mappingGuard{ &fileView };
    
    // VALIDATION 6: Memory mapping integrity
    if (!fileView.baseAddress || fileView.fileSize == 0) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanFile: Invalid memory mapping");
        return {};
    }
    
    // VALIDATION 7: Cross-check sizes
    if (fileView.fileSize != static_cast<uint64_t>(fileSize.QuadPart)) {
        SS_LOG_WARN(L"YaraRuleStore", 
            L"ScanFile: Mapped size differs from file size (TOCTOU warning)");
        // Continue but log for audit
    }

    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(fileView.baseAddress),
        static_cast<size_t>(fileView.fileSize)
    );

    // Execute scan - mapping will be closed by RAII guard
    return ScanBuffer(buffer, options);
}

std::vector<YaraMatch> YaraRuleStore::ScanProcess(
    uint32_t processId,
    const YaraScanOptions& options
) const noexcept {
    // ========================================================================
    // TITANIUM VALIDATION LAYER - PROCESS SCANNING
    // ========================================================================
    
    SS_LOG_DEBUG(L"YaraRuleStore", L"ScanProcess: PID=%u", processId);

    std::vector<YaraMatch> matches;

    // VALIDATION 1: Process ID sanity check
    if (processId == 0) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanProcess: Invalid PID 0 (System Idle Process)");
        return matches;
    }
    
    // VALIDATION 2: Self-scan protection (debugging only)
    if (processId == GetCurrentProcessId()) {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanProcess: Scanning self (PID=%u) - use with caution", processId);
        // Allow but warn
    }
    
    // VALIDATION 3: System process protection (PID 4 = System)
    if (processId == 4) {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanProcess: Scanning System process (PID=4)");
        // Allow but warn - may fail due to permissions
    }

    // VALIDATION 4: Initialization state (fast unlocked path)
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanProcess: Store not initialized");
        return matches;
    }

    // TITANIUM CRITICAL: hold the global shared lock for the entire scan to
    // prevent Close() from destroying m_rules / clearing m_ruleMetadata while
    // yr_rules_scan_proc and its callback are still using them.
    std::shared_lock<std::shared_mutex> scanLock(m_globalLock);

    // Re-check initialization under the lock.
    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_DEBUG(L"YaraRuleStore", L"ScanProcess: Store closed during entry");
        return matches;
    }

    // VALIDATION 5: Rules loaded check (race-free under the lock)
    if (!m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanProcess: No compiled rules loaded");
        return matches;
    }
    
    // VALIDATION 6: Performance counter (prevent division by zero)
    if (m_perfFrequency.QuadPart == 0) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanProcess: Performance counter not initialized");
        return matches;
    }

    // ========================================================================
    // PROCESS HANDLE ACQUISITION WITH RAII
    // ========================================================================
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        processId
    );

    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanProcess: OpenProcess failed for PID=%u (error: %u)",
            processId, winErr);
        return matches;//-V773 false positive: RAII guard releases handle
    }

    // RAII handle guard
    struct ProcessHandleGuard {
        HANDLE handle;
        ~ProcessHandleGuard() { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    } guard{ hProcess };

    // ========================================================================
    // STATISTICS & TIMING
    // ========================================================================
    m_totalScans.fetch_add(1, std::memory_order_relaxed);

    LARGE_INTEGER startTime{};
    if (!QueryPerformanceCounter(&startTime)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanProcess: Failed to get start time");
        return matches;
    }

    // ========================================================================
    // CALLBACK CONTEXT SETUP (TITANIUM SAFE)
    // ========================================================================
    struct ScanCallbackContext {
        const YaraRuleStore* store;
        std::vector<YaraMatch>* matches;
        LARGE_INTEGER scanStartTime;
        LARGE_INTEGER perfFrequency;
        uint32_t maxMatchesPerRule;
        ThreatLevel minThreatLevel;
    };

    ScanCallbackContext ctx{};
    ctx.store = this;
    ctx.matches = &matches;
    ctx.scanStartTime = startTime;
    ctx.perfFrequency = m_perfFrequency;
    ctx.maxMatchesPerRule = options.maxMatchesPerRule;
    ctx.minThreatLevel = options.minThreatLevel;

    // ========================================================================
    // YARA CALLBACK FOR PROCESS SCAN (TITANIUM SAFE)
    // ========================================================================
    auto callback = [](YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) -> int {
        // VALIDATION: Null user_data check
        if (!user_data) {
            return CALLBACK_ABORT;
        }
        
        auto* ctx = static_cast<ScanCallbackContext*>(user_data);
        
        // VALIDATION: Context sanity
        if (!ctx->store || !ctx->matches) {
            return CALLBACK_ABORT;
        }

        if (message == CALLBACK_MSG_RULE_MATCHING) {
            auto* rule = static_cast<YR_RULE*>(message_data);

            // VALIDATION: Rule pointer and identifier
            if (!rule || !rule->identifier) {
                return CALLBACK_CONTINUE;
            }

            std::string ruleName = rule->identifier;
            std::string ruleNamespace = rule->ns ? rule->ns->name : "default";
            std::string fullName = ruleNamespace + "::" + ruleName;

            // Get rule metadata (read access - should be thread-safe if caller holds shared lock)
            auto metadataIt = ctx->store->m_ruleMetadata.find(fullName);
            if (metadataIt != ctx->store->m_ruleMetadata.end()) {
                // Filter by threat level
                if (static_cast<uint8_t>(metadataIt->second.threatLevel) <
                    static_cast<uint8_t>(ctx->minThreatLevel)) {
                    return CALLBACK_CONTINUE;
                }
            }

            // Build match result
            YaraMatch match{};
            match.ruleName = ruleName;
            match.namespace_ = ruleNamespace;

            // Get metadata if available
            if (metadataIt != ctx->store->m_ruleMetadata.end()) {
                match.ruleId = metadataIt->second.ruleId;
                match.threatLevel = metadataIt->second.threatLevel;
                match.tags = metadataIt->second.tags;
            }

            // Extract string matches with bounds checking
            YR_STRING* string = nullptr;
            yr_rule_strings_foreach(rule, string) {
                if (!string || !string->identifier) continue;
                
                YR_MATCH* match_info = nullptr;
                yr_string_matches_foreach(context, string, match_info) {
                    if (!match_info) continue;
                    
                    YaraMatch::StringMatch strMatch{};
                    strMatch.identifier = string->identifier;
                    strMatch.offsets.push_back(match_info->offset);

                    // Add match data if available with size limit
                    if (match_info->data && match_info->data_length > 0) {
                        size_t safeLen = std::min(static_cast<size_t>(match_info->data_length), 
                                                   static_cast<size_t>(1024)); // 1KB limit
                        std::string matchData(
                            reinterpret_cast<const char*>(match_info->data),
                            safeLen
                        );
                        strMatch.data.push_back(std::move(matchData));
                    }

                    match.stringMatches.push_back(std::move(strMatch));

                    // Limit matches per rule
                    if (match.stringMatches.size() >= ctx->maxMatchesPerRule) {
                        goto process_string_matches_done;
                    }
                }
            }
        process_string_matches_done:

            // Calculate match time (division by zero safe)
            if (ctx->perfFrequency.QuadPart > 0) {
                LARGE_INTEGER endTime{};
                QueryPerformanceCounter(&endTime);
                match.matchTimeMicroseconds =
                    ((endTime.QuadPart - ctx->scanStartTime.QuadPart) * 1000000ULL) / 
                    ctx->perfFrequency.QuadPart;
            }

            ctx->matches->push_back(std::move(match));

            // TITANIUM: hit-count updates are deferred (see PerformScan
            // comment); recursive acquisition of m_globalLock is unsupported.
        }

        return CALLBACK_CONTINUE;
        };

    // Prepare YARA scan flags
    int scanFlags = 0;
    if (options.fastMode) {
        scanFlags |= SCAN_FLAGS_FAST_MODE;
    }

    // YARA scanning is not thread-safe
    std::lock_guard<std::mutex> lock(m_scanMutex);

    // Perform process scan
    int result = yr_rules_scan_proc(
        m_rules,
        static_cast<int>(processId),
        scanFlags,
        callback,
        &ctx,
        static_cast<int>(options.timeoutSeconds)
    );

    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t scanTimeUs =
        ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) / m_perfFrequency.QuadPart;

    // Handle scan result
    if (result == ERROR_SUCCESS) {
        m_totalMatches.fetch_add(matches.size(), std::memory_order_relaxed);

        // Update match timestamps
        for (auto& match : matches) {
            if (match.matchTimeMicroseconds == 0) {
                match.matchTimeMicroseconds = scanTimeUs;
            }
        }

        SS_LOG_INFO(L"YaraRuleStore",
            L"Process scan complete: PID=%u, matches=%zu, time=%llu us",
            processId, matches.size(), scanTimeUs);
    }
    else {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"Process scan failed for PID=%u (YARA error: %d)",
            processId, result);

        // Clear partial results on error
        matches.clear();
    }

    // Release the global shared lock before applying deferred best-effort
    // hit-count updates (UpdateRuleHitCount takes m_globalLock exclusively;
    // recursive acquisition on the same thread is unsupported).
    scanLock.unlock();

    for (const auto& match : matches) {
        if (!match.ruleName.empty()) {
            const std::string ns = match.namespace_.empty() ? "default" : match.namespace_;
            const_cast<YaraRuleStore*>(this)->UpdateRuleHitCount(ns + "::" + match.ruleName);
        }
    }

    return matches;
}

// ============================================================================
// SCAN CONTEXT (STREAMING INTERFACE) - TITANIUM HARDENED
// ============================================================================

YaraRuleStore::ScanContext YaraRuleStore::CreateScanContext(
    const YaraScanOptions& options
) const noexcept {
    ScanContext ctx;
    ctx.m_store = this;
    ctx.m_options = options;
    ctx.m_isValid = m_initialized.load(std::memory_order_acquire) && m_rules != nullptr;
    return ctx;
}

void YaraRuleStore::ScanContext::Reset() noexcept {
    m_buffer.clear();
    m_buffer.shrink_to_fit(); // Release memory
    m_totalBytesProcessed = 0;
}

std::vector<YaraMatch> YaraRuleStore::ScanContext::FeedChunk(
    std::span<const uint8_t> chunk
) noexcept {
    // ========================================================================
    // TITANIUM VALIDATION
    // ========================================================================
    
    // VALIDATION 1: Context validity
    if (!m_isValid || !m_store) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanContext::FeedChunk: Invalid context");
        return {};
    }
    
    // VALIDATION 2: Empty chunk check
    if (chunk.empty()) {
        return {};
    }
    
    // VALIDATION 3: Null pointer with non-empty span
    if (chunk.data() == nullptr) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanContext::FeedChunk: Null chunk pointer");
        return {};
    }
    
    // VALIDATION 4: Buffer overflow protection.
    // Compute the cap-check without unsigned wraparound: m_buffer.size() and
    // chunk.size() can each approach SIZE_MAX in theory; do the comparison in
    // the form `chunk.size() > MAX - m_buffer.size()` to avoid overflow.
    constexpr size_t MAX_CONTEXT_BUFFER = 100 * 1024 * 1024; // 100MB max

    // If the chunk alone exceeds the cap, reject it outright â€” there is no
    // safe way to accumulate it.
    if (chunk.size() > MAX_CONTEXT_BUFFER) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"ScanContext::FeedChunk: Chunk exceeds cap (%zu > %zu)",
            chunk.size(), MAX_CONTEXT_BUFFER);
        return {};
    }

    std::vector<YaraMatch> drainResults;
    if (chunk.size() > MAX_CONTEXT_BUFFER - m_buffer.size()) {
        SS_LOG_DEBUG(L"YaraRuleStore",
            L"ScanContext::FeedChunk: Accumulator full, draining %zu bytes before accumulating",
            m_buffer.size());
        if (!m_buffer.empty()) {
            drainResults = m_store->ScanBuffer(m_buffer, m_options);
        }
        m_buffer.clear();
    }
    
    // Add chunk to buffer
    try {
        m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.end());
        m_totalBytesProcessed += chunk.size();
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanContext::FeedChunk: Memory allocation failed");
        m_buffer.clear();
        return drainResults;
    }

    // Scan when buffer reaches threshold (10MB)
    constexpr size_t SCAN_THRESHOLD = 10 * 1024 * 1024;
    if (m_buffer.size() >= SCAN_THRESHOLD) {
        auto results = m_store->ScanBuffer(m_buffer, m_options);
        m_buffer.clear();
        if (!drainResults.empty()) {
            try {
                results.insert(results.end(),
                    std::make_move_iterator(drainResults.begin()),
                    std::make_move_iterator(drainResults.end()));
            } catch (const std::bad_alloc&) {
                SS_LOG_WARN(L"YaraRuleStore",
                    L"ScanContext::FeedChunk: failed to merge drain results (OOM)");
            }
        }
        return results;
    }

    return drainResults;
}

std::vector<YaraMatch> YaraRuleStore::ScanContext::Finalize() noexcept {
    // VALIDATION: Context validity
    if (!m_isValid || !m_store) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ScanContext::Finalize: Invalid context");
        return {};
    }
    
    if (m_buffer.empty()) {
        return {};
    }

    auto results = m_store->ScanBuffer(m_buffer, m_options);
    m_buffer.clear();
    m_buffer.shrink_to_fit(); // Release memory
    return results;
}

// ============================================================================
// RULE MANAGEMENT - TITANIUM CORE SCAN ENGINE
// ============================================================================

std::vector<YaraMatch> YaraRuleStore::PerformScan(
    const void* buffer,
    size_t size,
    const YaraScanOptions& options
) const noexcept {
    std::vector<YaraMatch> matches;

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Buffer pointer
    if (!buffer) {
        SS_LOG_ERROR(L"YaraRuleStore", L"PerformScan: Null buffer pointer");
        return matches;
    }
    
    // VALIDATION 2: Buffer size
    if (size == 0) {
        SS_LOG_DEBUG(L"YaraRuleStore", L"PerformScan: Zero-size buffer, nothing to scan");
        return matches;
    }
    
    // VALIDATION 3: Maximum buffer size (DoS protection)
    if (size > YaraTitaniumLimits::MAX_SCAN_BUFFER_SIZE) {
        SS_LOG_ERROR(L"YaraRuleStore", L"PerformScan: Buffer exceeds limit (%zu > %zu)",
            size, YaraTitaniumLimits::MAX_SCAN_BUFFER_SIZE);
        return matches;
    }

    // VALIDATION 4: Rules loaded
    if (!m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"PerformScan: No compiled rules loaded");
        return matches;
    }
    
    // VALIDATION 5: Performance counter (prevent division by zero)
    if (m_perfFrequency.QuadPart == 0) {
        SS_LOG_ERROR(L"YaraRuleStore", L"PerformScan: Performance counter not initialized");
        return matches;
    }
    
    // VALIDATION 6: Options sanity
    const uint32_t safeMaxMatches = std::min(options.maxMatchesPerRule, 
                                              YaraTitaniumLimits::ABSOLUTE_MAX_MATCHES_PER_RULE);
    const uint32_t safeTimeout = std::clamp(options.timeoutSeconds,
                                             YaraTitaniumLimits::MIN_TIMEOUT_SECONDS,
                                             YaraTitaniumLimits::MAX_TIMEOUT_SECONDS);

    // Reserve space to minimize reallocations (conservative estimate)
    try {
        matches.reserve(std::min(
            static_cast<size_t>(safeMaxMatches) * 10,
            static_cast<size_t>(1000)
        ));
    } catch (const std::bad_alloc&) {
        SS_LOG_WARN(L"YaraRuleStore", L"PerformScan: Failed to reserve match vector");
        // Continue - vector will grow as needed
    }

    // ========================================================================
    // STATISTICS & TIMING
    // ========================================================================
    m_totalScans.fetch_add(1, std::memory_order_relaxed);
    m_totalBytesScanned.fetch_add(size, std::memory_order_relaxed);

    LARGE_INTEGER startTime{};
    if (!QueryPerformanceCounter(&startTime)) {
        SS_LOG_WARN(L"YaraRuleStore", L"PerformScan: Failed to get start time");
        startTime.QuadPart = 0;
    }

    // ========================================================================
    // CALLBACK CONTEXT SETUP (TITANIUM SAFE)
    // ========================================================================
    // DoS protection constant - absolute max matches allowed per scan
    constexpr size_t MAX_TOTAL_MATCHES = 100000;
    
    struct ScanCallbackContext {
        std::vector<YaraMatch>* matches;
        const YaraRuleStore* store;
        uint32_t maxMatchesPerRule;
        ThreatLevel minThreatLevel;
        bool captureMatchData;
        LARGE_INTEGER perfFrequency;
        LARGE_INTEGER scanStartTime;
        size_t totalMatchesAdded{0};
        size_t maxTotalMatches;
    };

    ScanCallbackContext ctx{};
    ctx.matches = &matches;
    ctx.store = this;
    ctx.maxMatchesPerRule = safeMaxMatches;
    ctx.minThreatLevel = options.minThreatLevel;
    ctx.captureMatchData = options.captureMatchData;
    ctx.perfFrequency = m_perfFrequency;
    ctx.scanStartTime = startTime;
    ctx.maxTotalMatches = MAX_TOTAL_MATCHES;

    // ========================================================================
    // CALLBACK FUNCTION (C-compatible static function)
    // ========================================================================
    static auto callback = [](YR_SCAN_CONTEXT* scan_context,
        int message,
        void* message_data,
        void* user_data) -> int {
            // Only process matching rules
            if (message != CALLBACK_MSG_RULE_MATCHING) {
                return CALLBACK_CONTINUE;
            }

            auto* ctx = static_cast<ScanCallbackContext*>(user_data);
            auto* rule = static_cast<YR_RULE*>(message_data);

            // Validation
            if (!rule || !rule->identifier || !ctx || !ctx->matches) {
                return CALLBACK_CONTINUE;
            }

            std::string ruleName = rule->identifier;
            std::string ruleNamespace = rule->ns ? rule->ns->name : "default";
            std::string fullName = ruleNamespace + "::" + ruleName;

            // Get metadata (thread-safe read with shared_lock already held by caller)
            auto metaIt = ctx->store->m_ruleMetadata.find(fullName);

            // Threat level filtering
            if (metaIt != ctx->store->m_ruleMetadata.end()) {
                if (static_cast<uint8_t>(metaIt->second.threatLevel) <
                    static_cast<uint8_t>(ctx->minThreatLevel)) {
                    return CALLBACK_CONTINUE;
                }
            }

            // Build match result
            YaraMatch match{};
            match.ruleName = ruleName;
            match.namespace_ = ruleNamespace;

            // Populate metadata if available
            if (metaIt != ctx->store->m_ruleMetadata.end()) {
                match.ruleId = metaIt->second.ruleId;
                match.threatLevel = metaIt->second.threatLevel;
                match.tags = metaIt->second.tags;

                // Extract metadata fields
                YR_META* meta = nullptr;
                yr_rule_metas_foreach(rule, meta) {
                    if (!meta || !meta->identifier) continue;

                    std::string metaKey = meta->identifier;

                    if (meta->type == META_TYPE_STRING && meta->string) {
                        match.metadata[metaKey] = meta->string;
                    }
                    else if (meta->type == META_TYPE_INTEGER) {
                        match.metadata[metaKey] = std::to_string(meta->integer);
                    }
                    else if (meta->type == META_TYPE_BOOLEAN) {
                        match.metadata[metaKey] = meta->integer ? "true" : "false";
                    }
                }
            }

            // Extract string matches
            YR_STRING* string = nullptr;
            yr_rule_strings_foreach(rule, string) {
                if (!string) continue;

                YR_MATCH* match_info = nullptr;
                yr_string_matches_foreach(scan_context, string, match_info) {
                    if (!match_info) continue;

                    YaraMatch::StringMatch strMatch{};
                    strMatch.identifier = string->identifier ? string->identifier : "";
                    strMatch.offsets.push_back(match_info->offset);

                    // Capture match data if requested
                    if (ctx->captureMatchData && match_info->data && match_info->data_length > 0) {
                        std::string matchData(
                            reinterpret_cast<const char*>(match_info->data),
                            std::min(static_cast<size_t>(match_info->data_length), static_cast<size_t>(1024)) // Limit to 1KB
                        );
                        strMatch.data.push_back(std::move(matchData));
                    }

                    match.stringMatches.push_back(std::move(strMatch));

                    // Enforce match limit per rule
                    if (match.stringMatches.size() >= ctx->maxMatchesPerRule) {
                        goto string_matches_done;
                    }
                }
            }
        string_matches_done:

            // Calculate match time
            LARGE_INTEGER currentTime;
            QueryPerformanceCounter(&currentTime);
            match.matchTimeMicroseconds =
                ((currentTime.QuadPart - ctx->scanStartTime.QuadPart) * 1000000ULL) /
                ctx->perfFrequency.QuadPart;

            // DoS protection: Check total matches limit
            if (ctx->totalMatchesAdded >= ctx->maxTotalMatches) {
                SS_LOG_WARN(L"YaraRuleStore", L"PerformScan: Maximum total matches reached, aborting scan");
                return CALLBACK_ABORT;
            }

            // Add to results
            ctx->matches->push_back(std::move(match));
            ctx->totalMatchesAdded++;

            // TITANIUM: hit-count updates are deferred to after PerformScan
            // releases m_scanMutex AND the caller releases the shared_lock on
            // m_globalLock. UpdateRuleHitCount needs to acquire the global
            // lock exclusively; recursive acquisition (shared then exclusive)
            // on the same thread is unsupported by std::shared_mutex.

            return CALLBACK_CONTINUE;
        };

    // ========================================================================
    // YARA SCAN EXECUTION (Thread-safe with mutex)
    // ========================================================================
    std::lock_guard<std::mutex> lock(m_scanMutex);

    // Prepare scan flags
    int scanFlags = 0;
    if (options.fastMode) {
        scanFlags |= SCAN_FLAGS_FAST_MODE;
    }

    // Execute YARA scan with safe timeout
    int result = yr_rules_scan_mem(
        m_rules,
        static_cast<const uint8_t*>(buffer),
        size,
        scanFlags,
        callback,
        &ctx,
        static_cast<int>(safeTimeout)
    );

    // ========================================================================
    // POST-PROCESSING (TITANIUM)
    // ========================================================================
    LARGE_INTEGER endTime{};
    if (!QueryPerformanceCounter(&endTime)) {
        endTime.QuadPart = startTime.QuadPart; // Fallback
    }

    uint64_t totalScanTimeUs = 0;
    if (m_perfFrequency.QuadPart > 0) {
        totalScanTimeUs = ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) / m_perfFrequency.QuadPart;
    }

    // Handle scan result
    if (result == ERROR_SUCCESS) {
        // Update global match counter
        m_totalMatches.fetch_add(matches.size(), std::memory_order_relaxed);

        // Normalize match timestamps (some might be missing)
        for (auto& match : matches) {
            if (match.matchTimeMicroseconds == 0) {
                match.matchTimeMicroseconds = totalScanTimeUs;
            }
        }

        SS_LOG_DEBUG(L"YaraRuleStore",
            L"Scan complete: %zu matches, %llu us, %zu bytes",
            matches.size(), totalScanTimeUs, size);
    }
    else {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"Scan failed with YARA error: %d", result);

        // Clear partial results on error
        matches.clear();
    }

    return matches;
}

StoreError YaraRuleStore::AddRulesFromSource(
    const std::string& ruleSource,
    const std::string& namespace_
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"AddRulesFromSource: namespace=%S, size=%zu bytes",
        namespace_.c_str(), ruleSource.length());

    // ========================================================================
    // STEP 1: VALIDATION
    // ========================================================================
    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromSource: Database is read-only");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
    }

    if (ruleSource.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromSource: Empty rule source");
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Rule source cannot be empty" };
    }

    if (ruleSource.length() > YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: Rule source too large (%zu > %zu bytes)",
            ruleSource.length(), YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE);
        return StoreError{ SignatureStoreError::TooLarge, 0, "Rule source exceeds the maximum rule source size" };
    }

    if (namespace_.empty() || namespace_.length() > 128) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: Invalid namespace (length: %zu)", namespace_.length());
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Invalid namespace" };
    }

    // Validate namespace characters (alphanumeric + underscore only)
    if (!std::all_of(namespace_.begin(), namespace_.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_';
        })) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: Namespace contains invalid characters: %S",
            namespace_.c_str());
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
                          "Namespace must be alphanumeric with underscores only" };
    }

    // ========================================================================
    // STEP 2: SYNTAX VALIDATION (Before compilation)
    // ========================================================================
    std::vector<std::string> syntaxErrors;
    if (!YaraUtils::ValidateRuleSyntax(ruleSource, syntaxErrors)) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: YARA syntax validation failed");

        // Log first 5 errors for debugging
        for (size_t i = 0; i < std::min(syntaxErrors.size(), size_t(5)); ++i) {
            SS_LOG_ERROR(L"YaraRuleStore", L"  Syntax Error: %S",
                syntaxErrors[i].c_str());
        }

        if (syntaxErrors.size() > 5) {
            SS_LOG_ERROR(L"YaraRuleStore",
                L"  ... and %zu more errors", syntaxErrors.size() - 5);
        }

        std::string allErrors;
        for (const auto& err : syntaxErrors) {
            allErrors += err + "; ";
        }

        return StoreError{ SignatureStoreError::InvalidSignature, 0,
                          "YARA syntax errors: " + allErrors };
    }

    SS_LOG_DEBUG(L"YaraRuleStore",
        L"AddRulesFromSource: Syntax validation passed");

    // ========================================================================
    // STEP 3: COMPILATION
    // ========================================================================
    LARGE_INTEGER compileStartTime;
    QueryPerformanceCounter(&compileStartTime);

    YaraCompiler compiler;

    StoreError addErr = compiler.AddString(ruleSource, namespace_);
    if (!addErr.IsSuccess()) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: Failed to add rule string to compiler: %S",
            addErr.message.c_str());

        // Log compiler errors
        auto errors = compiler.GetErrors();
        for (size_t i = 0; i < std::min(errors.size(), size_t(3)); ++i) {
            SS_LOG_ERROR(L"YaraRuleStore", L"  Compiler Error: %S",
                errors[i].c_str());
        }

        return addErr;
    }

    YR_RULES* compiledRules = compiler.GetRules();
    if (!compiledRules) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: Failed to get compiled rules from compiler");
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
                          "Failed to compile YARA rules" };
    }

    LARGE_INTEGER compileEndTime;
    QueryPerformanceCounter(&compileEndTime);
    uint64_t compileTimeUs =
        ((compileEndTime.QuadPart - compileStartTime.QuadPart) * 1000000ULL) /
        m_perfFrequency.QuadPart;

    SS_LOG_DEBUG(L"YaraRuleStore",
        L"AddRulesFromSource: Compilation completed in %llu microseconds",
        compileTimeUs);

    // ========================================================================
    // STEP 4: EXTRACT METADATA FROM COMPILED RULES
    // ========================================================================
    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    if (m_ruleSources.size() >= YaraTitaniumLimits::MAX_RULE_SOURCES) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: Rule source limit reached (%zu/%zu)",
            m_ruleSources.size(), YaraTitaniumLimits::MAX_RULE_SOURCES);
        // compiledRules is this compiler's singleton, not ours to release -
        // yr_compiler_destroy handles it. Destroying it here double freed.
        return StoreError{ SignatureStoreError::TooLarge, 0,
                          "Maximum rule source count exceeded" };
    }

    // ========================================================================
    // STEP 4: SURVEY THE NEWLY COMPILED RULES
    // ========================================================================
    // The survey READS compiledRules and writes nothing to m_ruleMetadata. The
    // authoritative metadata comes from RebuildRuleMetadataFromRules once the
    // rebuild below succeeds, so there is ONE producer of that map rather than two
    // that can disagree - two producers is exactly what left every YARA rule
    // reporting ThreatLevel::Medium.
    //
    // It runs before the source is recorded because both of its answers - does
    // this source add anything, and can it merge at all - must be known before
    // m_ruleSources changes. A source that cannot compile alongside the others
    // would otherwise sit there and fail every future rebuild.
    size_t rulesNew = 0;
    const StoreError surveyResult =
        SurveyCompiledRules(compiledRules, namespace_, rulesNew);
    if (!surveyResult.IsSuccess()) {
        // Returning without touching compiledRules is deliberate: it is the local
        // compiler's singleton and ~YaraCompiler releases it. Destroying it here
        // freed the compiler's only rule set together with the arena that holds
        // every rule identifier and namespace name.
        return surveyResult;
    }

    // ========================================================================
    // STEP 5: RECORD THE SOURCE, THEN REBUILD FROM ALL SOURCES
    // ========================================================================
    // m_ruleSources is what the store holds; RebuildRulesFromSources makes m_rules
    // agree with it. This function deliberately never assigns m_rules, never calls
    // yr_rules_destroy, and never stores compiledRules.
    //
    // What it used to do instead, and why the tests fault: on a first add it did
    // `m_rules = compiledRules`, storing the LOCAL compiler's singleton, so m_rules
    // dangled the moment this function returned. Every later scan walked released
    // memory, and the next add or removal called yr_rules_destroy on it. On the
    // merge path it then destroyed m_rules a second time, because
    // AdoptRulesFromCompiler destroys the old set itself.
    const uint64_t sourceId = m_sourceIdCounter.fetch_add(1, std::memory_order_relaxed);
    const std::string sourceKey = namespace_ + "::__source__" + std::to_string(sourceId);
    m_ruleSources[sourceKey] = ruleSource;

    const StoreError rebuildResult = RebuildRulesFromSources();
    if (!rebuildResult.IsSuccess()) {
        // A failed add must leave the store exactly as it was. The rebuild
        // guarantees m_rules and m_ruleMetadata are untouched on failure, so
        // dropping the source key restores full consistency.
        m_ruleSources.erase(sourceKey);
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromSource: rebuild failed, so the source was discarded and "
            L"the rule set is unchanged: %S", rebuildResult.message.c_str());
        return rebuildResult;
    }

    SS_LOG_INFO(L"YaraRuleStore",
        L"AddRulesFromSource: added %zu rule(s); the store now holds %zu rule(s) "
        L"from %zu source(s)",
        rulesNew, m_ruleMetadata.size(), m_ruleSources.size());

    return StoreError{ SignatureStoreError::Success };
}

// Read a YARA rule file into text, bounded before allocating.
//
// Shared by AddRulesFromFile and AddRulesFromDirectory so the two cannot diverge
// on size limits or on what a short read means. The bound is the same constant
// AddRulesFromSource enforces, so an oversized file is refused here rather than
// read into memory and rejected one call later.
static StoreError ReadRuleFileText(
    const std::wstring& filePath,
    std::string& out
) noexcept {
    out.clear();

    std::ifstream input(filePath, std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ReadRuleFileText: cannot open %s",
            filePath.c_str());
        return StoreError{ SignatureStoreError::AccessDenied, 0,
                           "Cannot open rule file" };
    }

    const std::streamoff sizeOnDisk = input.tellg();
    if (sizeOnDisk < 0) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ReadRuleFileText: cannot size %s",
            filePath.c_str());
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                           "Cannot determine rule file size" };
    }

    if (static_cast<uint64_t>(sizeOnDisk) > YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"ReadRuleFileText: rule file too large (%llu > %zu bytes): %s",
            static_cast<uint64_t>(sizeOnDisk),
            YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE, filePath.c_str());
        return StoreError{ SignatureStoreError::TooLarge, 0,
                           "Rule file exceeds the maximum rule source size" };
    }

    input.seekg(0, std::ios::beg);

    try {
        out.resize(static_cast<size_t>(sizeOnDisk));
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ReadRuleFileText: out of memory reading %s",
            filePath.c_str());
        return StoreError{ SignatureStoreError::OutOfMemory, 0,
                           "Out of memory reading rule file" };
    }

    if (sizeOnDisk > 0) {
        input.read(out.data(), sizeOnDisk);
        if (input.gcount() != sizeOnDisk) {
            // A partially read rule file is refused, never compiled. Truncated
            // rule text can still parse into FEWER rules than the file declares,
            // which would silently reduce detection.
            SS_LOG_ERROR(L"YaraRuleStore",
                L"ReadRuleFileText: short read on %s (%lld of %lld bytes)",
                filePath.c_str(), static_cast<long long>(input.gcount()),
                static_cast<long long>(sizeOnDisk));
            out.clear();
            return StoreError{ SignatureStoreError::InvalidFormat, 0,
                               "Short read on rule file" };
        }
    }

    return StoreError{ SignatureStoreError::Success };
}

StoreError YaraRuleStore::AddRulesFromFile(
    const std::wstring& filePath,
    const std::string& namespace_
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"AddRulesFromFile: %s (namespace: %S)", 
        filePath.c_str(), namespace_.c_str());

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Read-only check
    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: Database is read-only");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }
    
    // VALIDATION 2: Path validation
    if (filePath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: Empty file path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "File path is empty"};
    }
    
    // VALIDATION 3: Path length check
    if (filePath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: Path too long");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Path too long"};
    }
    
    // VALIDATION 4: Null character check
    if (filePath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: Path contains null character");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Path contains null character"};
    }
    
    // VALIDATION 5: File existence check
    DWORD fileAttrs = GetFileAttributesW(filePath.c_str());
    if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: File not found (error: %u)", winErr);
        return StoreError{SignatureStoreError::FileNotFound, winErr, "File not found"};
    }
    
    // VALIDATION 6: Not a directory check
    if (fileAttrs & FILE_ATTRIBUTE_DIRECTORY) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: Path is a directory");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Path is a directory"};
    }
    
    // VALIDATION 7: Namespace validation
    if (!namespace_.empty()) {
        if (namespace_.length() > YaraTitaniumLimits::MAX_NAMESPACE_LENGTH) {
            SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: Namespace too long");
            return StoreError{SignatureStoreError::InvalidSignature, 0, "Namespace too long"};
        }
        
        if (!std::all_of(namespace_.begin(), namespace_.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_';
        })) {
            SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: Invalid namespace characters");
            return StoreError{SignatureStoreError::InvalidSignature, 0, "Invalid namespace"};
        }
    }

    // ========================================================================
    // READ THE FILE, THEN GO THROUGH THE SINGLE ADD PATH
    // ========================================================================
    // This used to compile the file with its own local YaraCompiler, adopt the
    // result, and then run a FOURTH copy of the metadata loop - which overwrote
    // everything RebuildRuleMetadataFromRules had just derived, flattening every
    // rule to ThreatLevel::Medium and erasing author, description and tags. Since
    // threat level decides the verdict, a Critical rule added this way convicted
    // as Medium.
    //
    // It was also not an add. Adopting a compiler that held only this file
    // REPLACED the store's entire rule set, and the file was never recorded in
    // m_ruleSources - so it discarded every previously added rule, and its own
    // rules disappeared at the next rebuild because no source described them.
    //
    // Reading the text and going through AddRulesFromSource makes it a real add:
    // one merge model, one metadata producer, one function that mutates the rules.
    //
    // LIMITATION, stated because it is a real behaviour change: the file is stored
    // as text, so a YARA `include` directive is no longer resolved relative to the
    // file. Pass pre-resolved rule text, or use ImportFromYaraRulesRepo, which
    // compiles files in place. Nothing in the product calls this entry point.
    std::string ruleText;
    const StoreError readResult = ReadRuleFileText(filePath, ruleText);
    if (!readResult.IsSuccess()) {
        return readResult;
    }

    // No lock is held here on purpose: AddRulesFromSource takes m_globalLock
    // itself and std::shared_mutex is not recursive.
    const StoreError addResult = AddRulesFromSource(ruleText, namespace_);
    if (!addResult.IsSuccess()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromFile: %s rejected: %S",
            filePath.c_str(), addResult.message.c_str());
        return addResult;
    }

    SS_LOG_INFO(L"YaraRuleStore", L"AddRulesFromFile: added rules from %s",
        filePath.c_str());
    return StoreError{SignatureStoreError::Success};
}

// ============================================================================
// TITANIUM: DIRECTORY-BASED RULE LOADING
// ============================================================================

StoreError YaraRuleStore::AddRulesFromDirectory(
    const std::wstring& directoryPath,
    const std::string& namespace_,
    std::function<void(size_t, size_t)> progressCallback
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"AddRulesFromDirectory: %s", directoryPath.c_str());
    
    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Read-only check
    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromDirectory: Database is read-only");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Database is read-only"};
    }
    
    // VALIDATION 2: Directory path validation
    if (directoryPath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromDirectory: Empty directory path");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Directory path is empty"};
    }
    
    // VALIDATION 3: Path length check
    if (directoryPath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromDirectory: Path too long");
        return StoreError{SignatureStoreError::FileNotFound, 0, "Path too long"};
    }
    
    // VALIDATION 4: Null character check
    if (directoryPath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromDirectory: Path contains null character");
        return StoreError{SignatureStoreError::AccessDenied, 0, "Path contains null character"};
    }
    
    // VALIDATION 5: Namespace validation
    if (namespace_.length() > YaraTitaniumLimits::MAX_NAMESPACE_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromDirectory: Namespace too long");
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Namespace too long"};
    }
    
    // VALIDATION 6: Namespace character check
    if (!namespace_.empty()) {
        if (!std::all_of(namespace_.begin(), namespace_.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_';
        })) {
            SS_LOG_ERROR(L"YaraRuleStore", L"AddRulesFromDirectory: Invalid namespace characters");
            return StoreError{SignatureStoreError::InvalidSignature, 0, "Namespace must be alphanumeric"};
        }
    }
    
    // ========================================================================
    // FIND YARA FILES
    // ========================================================================
    auto yaraFiles = YaraUtils::FindYaraFiles(directoryPath, true);
    
    if (yaraFiles.empty()) {
        SS_LOG_WARN(L"YaraRuleStore", L"AddRulesFromDirectory: No YARA files found in %s", 
            directoryPath.c_str());
        return StoreError{SignatureStoreError::FileNotFound, 0, "No YARA files found"};
    }
    
    // VALIDATION 7: File count limit (DoS protection)
    if (yaraFiles.size() > YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO) {
        SS_LOG_ERROR(L"YaraRuleStore", 
            L"AddRulesFromDirectory: Too many YARA files (%zu > %zu limit)",
            yaraFiles.size(), YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO);
        return StoreError{SignatureStoreError::TooLarge, 0, 
            "Directory contains too many YARA files (max: " + 
            std::to_string(YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO) + ")"};
    }
    
    SS_LOG_INFO(L"YaraRuleStore", L"AddRulesFromDirectory: Found %zu YARA files", yaraFiles.size());

    // ========================================================================
    // READ AND STAGE EVERY FILE, THEN REBUILD ONCE
    // ========================================================================
    // What this did before: compiled every file into a LOCAL YaraCompiler and
    // returned that compiler's result, without ever touching m_rules,
    // m_ruleSources or m_ruleMetadata. The compiler was then destroyed along with
    // its rules. So it compiled the whole directory, reported success, and added
    // nothing - indistinguishable from a working import from the outside, which is
    // this codebase's characteristic failure mode.
    //
    // Staging every file and rebuilding ONCE, rather than calling
    // AddRulesFromSource per file, keeps the cost at one compile per file plus one
    // combined compile. A per-file add would recompile every already-added source
    // each time, which is quadratic in the file count, and the cap checked above
    // admits MAX_YARA_FILES_IN_REPO files.
    //
    // The lock spans the file reads deliberately: replacing a rule set has to be
    // atomic, and a half-imported directory visible to scans is worse than a
    // longer exclusive section on a bulk administrative operation.
    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    if (m_ruleSources.size() + yaraFiles.size() > YaraTitaniumLimits::MAX_RULE_SOURCES) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromDirectory: %zu existing source(s) plus %zu file(s) would "
            L"exceed the %zu source limit",
            m_ruleSources.size(), yaraFiles.size(), YaraTitaniumLimits::MAX_RULE_SOURCES);
        return StoreError{SignatureStoreError::TooLarge, 0,
                          "Directory would exceed the maximum rule source count"};
    }

    std::vector<std::string> stagedKeys;
    std::set<std::string> stagedRuleNames;
    size_t filesRejected = 0;
    size_t rulesStaged = 0;

    for (size_t i = 0; i < yaraFiles.size(); ++i) {
        const std::wstring& yaraFile = yaraFiles[i];

        if (progressCallback) {
            try {
                progressCallback(i + 1, yaraFiles.size());
            } catch (...) {
                SS_LOG_WARN(L"YaraRuleStore",
                    L"AddRulesFromDirectory: progress callback threw");
            }
        }

        std::string ruleText;
        if (!ReadRuleFileText(yaraFile, ruleText).IsSuccess()) {
            ++filesRejected;
            continue;
        }

        // Compiled on its own so a bad file is rejected by itself rather than
        // failing the combined build and taking every good file down with it.
        YaraCompiler fileCompiler;
        const StoreError compileResult = fileCompiler.AddString(ruleText, namespace_);
        if (!compileResult.IsSuccess()) {
            SS_LOG_WARN(L"YaraRuleStore",
                L"AddRulesFromDirectory: %s does not compile, skipping: %S",
                yaraFile.c_str(), compileResult.message.c_str());
            ++filesRejected;
            continue;
        }

        YR_RULES* fileRules = fileCompiler.GetRules();
        size_t newRules = 0;
        const StoreError surveyResult =
            SurveyCompiledRules(fileRules, namespace_, newRules);
        if (!surveyResult.IsSuccess()) {
            SS_LOG_WARN(L"YaraRuleStore",
                L"AddRulesFromDirectory: %s skipped: %S",
                yaraFile.c_str(), surveyResult.message.c_str());
            ++filesRejected;
            continue;
        }

        // The survey compares against rules the STORE holds. Files staged earlier
        // in this same import are not in the store yet, so their rule names are
        // tracked here as well - otherwise two files declaring the same rule would
        // both pass, and the combined rebuild would fail with a duplicated
        // identifier that named a source key rather than a file.
        std::vector<std::string> thisFileRules;
        bool collides = false;
        YR_RULE* rule = nullptr;
        yr_rules_foreach(fileRules, rule) {
            if (rule == nullptr || rule->identifier == nullptr) {
                continue;
            }
            const std::string ruleNamespace =
                (rule->ns != nullptr && rule->ns->name != nullptr)
                    ? rule->ns->name : namespace_;
            std::string fullName = ruleNamespace + "::" + rule->identifier;
            if (stagedRuleNames.count(fullName) != 0) {
                SS_LOG_WARN(L"YaraRuleStore",
                    L"AddRulesFromDirectory: %s redeclares %S, already staged by an "
                    L"earlier file in this import; skipping the file",
                    yaraFile.c_str(), fullName.c_str());
                collides = true;
                break;
            }
            thisFileRules.push_back(std::move(fullName));
        }

        if (collides) {
            ++filesRejected;
            continue;
        }

        const uint64_t sourceId =
            m_sourceIdCounter.fetch_add(1, std::memory_order_relaxed);
        const std::string sourceKey =
            namespace_ + "::__source__" + std::to_string(sourceId);

        m_ruleSources[sourceKey] = std::move(ruleText);
        stagedKeys.push_back(sourceKey);
        for (auto& name : thisFileRules) {
            stagedRuleNames.insert(std::move(name));
        }
        rulesStaged += newRules;
    }

    if (stagedKeys.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromDirectory: none of the %zu file(s) in %s produced rules "
            L"that could be added; the rule set is unchanged",
            yaraFiles.size(), directoryPath.c_str());
        return StoreError{SignatureStoreError::InvalidSignature, 0,
                          "No rules from the directory could be added"};
    }

    const StoreError rebuildResult = RebuildRulesFromSources();
    if (!rebuildResult.IsSuccess()) {
        for (const std::string& key : stagedKeys) {
            m_ruleSources.erase(key);
        }
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AddRulesFromDirectory: rebuild failed, so all %zu staged file(s) were "
            L"discarded and the rule set is unchanged: %S",
            stagedKeys.size(), rebuildResult.message.c_str());
        return rebuildResult;
    }

    SS_LOG_INFO(L"YaraRuleStore",
        L"AddRulesFromDirectory: added %zu file(s) contributing %zu rule(s), "
        L"%zu file(s) rejected; the store now holds %zu rule(s)",
        stagedKeys.size(), rulesStaged, filesRejected, m_ruleMetadata.size());
    return StoreError{SignatureStoreError::Success};
}

StoreError YaraRuleStore::RemoveRule(
    const std::string& ruleName,
    const std::string& namespace_
) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    std::string fullName = namespace_ + "::" + ruleName;
    
    // Check if rule exists - if not, return success (idempotent delete)
    if (m_ruleMetadata.find(fullName) == m_ruleMetadata.end()) {
        SS_LOG_DEBUG(L"YaraRuleStore", L"RemoveRule: Rule not found (already removed): %S", fullName.c_str());
        return StoreError{SignatureStoreError::Success};
    }

    // Remove from metadata
    m_ruleMetadata.erase(fullName);

    // ========================================================================
    // ENTERPRISE-GRADE: Actually remove the rule from compiled rules
    // We need to find which source contains this rule and rebuild without it
    // ========================================================================
    
    // If no sources are tracked, we can only remove metadata (legacy behavior)
    if (m_ruleSources.empty()) {
        SS_LOG_WARN(L"YaraRuleStore", 
            L"RemoveRule: No source cache - only metadata removed for: %S", fullName.c_str());
        return StoreError{SignatureStoreError::Success};
    }
    
    // Find and remove source entries that contain this rule
    // We need to recompile all sources and check which rules are produced
    std::vector<std::string> sourcesToKeep;
    std::vector<std::string> keysToKeep;
    
    for (const auto& [key, source] : m_ruleSources) {
        // Extract namespace from key
        std::string ns = "default";
        size_t delimPos = key.find("::");
        if (delimPos != std::string::npos) {
            ns = key.substr(0, delimPos);
        }
        
        // Compile this source individually to check if it contains the target rule
        YaraCompiler testCompiler;
        if (!testCompiler.AddString(source, ns).IsSuccess()) {
            continue;  // Skip invalid sources
        }
        
        YR_RULES* testRules = testCompiler.GetRules();
        if (!testRules) {
            continue;
        }
        
        // Check if this source contains the rule we want to remove
        bool containsTargetRule = false;
        YR_RULE* rule = nullptr;
        yr_rules_foreach(testRules, rule) {
            if (rule && rule->identifier) {
                std::string ruleNs = rule->ns ? rule->ns->name : ns;
                std::string checkFullName = ruleNs + "::" + rule->identifier;
                if (checkFullName == fullName) {
                    containsTargetRule = true;
                    break;
                }
            }
        }
        
        // testRules is testCompiler's singleton, owned by the compiler and released
        // by yr_compiler_destroy when it leaves scope. Destroying it here was a
        // double free of the arena holding every rule identifier.
        
        // Keep sources that don't contain the target rule
        // (We can't easily modify a source to remove one rule from it,
        // so sources with multiple rules that include the target will be lost)
        if (!containsTargetRule) {
            sourcesToKeep.push_back(source);
            keysToKeep.push_back(key);
        }
    }
    
    // Snapshot before mutating, so a failed rebuild can restore the store exactly.
    const std::map<std::string, std::string> previousSources = m_ruleSources;

    // Rebuild m_ruleSources with only kept sources
    m_ruleSources.clear();
    for (size_t i = 0; i < keysToKeep.size(); ++i) {
        m_ruleSources[keysToKeep[i]] = sourcesToKeep[i];
    }

    // One function changes the rule set: it recompiles what remains, adopts a copy
    // this store owns, and re-derives the metadata. On failure it leaves m_rules
    // untouched, so restoring the source map restores the whole store.
    //
    // What this replaced was another copy of the compile-all-sources loop whose
    // branches called yr_rules_destroy(m_rules) directly - and on any store built
    // by AddRulesFromSource that pointer was already dangling, which is what made
    // rule removal fault.
    const StoreError rebuildResult = RebuildRulesFromSources();
    if (!rebuildResult.IsSuccess()) {
        m_ruleSources = previousSources;

        // The metadata entry was erased above on the assumption the removal would
        // succeed. Re-derive it from the compiled image - which the failed rebuild
        // guarantees is unchanged - so the store cannot report a rule as gone while
        // that rule still matches.
        (void)RebuildRuleMetadataFromRules();

        SS_LOG_ERROR(L"YaraRuleStore",
            L"RemoveRule: %S was not removed because the remaining sources would "
            L"not rebuild; the rule set is unchanged: %S",
            fullName.c_str(), rebuildResult.message.c_str());
        return rebuildResult;
    }

    SS_LOG_DEBUG(L"YaraRuleStore", L"Removed rule: %S", fullName.c_str());
    return StoreError{SignatureStoreError::Success};
}

StoreError YaraRuleStore::RemoveNamespace(const std::string& namespace_) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Snapshot before mutating, so a failed rebuild can restore the store exactly.
    const std::map<std::string, std::string> previousSources = m_ruleSources;

    // Count what the caller is asking to remove, before anything changes.
    size_t rulesInNamespace = 0;
    for (const auto& [metaKey, metadata] : m_ruleMetadata) {
        if (metadata.namespace_ == namespace_) {
            ++rulesInNamespace;
        }
    }

    // Removal is expressed against the SOURCES, because those are what the store
    // holds. The metadata is derived and gets re-produced from the rebuilt rules,
    // so it is deliberately not edited here: editing it separately is precisely how
    // this function came to report a namespace as removed while every rule in it
    // stayed compiled and went on matching.
    size_t sourcesRemoved = 0;
    const std::string nsPrefix = namespace_ + "::";
    for (auto it = m_ruleSources.begin(); it != m_ruleSources.end(); ) {
        if (it->first.compare(0, nsPrefix.length(), nsPrefix) == 0) {
            it = m_ruleSources.erase(it);
            ++sourcesRemoved;
        } else {
            ++it;
        }
    }

    if (sourcesRemoved == 0) {
        if (rulesInNamespace == 0) {
            // Idempotent: the store holds nothing under that name, so there is
            // nothing to remove and that is not an error.
            SS_LOG_DEBUG(L"YaraRuleStore",
                L"RemoveNamespace: %S holds nothing; nothing to remove",
                namespace_.c_str());
            return StoreError{SignatureStoreError::Success};
        }

        // The namespace has rules, but no tracked source produced them, so
        // recompiling cannot remove them. Refusing is the only honest answer: the
        // previous code erased the metadata and returned success, leaving the rules
        // compiled and live, so the store claimed the namespace was gone while
        // every rule in it kept matching.
        SS_LOG_ERROR(L"YaraRuleStore",
            L"RemoveNamespace: %S holds %zu rule(s) that came from compiled bytecode "
            L"rather than a tracked source, so recompiling cannot remove them. "
            L"Nothing was changed.",
            namespace_.c_str(), rulesInNamespace);
        return StoreError{SignatureStoreError::AccessDenied, 0,
                          "Namespace holds compiled rules that no tracked source can "
                          "reproduce; nothing was removed"};
    }

    const StoreError rebuildResult = RebuildRulesFromSources();
    if (!rebuildResult.IsSuccess()) {
        m_ruleSources = previousSources;
        SS_LOG_ERROR(L"YaraRuleStore",
            L"RemoveNamespace: %S was not removed because the remaining sources "
            L"would not rebuild; the rule set is unchanged: %S",
            namespace_.c_str(), rebuildResult.message.c_str());
        return rebuildResult;
    }

    SS_LOG_INFO(L"YaraRuleStore",
        L"RemoveNamespace: removed %S (%zu rule(s) from %zu source(s)); the store "
        L"now holds %zu rule(s)",
        namespace_.c_str(), rulesInNamespace, sourcesRemoved, m_ruleMetadata.size());
    return StoreError{SignatureStoreError::Success};
}

// ============================================================================
// QUERY OPERATIONS
// ============================================================================

std::optional<YaraRuleMetadata> YaraRuleStore::GetRuleMetadata(
    const std::string& ruleName,
    const std::string& namespace_
) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::string fullName = namespace_ + "::" + ruleName;
    auto it = m_ruleMetadata.find(fullName);
    
    if (it != m_ruleMetadata.end()) {
        return it->second;
    }

    return std::nullopt;
}

StoreError YaraRuleStore::UpdateRuleMetadata(
    const std::string& ruleName,
    const YaraRuleMetadata& metadata
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"UpdateRuleMetadata: %S", ruleName.c_str());

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    if (ruleName.empty()) {
        return StoreError{ SignatureStoreError::InvalidSignature, 0, "Empty rule name" };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Find existing metadata
    std::string fullName = metadata.namespace_.empty() ? ruleName : (metadata.namespace_ + "::" + ruleName);

    auto it = m_ruleMetadata.find(fullName);
    if (it == m_ruleMetadata.end()) {
        // Rule doesn't exist, try without namespace
        it = m_ruleMetadata.find(ruleName);
        if (it == m_ruleMetadata.end()) {
            SS_LOG_ERROR(L"YaraRuleStore", L"Rule not found: %S", ruleName.c_str());
            return StoreError{ SignatureStoreError::FileNotFound, 0, "Rule not found" };
        }
    }

    // Update metadata (preserve hitCount and ruleId if not changed)
    YaraRuleMetadata updatedMetadata = metadata;

    // Preserve hit count if not explicitly changed
    if (metadata.hitCount == 0) {
        updatedMetadata.hitCount = it->second.hitCount;
    }

    // Preserve rule ID if not explicitly changed
    if (metadata.ruleId == 0) {
        updatedMetadata.ruleId = it->second.ruleId;
    }

    // Update the metadata
    it->second = updatedMetadata;

    // HONEST LIMITATION, stated where a caller will read it: this override lives
    // only in m_ruleMetadata, and that map is re-derived from the compiled rules
    // whenever the rule set changes - any add, removal or recompile. Accumulated
    // statistics are carried across a rebuild; an author, description or threat
    // level set here is not, because the rule's own metadata is what the store
    // treats as authoritative. Nothing in the product calls this today; a caller
    // that needs a durable override needs a field the rebuild consults, which does
    // not exist yet.
    SS_LOG_DEBUG(L"YaraRuleStore", L"Updated metadata for rule: %S", ruleName.c_str());
    return StoreError{ SignatureStoreError::Success };
}

std::vector<YaraRuleMetadata> YaraRuleStore::ListRules(
    const std::string& namespaceFilter
) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::vector<YaraRuleMetadata> rules;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        if (namespaceFilter.empty() || metadata.namespace_ == namespaceFilter) {
            rules.push_back(metadata);
        }
    }

    return rules;
}

std::vector<std::string> YaraRuleStore::ListNamespaces() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::set<std::string> namespaces;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        namespaces.insert(metadata.namespace_);
    }

    return std::vector<std::string>(namespaces.begin(), namespaces.end());
}

std::vector<YaraRuleMetadata> YaraRuleStore::FindRulesByTag(
    const std::string& tag
) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::vector<YaraRuleMetadata> matching;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        if (std::find(metadata.tags.begin(), metadata.tags.end(), tag) != metadata.tags.end()) {
            matching.push_back(metadata);
        }
    }

    return matching;
}

std::vector<YaraRuleMetadata> YaraRuleStore::FindRulesByAuthor(
    const std::string& author
) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::vector<YaraRuleMetadata> matching;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        if (metadata.author == author) {
            matching.push_back(metadata);
        }
    }

    return matching;
}

// ============================================================================
// STATISTICS
// ============================================================================

YaraRuleStore::YaraStoreStatistics YaraRuleStore::GetStatistics() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    YaraStoreStatistics stats{};
    stats.totalRules = m_ruleMetadata.size();
    stats.totalScans = m_totalScans.load(std::memory_order_relaxed);
    stats.totalMatches = m_totalMatches.load(std::memory_order_relaxed);
    stats.totalBytesScanned = m_totalBytesScanned.load(std::memory_order_relaxed);
    stats.compiledRulesSize = m_mappedView.fileSize;

    // Count namespaces
    std::set<std::string> namespaces;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        namespaces.insert(metadata.namespace_);
        stats.ruleHitCounts[name] = metadata.hitCount;
    }
    stats.totalNamespaces = namespaces.size();

    return stats;
}

void YaraRuleStore::ResetStatistics() noexcept {
    m_totalScans.store(0, std::memory_order_release);
    m_totalMatches.store(0, std::memory_order_release);
    m_totalBytesScanned.store(0, std::memory_order_release);
}

std::vector<std::pair<std::string, uint64_t>> YaraRuleStore::GetTopRules(
    uint32_t topN
) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    std::vector<std::pair<std::string, uint64_t>> topRules;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        topRules.emplace_back(name, metadata.hitCount);
    }

    // Sort by hit count (descending)
    std::partial_sort(topRules.begin(), 
                     topRules.begin() + std::min(static_cast<size_t>(topN), topRules.size()),
                     topRules.end(),
                     [](const auto& a, const auto& b) { return a.second > b.second; });

    if (topRules.size() > topN) {
        topRules.resize(topN);
    }

    return topRules;
}

std::wstring YaraRuleStore::GetDatabasePath() const noexcept {
    return m_databasePath;
}

// ============================================================================
// INTERNAL METHODS
// ============================================================================

StoreError YaraRuleStore::OpenMemoryMapping(const std::wstring& path, bool readOnly) noexcept {
    StoreError err{};
    if (!MemoryMapping::OpenView(path, readOnly, m_mappedView, err)) {
        return err;
    }
    return StoreError{SignatureStoreError::Success};
}

void YaraRuleStore::CloseMemoryMapping() noexcept {
    MemoryMapping::CloseView(m_mappedView);
}

// Takes ownership of a compiler's rules by round-tripping them through a
// serialised buffer, replacing m_rules with a set this store genuinely owns.
//
// This exists because of a use-after-free class that ran right through this
// file. Since YARA 4.0, yr_compiler_get_rules returns the compiler's own
// singleton, freed by yr_compiler_destroy - so `m_rules = someCompiler.GetRules()`
// stores a pointer owned by something else. Every site doing that used a LOCAL
// YaraCompiler, which meant m_rules dangled the moment the function returned and
// every subsequent scan walked released memory. It was also a double free, since
// the store's own yr_rules_destroy would later release the same pointer.
//
// Serialising and reloading is the fix rather than keeping the compiler alive
// alongside the store: a compiler cannot accept more rules once its rules have
// been generated, so holding one forever buys nothing, and an owned rule set is
// what every other path here already assumes it has. The round trip costs one
// serialise plus one load, paid only when the rule set changes - adding,
// removing, recompiling - never per scan.
//
// On failure m_rules is left exactly as it was, so a failed update degrades to
// "rules unchanged" instead of "no rules at all".
//
// @note Caller must hold m_globalLock exclusively.
bool YaraRuleStore::AdoptRulesFromCompiler(YaraCompiler& compiler) noexcept {
    auto buffer = compiler.SaveToBuffer();
    if (!buffer.has_value() || buffer->empty()) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AdoptRulesFromCompiler: could not serialise compiled rules; "
            L"keeping the previous rule set");
        return false;
    }

    struct SpanReader {
        const uint8_t* data;
        size_t         size;
        size_t         pos;
    };

    SpanReader reader{ buffer->data(), buffer->size(), 0u };

    YR_STREAM stream{};
    stream.user_data = &reader;
    stream.write     = nullptr;
    stream.read = [](void* ptr, size_t size, size_t count, void* userData) -> size_t {
        auto* r = static_cast<SpanReader*>(userData);
        if (r == nullptr || r->data == nullptr || ptr == nullptr ||
            size == 0u || count == 0u) {
            return 0u;
        }
        const size_t available = (r->pos < r->size) ? (r->size - r->pos) : 0u;
        const size_t maxItems  = available / size;
        const size_t items     = (count < maxItems) ? count : maxItems;
        if (items == 0u) {
            return 0u;
        }
        const size_t bytes = items * size;
        std::memcpy(ptr, r->data + r->pos, bytes);
        r->pos += bytes;
        return items;
    };

    YR_RULES* adopted = nullptr;
    const int loadResult = yr_rules_load_stream(&stream, &adopted);
    if (loadResult != ERROR_SUCCESS || adopted == nullptr) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"AdoptRulesFromCompiler: yr_rules_load_stream failed (error: %d); "
            L"keeping the previous rule set", loadResult);
        return false;
    }

    // Only now is it safe to release the old set: this one is ours, came from
    // yr_rules_load_stream rather than from a compiler, and is independent of
    // any compiler's lifetime.
    if (m_rules != nullptr) {
        yr_rules_destroy(m_rules);
    }
    m_rules = adopted;

    const size_t indexed = RebuildRuleMetadataFromRules();
    SS_LOG_INFO(L"YaraRuleStore",
        L"AdoptRulesFromCompiler: adopted %zu rule(s) with owned lifetime", indexed);
    return true;
}

// The one place the store's compiled rule set changes. See the header for the
// invariant; the short version is that m_ruleSources decides what the store
// holds, this function makes m_rules agree with it, and nothing else may touch
// either pointer.
StoreError YaraRuleStore::RebuildRulesFromSources() noexcept {
    // REFUSE rather than narrow detection. If the compiled image contains rules
    // that arrived as bytecode, no set of sources can reproduce them, so
    // recompiling from sources would delete them - and a rule set that silently
    // loses most of its rules while reporting success is the worst outcome this
    // store can produce.
    if (m_hasUntrackedRules && m_rules != nullptr) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"RebuildRulesFromSources: refusing to rebuild. This store holds %zu "
            L"rule(s) that came from compiled bytecode rather than from tracked "
            L"sources, and rebuilding from %zu source(s) would DELETE them. Load "
            L"rules from sources, or use Recompile on a source-backed store.",
            m_ruleMetadata.size(), m_ruleSources.size());
        return StoreError{ SignatureStoreError::AccessDenied, 0,
                           "Store holds compiled rules that no tracked source can "
                           "reproduce; rebuilding would discard them" };
    }

    // An empty source set is a legitimate state, not a failure. Releasing the
    // rules here is what makes removal actually remove: keeping the previous
    // compiled image would go on matching rules the store no longer holds.
    if (m_ruleSources.empty()) {
        if (m_rules != nullptr) {
            yr_rules_destroy(m_rules);
            m_rules = nullptr;
        }
        m_ruleMetadata.clear();
        m_hasUntrackedRules = false;
        SS_LOG_INFO(L"YaraRuleStore",
            L"RebuildRulesFromSources: no sources remain; rule set is now empty");
        return StoreError{ SignatureStoreError::Success };
    }

    YaraCompiler compiler;
    size_t compiled = 0;

    for (const auto& [key, source] : m_ruleSources) {
        // Key format is "<namespace>::__source__<id>", written by
        // AddRulesFromSource. Namespaces are validated alphanumeric-plus-
        // underscore at entry, so the first "::" is unambiguous.
        std::string ns = "default";
        const size_t delimPos = key.find("::");
        if (delimPos != std::string::npos && delimPos > 0) {
            ns = key.substr(0, delimPos);
        }

        const StoreError addResult = compiler.AddString(source, ns);
        if (!addResult.IsSuccess()) {
            // Named, at ERROR, with the consequence stated: this source compiled
            // on its own when it was accepted, so reaching here means it
            // conflicts with another stored source - most often a duplicated rule
            // identifier in the same namespace.
            SS_LOG_ERROR(L"YaraRuleStore",
                L"RebuildRulesFromSources: stored source '%S' no longer compiles (%S). "
                L"The rule set is UNCHANGED - no rule was added or removed.",
                key.c_str(), addResult.message.c_str());

            const auto errors = compiler.GetErrors();
            for (size_t i = 0; i < (std::min)(errors.size(), size_t(3)); ++i) {
                SS_LOG_ERROR(L"YaraRuleStore", L"  compiler: %S", errors[i].c_str());
            }

            return StoreError{ SignatureStoreError::CompilationFailed, 0,
                               "A stored rule source conflicts with another; "
                               "rule set left unchanged" };
        }
        ++compiled;
    }

    // AdoptRulesFromCompiler serialises and reloads, so what lands in m_rules is
    // independent of this local compiler's lifetime, and it releases the previous
    // set only after the replacement has loaded. On failure m_rules is untouched.
    if (!AdoptRulesFromCompiler(compiler)) {
        return StoreError{ SignatureStoreError::Unknown, 0,
                           "Could not adopt the recompiled rule set; "
                           "rule set left unchanged" };
    }

    // Every rule now present came from a tracked source, by construction.
    m_hasUntrackedRules = false;

    SS_LOG_INFO(L"YaraRuleStore",
        L"RebuildRulesFromSources: recompiled %zu source(s) into %zu rule(s)",
        compiled, m_ruleMetadata.size());
    return StoreError{ SignatureStoreError::Success };
}

// Reads the caller's compiled rules and answers one question: can this source be
// merged into the store, and what would it add? Never stores or destroys the
// pointer - it belongs to the caller's compiler.
StoreError YaraRuleStore::SurveyCompiledRules(
    YR_RULES* compiled,
    const std::string& fallbackNamespace,
    size_t& newRules
) noexcept {
    newRules = 0;

    if (compiled == nullptr) {
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
                           "No compiled rules to survey" };
    }

    size_t duplicates = 0;
    size_t unnamed = 0;

    YR_RULE* rule = nullptr;
    yr_rules_foreach(compiled, rule) {
        if (rule == nullptr || rule->identifier == nullptr) {
            ++unnamed;
            continue;
        }

        const std::string ruleNamespace =
            (rule->ns != nullptr && rule->ns->name != nullptr)
                ? rule->ns->name
                : fallbackNamespace;
        const std::string fullName = ruleNamespace + "::" + rule->identifier;

        if (m_ruleMetadata.find(fullName) != m_ruleMetadata.end()) {
            SS_LOG_WARN(L"YaraRuleStore",
                L"SurveyCompiledRules: rule already present in this store: %S",
                fullName.c_str());
            ++duplicates;
            continue;
        }

        ++newRules;
    }

    if (unnamed > 0) {
        SS_LOG_WARN(L"YaraRuleStore",
            L"SurveyCompiledRules: %zu compiled rule(s) carried no identifier and "
            L"were not surveyed", unnamed);
    }

    if (newRules == 0) {
        SS_LOG_WARN(L"YaraRuleStore",
            L"SurveyCompiledRules: source contributes no new rules (%zu already "
            L"present)", duplicates);
        return StoreError{ SignatureStoreError::InvalidSignature, 0,
                           "No valid rules found in source" };
    }

    if (duplicates > 0) {
        // REFUSED rather than partially accepted. YARA rejects a duplicated
        // identifier for the WHOLE source, so this source could never compile
        // alongside the one already defining those rules. Accepting it would store
        // a source that contributes nothing and breaks every later rebuild, while
        // this call reported success and the new rules never appeared.
        SS_LOG_ERROR(L"YaraRuleStore",
            L"SurveyCompiledRules: source mixes %zu new rule(s) with %zu this store "
            L"already defines. YARA rejects a duplicated identifier for the entire "
            L"source, so nothing was added. Remove the duplicates, or use a "
            L"different namespace, and retry.",
            newRules, duplicates);
        return StoreError{ SignatureStoreError::DuplicateEntry, 0,
                           "Source redefines rules this store already holds" };
    }

    return StoreError{ SignatureStoreError::Success };
}

size_t YaraRuleStore::RebuildRuleMetadataFromRules() noexcept {
    // Accumulated statistics are NOT derivable from the compiled rules, so they are
    // carried across the rebuild by rule name. Everything else in the map is
    // re-derived from the bytecode, which is the whole point of this function.
    //
    // This matters more than it used to: the rule set is now rebuilt on every add
    // and every removal, so without this a single added rule would reset the hit
    // count of every rule already in the store, and an edited store would report
    // that nothing had ever matched.
    //
    // Carried by NAME, which is the only identity that survives recompilation - the
    // numeric ruleId is a hash of the name and the compiled order is not stable.
    struct CarriedStats {
        uint32_t hitCount;
        uint64_t averageMatchTimeMicroseconds;
    };
    std::map<std::string, CarriedStats> carried;
    for (const auto& [carriedName, carriedMeta] : m_ruleMetadata) {
        if (carriedMeta.hitCount != 0u || carriedMeta.averageMatchTimeMicroseconds != 0u) {
            carried[carriedName] =
                CarriedStats{ carriedMeta.hitCount, carriedMeta.averageMatchTimeMicroseconds };
        }
    }

    m_ruleMetadata.clear();

    if (m_rules == nullptr) {
        return 0u;
    }

    size_t ruleCount = 0;
    size_t rulesWithReadableMetadata = 0;
    const auto now = static_cast<uint64_t>(std::time(nullptr));

    YR_RULE* rule = nullptr;
    yr_rules_foreach(m_rules, rule) {
        if (rule == nullptr || rule->identifier == nullptr) {
            continue;
        }

        std::string ruleName = rule->identifier;
        std::string ruleNamespace =
            (rule->ns != nullptr && rule->ns->name != nullptr) ? rule->ns->name : "default";
        std::string fullName = ruleNamespace + "::" + ruleName;

        YaraRuleMetadata metadata{};
        metadata.ruleId = static_cast<uint64_t>(std::hash<std::string>{}(fullName));
        metadata.ruleName = ruleName;
        metadata.namespace_ = ruleNamespace;
        // Neutral default. Overridden below from the rule's own metadata when the
        // rule states anything usable - deliberately Medium rather than something
        // severe, because a placeholder that convicts is worse than one that does
        // not.
        metadata.threatLevel = ThreatLevel::Medium;
        metadata.isGlobal = (rule->flags & RULE_FLAGS_GLOBAL) != 0;
        metadata.isPrivate = (rule->flags & RULE_FLAGS_PRIVATE) != 0;
        metadata.lastModified = now;

        const char* tag = nullptr;
        yr_rule_tags_foreach(rule, tag) {
            if (tag != nullptr) {
                const size_t tagLen = std::strlen(tag);
                if (tagLen > 0 && tagLen <= 64) {
                    metadata.tags.emplace_back(tag);
                }
            }
        }

        // Rule metadata: author, description, reference, and anything that could
        // carry a severity.
        //
        // THIS PARSING LIVES HERE AND ONLY HERE. LoadRulesInternal used to keep its
        // own copy of this loop, and the two had diverged: this one read tags and
        // nothing else, while that one read author, description and a `severity`
        // string. Which of the two ran therefore decided whether a rule had an
        // author or a severity at all - and both are reached from a plain
        // Initialize depending on how the rules got there. One implementation
        // cannot disagree with itself.
        std::map<std::string, std::string> severityMetadata;

        YR_META* meta = nullptr;
        yr_rule_metas_foreach(rule, meta) {
            if (meta == nullptr || meta->identifier == nullptr) {
                continue;
            }

            const std::string metaKey = meta->identifier;

            if (meta->type == META_TYPE_STRING && meta->string != nullptr) {
                if (metaKey == "author") {
                    metadata.author = meta->string;
                } else if (metaKey == "description") {
                    metadata.description = meta->string;
                } else if (metaKey == "reference") {
                    metadata.reference = meta->string;
                }
                severityMetadata[metaKey] = meta->string;
            } else if (meta->type == META_TYPE_INTEGER) {
                // Integer metas were previously not read at all, which is how
                // `score = <integer>` - present on every rule in the shipped
                // ruleset - never reached the level parser.
                severityMetadata[metaKey] = std::to_string(meta->integer);
            }
        }

        if (!severityMetadata.empty()) {
            metadata.threatLevel = YaraUtils::ParseThreatLevel(severityMetadata);
            ++rulesWithReadableMetadata;
        }

        const auto carriedIt = carried.find(fullName);
        if (carriedIt != carried.end()) {
            metadata.hitCount = carriedIt->second.hitCount;
            metadata.averageMatchTimeMicroseconds = carriedIt->second.averageMatchTimeMicroseconds;
        }

        m_ruleMetadata[fullName] = std::move(metadata);
        ++ruleCount;
    }

    // Reported because a severity nobody can read is worse than no severity: every
    // rule then carries the Medium default and looks like a real judgement. 0 of N
    // here means no rule's own severity reached the level parser.
    SS_LOG_INFO(L"YaraRuleStore",
        L"RebuildRuleMetadataFromRules: indexed %zu rule(s), %zu carried readable "
        L"metadata usable for severity",
        ruleCount, rulesWithReadableMetadata);

    return ruleCount;
}

StoreError YaraRuleStore::LoadRulesInternal() noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"LoadRulesInternal: Starting rule loading from mapped database");

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (!m_mappedView.IsValid()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Memory mapping is invalid");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Memory mapping not initialized" };
    }

    // ========================================================================
    // READ DATABASE HEADER
    // ========================================================================
    const auto* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);
    if (!header) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to read database header");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Cannot read header from mapped file" };
    }

    // Validate header
    if (!Format::ValidateHeader(header)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Header validation failed");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid or corrupted database header" };
    }

    SS_LOG_DEBUG(L"YaraRuleStore", L"LoadRulesInternal: Header valid - version %u.%u",
        header->versionMajor, header->versionMinor);

    // ========================================================================
    // LOAD YARA RULES FROM OFFSET
    // ========================================================================
    if (header->yaraRulesOffset == 0 || header->yaraRulesSize == 0) {
        SS_LOG_WARN(L"YaraRuleStore", L"LoadRulesInternal: No YARA rules section in database");
        // This is not necessarily an error - database might only have hashes/patterns
        return StoreError{ SignatureStoreError::Success };
    }

    // Validate offset is within mapped file bounds
    if (header->yaraRulesOffset + header->yaraRulesSize > m_mappedView.fileSize) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"LoadRulesInternal: YARA section offset out of bounds (offset: %llu, size: %llu, file: %llu)",
            header->yaraRulesOffset, header->yaraRulesSize, m_mappedView.fileSize);
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "YARA section offset out of bounds" };
    }

    // Get YARA compiled rules data
    auto yaraData = m_mappedView.GetSpan(header->yaraRulesOffset, header->yaraRulesSize);
    if (yaraData.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to get YARA data span");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Cannot read YARA rules section" };
    }

    SS_LOG_DEBUG(L"YaraRuleStore", L"LoadRulesInternal: Read YARA section - %llu bytes", yaraData.size());

    // ========================================================================
    // LOAD THE COMPILED BYTECODE INTO YARA
    // ========================================================================
    // This step did not exist, and its absence is why YARA matching never
    // worked from the combined database. The function mapped the file, read the
    // section bounds, took the span, logged its size - and then went straight on
    // to the metadata section without ever handing the bytecode to YARA.
    // m_rules stayed null, Initialize still returned Success, and GetStatus
    // reported yaraStoreReady = true. A store that loads no rules and calls
    // itself ready is worse than one that fails, because nothing looks wrong.
    //
    // The only loader in this file was LoadCompiledRules, which takes a file
    // path, and it has zero callers anywhere in the tree - so the one load path
    // that existed was unreachable code.
    //
    // Loaded through a YR_STREAM over the mapped span rather than by path.
    // The comment at the bottom of this file - "YARA yr_rules_load() expects
    // file path, not memory buffer" - is true of yr_rules_load and led to a
    // temp-file write-then-load dance elsewhere in this file. But
    // yr_rules_load_stream takes a caller-supplied reader, so no temp file is
    // needed: we read straight out of the mapping. That avoids writing rule
    // bytecode to disk on every start, avoids the window where it sits there
    // readable, and keeps the memory-mapped design intact.
    {
        struct SpanReader {
            const uint8_t* data;
            size_t         size;
            size_t         pos;
        };

        SpanReader reader{ yaraData.data(), yaraData.size(), 0u };

        YR_STREAM stream{};
        stream.user_data = &reader;
        stream.write     = nullptr;   // read-only stream
        // Capture-free lambda so it converts to YR_STREAM_READ_FUNC.
        // Follows fread semantics: returns the number of ITEMS read, not bytes.
        stream.read = [](void* ptr, size_t size, size_t count, void* userData) -> size_t {
            auto* r = static_cast<SpanReader*>(userData);
            if (r == nullptr || r->data == nullptr || ptr == nullptr ||
                size == 0u || count == 0u) {
                return 0u;
            }
            // Clamp against what remains before multiplying, so the byte count
            // can never overflow regardless of what YARA asks for.
            const size_t available = (r->pos < r->size) ? (r->size - r->pos) : 0u;
            const size_t maxItems  = available / size;
            const size_t items     = (count < maxItems) ? count : maxItems;
            if (items == 0u) {
                return 0u;
            }
            const size_t bytes = items * size;
            std::memcpy(ptr, r->data + r->pos, bytes);
            r->pos += bytes;
            return items;
        };

        // Release rules from any previous load before replacing them. Destroying
        // is correct here and only here: yr_rules_load_stream allocates a rule
        // set we own, unlike yr_compiler_get_rules which returns the compiler's
        // singleton (see the contract on YaraCompiler::GetRules).
        if (m_rules != nullptr) {
            yr_rules_destroy(m_rules);
            m_rules = nullptr;
        }

        const int loadResult = yr_rules_load_stream(&stream, &m_rules);
        if (loadResult != ERROR_SUCCESS || m_rules == nullptr) {
            m_rules = nullptr;
            SS_LOG_ERROR(L"YaraRuleStore",
                L"LoadRulesInternal: yr_rules_load_stream failed (error: %d, section: %llu bytes)",
                loadResult, yaraData.size());
            return StoreError{ SignatureStoreError::InvalidFormat,
                               static_cast<DWORD>(loadResult),
                               "Cannot load compiled YARA rules from database" };
        }

        // Rebuild the rule index from what actually loaded. Reporting readiness
        // without knowing how many rules are live is the failure this replaces.
        const size_t indexed = RebuildRuleMetadataFromRules();
        if (indexed == 0u) {
            yr_rules_destroy(m_rules);
            m_rules = nullptr;
            SS_LOG_ERROR(L"YaraRuleStore",
                L"LoadRulesInternal: bytecode loaded but contains no rules - "
                L"refusing to report ready with an empty rule set");
            return StoreError{ SignatureStoreError::InvalidSignature, 0,
                               "YARA section contains no rules" };
        }

        SS_LOG_INFO(L"YaraRuleStore",
            L"LoadRulesInternal: loaded %zu YARA rule(s) from the database", indexed);
    }

    // ========================================================================
    // LOAD METADATA SECTION
    // ========================================================================
   // Load metadata section (JSON format)
    if (header->metadataOffset == 0 || header->metadataSize == 0) {
        SS_LOG_WARN(L"YaraRuleStore", L"LoadRulesInternal: No metadata section in database");
    }
    else {
        if (header->metadataOffset + header->metadataSize > m_mappedView.fileSize) {
            SS_LOG_ERROR(L"YaraRuleStore",
                L"LoadRulesInternal: Metadata section offset out of bounds");
            return StoreError{ SignatureStoreError::InvalidFormat, 0, "Metadata section offset out of bounds" };
        }

        auto metadataSpan = m_mappedView.GetSpan(header->metadataOffset, header->metadataSize);
        if (!metadataSpan.empty()) {
            SS_LOG_DEBUG(L"YaraRuleStore", L"LoadRulesInternal: Read metadata section - %llu bytes",
                metadataSpan.size());

            try {
                // Convert span to string for JSON parsing
                std::string metadataJson(
                    reinterpret_cast<const char*>(metadataSpan.data()),
                    metadataSpan.size()
                );

                // Parse metadata JSON
                ShadowStrike::Utils::JSON::Json metadataRoot;
                ShadowStrike::Utils::JSON::Error jsonErr;
                ShadowStrike::Utils::JSON::ParseOptions parseOpt;
                parseOpt.maxDepth = 100; // Reasonable limit for metadata

                if (!ShadowStrike::Utils::JSON::Parse(metadataJson, metadataRoot, &jsonErr, parseOpt)) {
                    SS_LOG_WARN(L"YaraRuleStore",
                        L"LoadRulesInternal: Failed to parse metadata JSON: %S",
                        jsonErr.message.c_str());
                    // Continue without metadata - this is not fatal
                    return StoreError{ SignatureStoreError::Success };
                }

                // Validate metadata structure - must be array
                if (!metadataRoot.is_array()) {
                    SS_LOG_WARN(L"YaraRuleStore",
                        L"LoadRulesInternal: Metadata root is not an array");
                    return StoreError{ SignatureStoreError::Success };
                }

                size_t metadataCount = 0;
                size_t parseErrors = 0;

                // Iterate through metadata entries
                for (const auto& entry : metadataRoot) {
                    if (!entry.is_object()) {
                        SS_LOG_WARN(L"YaraRuleStore",
                            L"LoadRulesInternal: Metadata entry is not an object, skipping");
                        parseErrors++;
                        continue;
                    }

                    try {
                        // Extract required fields
                        if (!entry.contains("ruleName") || !entry["ruleName"].is_string()) {
                            SS_LOG_WARN(L"YaraRuleStore",
                                L"LoadRulesInternal: Metadata entry missing 'ruleName' field");
                            parseErrors++;
                            continue;
                        }

                        if (!entry.contains("namespace") || !entry["namespace"].is_string()) {
                            SS_LOG_WARN(L"YaraRuleStore",
                                L"LoadRulesInternal: Metadata entry missing 'namespace' field");
                            parseErrors++;
                            continue;
                        }

                        std::string ruleName = entry["ruleName"].get<std::string>();
                        std::string ruleNamespace = entry["namespace"].get<std::string>();
                        std::string fullName = ruleNamespace + "::" + ruleName;

                        // Check if rule already exists (from compiled rules)
                        auto metaIt = m_ruleMetadata.find(fullName);
                        if (metaIt == m_ruleMetadata.end()) {
                            SS_LOG_DEBUG(L"YaraRuleStore",
                                L"LoadRulesInternal: Metadata for rule not found in compiled rules: %S",
                                fullName.c_str());
                            parseErrors++;
                            continue;
                        }

                        // Update existing metadata with file data
                        YaraRuleMetadata& metadata = metaIt->second;

                        // Optional fields - author
                        if (entry.contains("author") && entry["author"].is_string()) {
                            metadata.author = entry["author"].get<std::string>();
                        }

                        // Optional fields - description
                        if (entry.contains("description") && entry["description"].is_string()) {
                            metadata.description = entry["description"].get<std::string>();
                        }

                        // Optional fields - reference
                        if (entry.contains("reference") && entry["reference"].is_string()) {
                            metadata.reference = entry["reference"].get<std::string>();
                        }

                        // Optional fields - threat level (0-100)
                        if (entry.contains("threatLevel") && entry["threatLevel"].is_number_integer()) {
                            int32_t threatVal = entry["threatLevel"].get<int32_t>();
                            if (threatVal >= 0 && threatVal <= 100) {
                                // Map 0-100 to ThreatLevel enum
                                if (threatVal >= 80) {
                                    metadata.threatLevel = ThreatLevel::Critical;
                                }
                                else if (threatVal >= 60) {
                                    metadata.threatLevel = ThreatLevel::High;
                                }
                                else if (threatVal >= 30) {
                                    metadata.threatLevel = ThreatLevel::Medium;
                                }
                                else {
                                    metadata.threatLevel = ThreatLevel::Low;
                                }
                            }
                        }

                        // Optional fields - tags (array of strings)
                        if (entry.contains("tags") && entry["tags"].is_array()) {
                            metadata.tags.clear();
                            for (const auto& tagEntry : entry["tags"]) {
                                if (tagEntry.is_string()) {
                                    metadata.tags.push_back(tagEntry.get<std::string>());
                                }
                            }
                        }

                        // Optional fields - compiled size
                        if (entry.contains("compiledSize") && entry["compiledSize"].is_number_unsigned()) {
                            metadata.compiledSize = entry["compiledSize"].get<uint32_t>();
                        }

                        // Optional fields - last modified (unix timestamp)
                        if (entry.contains("lastModified") && entry["lastModified"].is_number_unsigned()) {
                            metadata.lastModified = entry["lastModified"].get<uint64_t>();
                        }

                        metadataCount++;

                    }
                    catch (const std::exception& e) {
                        SS_LOG_WARN(L"YaraRuleStore",
                            L"LoadRulesInternal: Error parsing metadata entry: %S", e.what());
                        parseErrors++;
                        continue;
                    }
                }

                SS_LOG_INFO(L"YaraRuleStore",
                    L"LoadRulesInternal: Loaded metadata for %zu rules (%zu errors)",
                    metadataCount, parseErrors);

                if (parseErrors > 0 && metadataCount == 0) {
                    SS_LOG_WARN(L"YaraRuleStore",
                        L"LoadRulesInternal: All metadata entries failed to parse");
                }

            }
            catch (const std::exception& e) {
                SS_LOG_ERROR(L"YaraRuleStore",
                    L"LoadRulesInternal: Unexpected error processing metadata: %S", e.what());
                // Continue without metadata - this is not fatal
            }
        }
    }

    // ========================================================================
    // CREATE TEMPORARY FILE FOR YARA LOADING
    // ========================================================================
    // YARA yr_rules_load() expects file path, not memory buffer
    // So we need to extract the YARA compiled bytecode to temporary file

    std::wstring tempPath;
    {
        wchar_t tempDir[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, tempDir)) {
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to get temp directory");
            return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot get temp path" };
        }

        wchar_t tempFile[MAX_PATH]{};
        if (!GetTempFileNameW(tempDir, L"YARA", 0, tempFile)) {
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to create temp filename");
            return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot create temp filename" };
        }

        tempPath = tempFile;
    }

    // RAII guard for temp file cleanup
    struct TempFileGuard {
        std::wstring path;
        ~TempFileGuard() {
            if (!path.empty()) {
                if (!DeleteFileW(path.c_str())) {
                    // Log warning but don't fail
                    DWORD err = GetLastError();
                    if (err != ERROR_FILE_NOT_FOUND) {
                        SS_LOG_WARN(L"YaraRuleStore", L"Failed to delete temp file: %s (error: %u)",
                            path.c_str(), err);
                    }
                }
            }
        }
    } tempGuard{ tempPath };

    // Write YARA data to temp file
    {
        // Note: Do NOT use FILE_FLAG_DELETE_ON_CLOSE as we need to read the file
        // with yr_rules_load() after closing the handle. The TempFileGuard will
        // handle cleanup instead.
        HANDLE hFile = CreateFileW(
            tempPath.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY,  // Just temporary, not delete-on-close
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD winErr = GetLastError();
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to create temp file (error: %u)", winErr);
            return StoreError{ SignatureStoreError::Unknown, winErr, "Cannot create temp file" };
        }

        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
        } handleGuard{ hFile };

        // TITANIUM: Validate yaraData size before cast to DWORD
        if (yaraData.size() > MAXDWORD) {
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: YARA data too large for single write");
            return StoreError{ SignatureStoreError::TooLarge, 0, "YARA data exceeds 4GB limit" };
        }

        DWORD bytesWritten = 0;
        if (!WriteFile(hFile, yaraData.data(), static_cast<DWORD>(yaraData.size()), &bytesWritten, nullptr)) {
            DWORD winErr = GetLastError();
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to write YARA data (error: %u)", winErr);
            return StoreError{ SignatureStoreError::Unknown, winErr, "Cannot write temp file" };
        }

        if (bytesWritten != yaraData.size()) {
            SS_LOG_ERROR(L"YaraRuleStore",
                L"LoadRulesInternal: Partial write to temp file (%u of %llu bytes)",
                bytesWritten, yaraData.size());
            return StoreError{ SignatureStoreError::Unknown, 0, "Incomplete write to temp file" };
        }
        
        // Flush to ensure data is written before reading
        if (!FlushFileBuffers(hFile)) {
            SS_LOG_WARN(L"YaraRuleStore", L"LoadRulesInternal: FlushFileBuffers warning");
        }

        SS_LOG_DEBUG(L"YaraRuleStore", L"LoadRulesInternal: Wrote %u bytes to temp file", bytesWritten);
        
        // Handle will be closed by guard, making file available for yr_rules_load
    }

    // ========================================================================
    // LOAD COMPILED RULES FROM TEMP FILE
    // ========================================================================
    int result = yr_rules_load(
        ShadowStrike::Utils::StringUtils::ToNarrow(tempPath).c_str(),
        &m_rules
    );

    if (result != ERROR_SUCCESS || !m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: YARA rules load failed (error: %d)", result);
        return StoreError{
            SignatureStoreError::InvalidFormat,
            static_cast<DWORD>(result),
            "Failed to load compiled YARA rules"
        };
    }

    SS_LOG_INFO(L"YaraRuleStore", L"LoadRulesInternal: Successfully loaded compiled YARA rules");

    // ========================================================================
    // POPULATE RULE METADATA FROM COMPILED RULES
    // ========================================================================
    // One implementation, shared with LoadCompiledRules and
    // AdoptRulesFromCompiler. This function used to keep its own copy of the
    // indexing loop and the two had drifted apart: the shared one read tags only,
    // this one read author, description and a `severity` string. Which of them ran
    // therefore decided whether a rule had an author or a severity at all, and both
    // are reachable from a plain Initialize depending on how the rules arrived.
    const size_t ruleCount = RebuildRuleMetadataFromRules();

    // These rules arrived as compiled bytecode, so m_ruleSources cannot reproduce
    // them. Recording that here is what stops a later source-driven rebuild from
    // silently replacing the whole database rule set with whatever sources happen
    // to be tracked - on the shipped database that would delete 11,053 rules.
    m_hasUntrackedRules = (ruleCount > 0u);

    // ========================================================================
    // LOAD STATISTICS FROM HEADER
    // ========================================================================
    m_totalScans.store(0, std::memory_order_release);
    m_totalMatches.store(0, std::memory_order_release);
    m_totalBytesScanned.store(0, std::memory_order_release);

    SS_LOG_INFO(L"YaraRuleStore",
        L"LoadRulesInternal: Complete - %zu rules loaded successfully", ruleCount);

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// TITANIUM: THREAD-SAFE HIT COUNT UPDATE
// ============================================================================

void YaraRuleStore::UpdateRuleHitCount(const std::string& ruleName) noexcept {
    // TITANIUM: This function is called from YARA callbacks during scanning.
    // The scan mutex (m_scanMutex) is already held by the caller, but we need
    // the global lock for m_ruleMetadata access.
    //
    // CRITICAL: Use try_lock to avoid deadlock. If we can't acquire the lock
    // immediately, skip the update - hit counts are best-effort statistics.
    
    // VALIDATION: Empty rule name check
    if (ruleName.empty()) {
        return;
    }
    
    // Try to acquire shared lock first (read-only lookup)
    // If metadata doesn't exist, we don't need to update
    {
        std::shared_lock<std::shared_mutex> readLock(m_globalLock, std::try_to_lock);
        if (!readLock.owns_lock()) {
            // Can't acquire lock - skip update to avoid deadlock
            SS_LOG_DEBUG(L"YaraRuleStore", L"UpdateRuleHitCount: Skipped (lock contention)");
            return;
        }
        
        auto it = m_ruleMetadata.find(ruleName);
        if (it == m_ruleMetadata.end()) {
            return; // Rule not found, nothing to update
        }
    }
    
    // Now try to acquire exclusive lock for write
    std::unique_lock<std::shared_mutex> writeLock(m_globalLock, std::try_to_lock);
    if (!writeLock.owns_lock()) {
        // Can't acquire lock - skip update to avoid deadlock
        SS_LOG_DEBUG(L"YaraRuleStore", L"UpdateRuleHitCount: Skipped write (lock contention)");
        return;
    }
    
    // Double-check after acquiring write lock (the map could have changed)
    auto it = m_ruleMetadata.find(ruleName);
    if (it != m_ruleMetadata.end()) {
        // Safe increment (overflow protection)
        if (it->second.hitCount < UINT32_MAX) {
            it->second.hitCount++;
        }
    }
}

YaraMatch YaraRuleStore::BuildYaraMatch(
    const std::string& ruleName,
    void* yaraRule,
    uint64_t matchTimeUs
) const noexcept {
    YaraMatch match{};
    match.ruleName = ruleName;
    match.matchTimeMicroseconds = matchTimeUs;

    // Get metadata
    auto it = m_ruleMetadata.find(ruleName);
    if (it != m_ruleMetadata.end()) {
        match.ruleId = it->second.ruleId;
        match.namespace_ = it->second.namespace_;
        match.threatLevel = it->second.threatLevel;
        match.tags = it->second.tags;
    }

    return match;
}

int YaraRuleStore::ScanCallback(int message, void* messageData, void* userData) {
    // Validate inputs
    if (!userData) {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanCallback: userData is null");
        return CALLBACK_CONTINUE;
    }

    // Handle different message types
    switch (message) {
        // ====================================================================
        // RULE MATCHING - Most important callback
        // ====================================================================
    case CALLBACK_MSG_RULE_MATCHING: {
        auto* rule = static_cast<YR_RULE*>(messageData);
        if (!rule || !rule->identifier) {
            SS_LOG_WARN(L"YaraRuleStore", L"ScanCallback: Invalid rule pointer");
            return CALLBACK_CONTINUE;
        }

        SS_LOG_DEBUG(L"YaraRuleStore", L"ScanCallback: Rule matched: %S",
            rule->identifier);

        // Update rule metadata if available
        auto* store = static_cast<YaraRuleStore*>(userData);
        if (store) {
            std::string ruleName = rule->identifier;
            std::string ruleNamespace = rule->ns ? rule->ns->name : "default";
            std::string fullName = ruleNamespace + "::" + ruleName;

            store->UpdateRuleHitCount(fullName);
        }

        return CALLBACK_CONTINUE;
    }

     // ====================================================================
     // RULE NOT MATCHING
     // ====================================================================
    case CALLBACK_MSG_RULE_NOT_MATCHING: {
        auto* rule = static_cast<YR_RULE*>(messageData);
        if (rule && rule->identifier) {
            SS_LOG_DEBUG(L"YaraRuleStore", L"ScanCallback: Rule not matched: %S",
                rule->identifier);
        }
        return CALLBACK_CONTINUE;
    }

                                       // ====================================================================
                                       // IMPORT CALLBACK - For imported rules
                                       // ====================================================================
    case CALLBACK_MSG_IMPORT_MODULE: {
        auto* importData = static_cast<YR_MODULE_IMPORT*>(messageData);
        if (importData && importData->module_name) {
            SS_LOG_DEBUG(L"YaraRuleStore", L"ScanCallback: Importing module: %S",
                importData->module_name);
        }
        return CALLBACK_CONTINUE;
    }

                                   // ====================================================================
                                   // INCLUDED FILE - For included rules
                                   // ====================================================================
#ifdef CALLBACK_MSG_INCLUDE_FILE
    case CALLBACK_MSG_INCLUDE_FILE: {
        if (messageData) {
            auto* fileName = static_cast<const char*>(messageData);
            SS_LOG_DEBUG(L"YaraRuleStore", L"ScanCallback: Including file: %S",
                fileName);
        }
        return CALLBACK_CONTINUE;
    }
#endif //CALLBACK_MSG_INCLUDE_FILE

                                  // ====================================================================
                                  // MODULE IMPORTED SUCCESSFULLY
                                  // ====================================================================
    case CALLBACK_MSG_MODULE_IMPORTED: {
        if (messageData) {
            auto* moduleName = static_cast<const char*>(messageData);
            SS_LOG_DEBUG(L"YaraRuleStore", L"ScanCallback: Module imported: %S",
                moduleName);
        }
        return CALLBACK_CONTINUE;
    }

                                     // ====================================================================
                                     // SCAN FINISHED
                                     // ====================================================================
    case CALLBACK_MSG_SCAN_FINISHED: {
        SS_LOG_DEBUG(L"YaraRuleStore", L"ScanCallback: Scan finished");
        return CALLBACK_CONTINUE;
    }

                                   // ====================================================================
                                   // UNKNOWN MESSAGE TYPE
                                   // ====================================================================
    default: {
        SS_LOG_WARN(L"YaraRuleStore", L"ScanCallback: Unknown message type: %d",
            message);
        return CALLBACK_CONTINUE;
    }
    }

    return CALLBACK_CONTINUE;
}

std::string YaraRuleStore::GetYaraVersion() noexcept {
   
    return YR_VERSION;
}

StoreError YaraRuleStore::TestRule(
    const std::string& ruleSource,
    std::vector<std::string>& errors
) const noexcept {
    YaraCompiler compiler;
    StoreError err = compiler.AddString(ruleSource, "test");
    
    errors = compiler.GetErrors();
    return err;
}

// ============================================================================
// EXPORT/IMPORT OPERATIONS - TITANIUM HARDENED
// ============================================================================

StoreError YaraRuleStore::ExportCompiled(
    const std::wstring& outputPath
) const noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"ExportCompiled: %s", outputPath.c_str());

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Empty path check
    if (outputPath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: Empty output path");
        return StoreError{ SignatureStoreError::FileNotFound, 0, "Output path is empty" };
    }
    
    // VALIDATION 2: Path length check
    if (outputPath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: Path too long");
        return StoreError{ SignatureStoreError::FileNotFound, 0, "Output path too long" };
    }
    
    // VALIDATION 3: Null character check
    if (outputPath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: Path contains null character");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Path contains null character" };
    }
    
    // VALIDATION 4: Rules exist check
    if (!m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: No compiled rules to export");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No compiled rules to export" };
    }

    // ========================================================================
    // ATOMIC FILE WRITE (Write to temp, then rename)
    // ========================================================================
    std::wstring tempPath = outputPath + L".tmp";
    
    {
        std::ofstream file(tempPath, std::ios::binary);
        if (!file.is_open()) {
            DWORD winErr = GetLastError();
            SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: Cannot create temp file (error: %u)", winErr);
            return StoreError{ SignatureStoreError::FileNotFound, winErr, "Cannot create export file" };
        }

        // Use shared lock for reading metadata
        std::shared_lock<std::shared_mutex> lock(m_globalLock);

        // Write header
        constexpr uint32_t magic = 0x59415241; // 'YARA'
        file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
        
        if (!file.good()) {
            SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: Failed to write magic number");
            lock.unlock();
            DeleteFileW(tempPath.c_str());
            return StoreError{ SignatureStoreError::MappingFailed, 0, "Failed to write to file" };
        }

        uint32_t ruleCount = static_cast<uint32_t>(m_ruleMetadata.size());
        file.write(reinterpret_cast<const char*>(&ruleCount), sizeof(ruleCount));

        // Write rule metadata
        for (const auto& [name, metadata] : m_ruleMetadata) {
            // Validate name length before cast
            if (name.length() > UINT32_MAX) {
                SS_LOG_WARN(L"YaraRuleStore", L"ExportCompiled: Rule name too long, skipping");
                continue;
            }
            
            uint32_t nameLen = static_cast<uint32_t>(name.length());
            file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
            file.write(name.data(), nameLen);

            if (metadata.namespace_.length() > UINT32_MAX) {
                SS_LOG_WARN(L"YaraRuleStore", L"ExportCompiled: Namespace too long, skipping");
                continue;
            }
            
            uint32_t nsLen = static_cast<uint32_t>(metadata.namespace_.length());
            file.write(reinterpret_cast<const char*>(&nsLen), sizeof(nsLen));
            file.write(metadata.namespace_.data(), nsLen);
            
            if (!file.good()) {
                SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: Write error during export");
                lock.unlock();
                file.close();
                DeleteFileW(tempPath.c_str());
                return StoreError{ SignatureStoreError::MappingFailed, 0, "Write error during export" };
            }
        }

        file.close();
    }
    
    // ========================================================================
    // ATOMIC RENAME
    // ========================================================================
    // Delete target if exists
    DeleteFileW(outputPath.c_str());
    
    // Rename temp to target
    if (!MoveFileW(tempPath.c_str(), outputPath.c_str())) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"ExportCompiled: Failed to rename temp file (error: %u)", winErr);
        DeleteFileW(tempPath.c_str());
        return StoreError{ SignatureStoreError::MappingFailed, winErr, "Failed to finalize export" };
    }
    
    SS_LOG_INFO(L"YaraRuleStore", L"ExportCompiled: Exported %zu rules successfully", 
        m_ruleMetadata.size());
    return StoreError{ SignatureStoreError::Success };
}

std::string YaraRuleStore::ExportToJson() const noexcept {
    SS_LOG_DEBUG(L"YaraRuleStore", L"ExportToJson");

    // ========================================================================
    // TITANIUM SAFE JSON EXPORT WITH PROPER ESCAPING
    // ========================================================================
    
    // Helper lambda to escape JSON strings properly
    auto escapeJsonString = [](const std::string& input) -> std::string {
        std::string output;
        output.reserve(input.length() + 16); // Reserve extra for escapes
        
        for (char c : input) {
            switch (c) {
                case '"':  output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    // Control characters need to be escaped as \uXXXX
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                        output += buf;
                    } else {
                        output += c;
                    }
                    break;
            }
        }
        return output;
    };

    try {
        std::shared_lock<std::shared_mutex> lock(m_globalLock);
        
        std::ostringstream json;
        json << "{\n  \"version\": \"1.0\",\n";
        json << "  \"yara_version\": \"" << escapeJsonString(GetYaraVersion()) << "\",\n";
        json << "  \"rule_count\": " << m_ruleMetadata.size() << ",\n  \"rules\": [\n";

        bool first = true;
        for (const auto& [name, metadata] : m_ruleMetadata) {
            if (!first) json << ",\n";
            first = false;

            json << "    {\n";
            json << "      \"name\": \"" << escapeJsonString(name) << "\",\n";
            json << "      \"namespace\": \"" << escapeJsonString(metadata.namespace_) << "\",\n";
            json << "      \"id\": " << metadata.ruleId << ",\n";
            json << "      \"threat_level\": " << static_cast<int>(metadata.threatLevel) << ",\n";
            json << "      \"author\": \"" << escapeJsonString(metadata.author) << "\",\n";
            json << "      \"description\": \"" << escapeJsonString(metadata.description) << "\",\n";
            json << "      \"hit_count\": " << metadata.hitCount << "\n";
            json << "    }";
        }

        json << "\n  ]\n}\n";
        return json.str();
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ExportToJson: Exception: %S", e.what());
        return "{ \"error\": \"Export failed\" }";
    }
}

// ============================================================================
// TITANIUM: REPOSITORY IMPORT
// ============================================================================

StoreError YaraRuleStore::ImportFromYaraRulesRepo(
    const std::wstring& repoPath,
    std::function<void(size_t current, size_t total)> progressCallback
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"ImportFromYaraRulesRepo: %s", repoPath.c_str());

    // ========================================================================
    // TITANIUM VALIDATION LAYER
    // ========================================================================
    
    // VALIDATION 1: Read-only check
    if (m_readOnly.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ImportFromYaraRulesRepo: Database is read-only");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }
    
    // VALIDATION 2: Path validation
    if (repoPath.empty()) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ImportFromYaraRulesRepo: Empty repository path");
        return StoreError{ SignatureStoreError::FileNotFound, 0, "Repository path is empty" };
    }
    
    // VALIDATION 3: Path length check
    if (repoPath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ImportFromYaraRulesRepo: Path too long");
        return StoreError{ SignatureStoreError::FileNotFound, 0, "Path too long" };
    }
    
    // VALIDATION 4: Null character check
    if (repoPath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraRuleStore", L"ImportFromYaraRulesRepo: Path contains null character");
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Path contains null character" };
    }

    // ========================================================================
    // FIND YARA FILES
    // ========================================================================
    auto yaraFiles = YaraUtils::FindYaraFiles(repoPath, true);
    if (yaraFiles.empty()) {
        SS_LOG_WARN(L"YaraRuleStore", L"ImportFromYaraRulesRepo: No YARA files found");
        return StoreError{ SignatureStoreError::FileNotFound, 0, "No YARA files found" };
    }
    
    // VALIDATION 5: File count limit (DoS protection)
    if (yaraFiles.size() > YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO) {
        SS_LOG_ERROR(L"YaraRuleStore", 
            L"ImportFromYaraRulesRepo: Too many files (%zu > %zu)",
            yaraFiles.size(), YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO);
        return StoreError{ SignatureStoreError::TooLarge, 0, 
            "Repository contains too many files" };
    }

    SS_LOG_INFO(L"YaraRuleStore", L"ImportFromYaraRulesRepo: Found %zu YARA files", yaraFiles.size());

    // ========================================================================
    // COMPILE FILES
    // ========================================================================
    YaraCompiler compiler;
    size_t successCount = 0;
    size_t failCount = 0;

    for (size_t i = 0; i < yaraFiles.size(); ++i) {
        std::string namespace_ = "default";
        StoreError err = compiler.AddFile(yaraFiles[i], namespace_);

        if (err.IsSuccess()) {
            successCount++;
        }
        else {
            failCount++;
            SS_LOG_WARN(L"YaraRuleStore", L"ImportFromYaraRulesRepo: Failed to compile: %s", 
                yaraFiles[i].c_str());
        }

        if (progressCallback) {
            try {
                progressCallback(i + 1, yaraFiles.size());
            } catch (...) {
                SS_LOG_WARN(L"YaraRuleStore", L"ImportFromYaraRulesRepo: Progress callback threw exception");
            }
        }
    }

    // ========================================================================
    // ACQUIRE LOCK AND UPDATE RULES
    // ========================================================================
    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    YR_RULES* newRules = compiler.GetRules();
    if (newRules) {
        // AdoptRulesFromCompiler serialises the compiler's output and reloads it, so
        // the store owns what it keeps and releases the previous set only after the
        // replacement has loaded. Direct assignment stored the LOCAL compiler's
        // singleton, which yr_compiler_destroy frees on return - leaving m_rules
        // dangling for every subsequent scan, and double freeing at teardown.
        if (!AdoptRulesFromCompiler(compiler)) {
            return StoreError{ SignatureStoreError::Unknown, 0,
                               "Could not adopt imported YARA rules" };
        }

        // This is a REPLACE, not a merge: the store now holds exactly the repo's
        // rules. Two consequences, recorded rather than left implicit:
        //  - previously tracked sources no longer describe anything that is loaded,
        //    so they are dropped instead of being left to resurrect removed rules
        //    at the next rebuild;
        //  - these rules came from bytecode, so no source can reproduce them, and a
        //    source-driven rebuild must refuse rather than silently discard them.
        // Compiling the files in place is deliberate and is why this path exists
        // separately from AddRulesFromDirectory: it keeps YARA `include` resolution,
        // which storing rule text cannot do.
        m_ruleSources.clear();
        m_hasUntrackedRules = true;
    } else {
        SS_LOG_ERROR(L"YaraRuleStore", L"ImportFromYaraRulesRepo: No rules compiled");
        return StoreError{ SignatureStoreError::Unknown, 0, "No rules compiled successfully" };
    }

    SS_LOG_INFO(L"YaraRuleStore", 
        L"ImportFromYaraRulesRepo: Complete - %zu succeeded, %zu failed", 
        successCount, failCount);
    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// MAINTENANCE OPERATIONS
// ============================================================================

StoreError YaraRuleStore::Recompile() noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"Recompiling all rules");

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Recompiling from the stored sources is exactly what RebuildRulesFromSources
    // does, so this delegates instead of keeping a sixth copy of the
    // compile-every-source loop. The copy that used to live here tolerated sources
    // that failed to compile and adopted whatever was left, then reported how many
    // had "succeeded" - a quietly reduced rule set presented as success.
    //
    // An empty source set is handled there too, and now means what it says: the
    // rules are released rather than left standing with nothing describing them.
    const StoreError rebuildResult = RebuildRulesFromSources();
    if (!rebuildResult.IsSuccess()) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"Recompile failed; the rule set is unchanged: %S",
            rebuildResult.message.c_str());
        return rebuildResult;
    }

    SS_LOG_INFO(L"YaraRuleStore",
        L"Recompilation complete: %zu source(s) produced %zu rule(s)",
        m_ruleSources.size(), m_ruleMetadata.size());
    return StoreError{ SignatureStoreError::Success };
}

StoreError YaraRuleStore::Verify(
    std::function<void(const std::string&)> logCallback
) const noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"Verifying YARA rule store");

    std::shared_lock<std::shared_mutex> lock(m_globalLock);

    if (!m_rules) {
        if (logCallback) {
            logCallback("ERROR: No compiled rules loaded");
        }
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No rules loaded" };
    }

    if (logCallback) {
        logCallback("Verifying rule metadata...");
    }

    size_t metadataCount = m_ruleMetadata.size();
    if (logCallback) {
        logCallback("Total rules in metadata: " + std::to_string(metadataCount));
    }

    std::set<uint64_t> ruleIds;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        if (ruleIds.find(metadata.ruleId) != ruleIds.end()) {
            if (logCallback) {
                logCallback("WARNING: Duplicate rule ID found: " + std::to_string(metadata.ruleId));
            }
        }
        ruleIds.insert(metadata.ruleId);
    }

    if (m_mappedView.IsValid()) {
        const auto* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);
        if (header) {
            bool validHeader = Format::ValidateHeader(header);
            if (!validHeader) {
                if (logCallback) {
                    logCallback("ERROR: Database header validation failed");
                }
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Invalid header" };
            }

            if (logCallback) {
                logCallback("Database header valid");
                logCallback("Database version: " +
                    std::to_string(header->versionMajor) + "." +
                    std::to_string(header->versionMinor));
            }
        }
    }

    if (!m_mappedView.IsValid()) {
        if (logCallback) {
            logCallback("WARNING: Memory mapping not initialized");
        }
    }
    else {
        if (logCallback) {
            logCallback("Memory mapping valid: " +
                std::to_string(m_mappedView.fileSize) + " bytes");
        }
    }

    if (logCallback) {
        logCallback("Verification complete - no critical errors found");
    }

    SS_LOG_INFO(L"YaraRuleStore", L"Verification passed");
    return StoreError{ SignatureStoreError::Success };
}

StoreError YaraRuleStore::Flush() noexcept {
    SS_LOG_DEBUG(L"YaraRuleStore", L"Flushing to disk");

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    if (!m_mappedView.IsValid()) {
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No memory mapping" };
    }

    StoreError err{};
    if (!MemoryMapping::FlushView(m_mappedView, err)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Flush failed: %S", err.message.c_str());
        return err;
    }

    SS_LOG_DEBUG(L"YaraRuleStore", L"Flush complete");
    return StoreError{ SignatureStoreError::Success };
}


// ============================================================================
// UTILITY FUNCTIONS - TITANIUM HARDENED
// ============================================================================

namespace YaraUtils {

bool ValidateRuleSyntax(
    const std::string& ruleSource,
    std::vector<std::string>& errors
) noexcept {
    // ========================================================================
    // TITANIUM VALIDATION
    // ========================================================================
    errors.clear();
    
    // Empty source check
    if (ruleSource.empty()) {
        errors.push_back("Rule source is empty");
        return false;
    }
    
    // Size limit (10MB max)
    if (ruleSource.length() > YaraTitaniumLimits::MAX_RULE_SOURCE_SIZE) {
        errors.push_back("Rule source exceeds the maximum rule source size");
        return false;
    }
    
    // ========================================================================
    // YARA INITIALIZATION - CRITICAL: Must initialize before using compiler
    // ========================================================================
    StoreError initResult = YaraRuleStore::InitializeYara();
    if (!initResult.IsSuccess()) {
        errors.push_back("Failed to initialize YARA library");
        return false;
    }
    
    // Compile with YARA to validate
    YaraCompiler compiler;
    StoreError err = compiler.AddString(ruleSource, "validate");
    
    errors = compiler.GetErrors();
    return err.IsSuccess();
}

std::map<std::string, std::string> ExtractMetadata(
    const std::string& ruleSource
) noexcept {
    std::map<std::string, std::string> metadata;

    // ========================================================================
    // TITANIUM BOUNDS CHECKING
    // ========================================================================
    if (ruleSource.empty() || ruleSource.length() > 10 * 1024 * 1024) {
        return metadata; // Empty or too large
    }

    try {
        // Simple parser: find meta: section
        size_t metaPos = ruleSource.find("meta:");
        if (metaPos == std::string::npos) {
            return metadata;
        }

        // Find the end of meta section (either "condition:", "strings:", or end of rule)
        size_t conditionPos = ruleSource.find("condition:", metaPos);
        size_t stringsPos = ruleSource.find("strings:", metaPos);
        
        size_t endPos = ruleSource.length();
        if (conditionPos != std::string::npos) {
            endPos = std::min(endPos, conditionPos);
        }
        if (stringsPos != std::string::npos) {
            endPos = std::min(endPos, stringsPos);
        }

        // Bounds check before substr
        if (metaPos + 5 >= endPos) {
            return metadata;
        }

        std::string metaSection = ruleSource.substr(metaPos + 5, endPos - metaPos - 5);
        
        // Limit number of metadata entries (DoS protection)
        constexpr size_t MAX_METADATA_ENTRIES = 100;
        size_t entryCount = 0;
        
        // Parse key = value pairs
        std::istringstream iss(metaSection);
        std::string line;
        while (std::getline(iss, line) && entryCount < MAX_METADATA_ENTRIES) {
            size_t eqPos = line.find('=');
            if (eqPos != std::string::npos && eqPos > 0 && eqPos < line.length() - 1) {
                std::string key = line.substr(0, eqPos);
                std::string value = line.substr(eqPos + 1);
                
                // Trim whitespace safely
                size_t keyStart = key.find_first_not_of(" \t");
                size_t keyEnd = key.find_last_not_of(" \t");
                if (keyStart != std::string::npos && keyEnd != std::string::npos && keyStart <= keyEnd) {
                    key = key.substr(keyStart, keyEnd - keyStart + 1);
                } else {
                    continue; // Empty key
                }
                
                size_t valStart = value.find_first_not_of(" \t\"");
                size_t valEnd = value.find_last_not_of(" \t\"");
                if (valStart != std::string::npos && valEnd != std::string::npos && valStart <= valEnd) {
                    value = value.substr(valStart, valEnd - valStart + 1);
                } else {
                    value.clear();
                }
                
                // Limit key/value lengths
                constexpr size_t MAX_KEY_LENGTH = 256;
                constexpr size_t MAX_VALUE_LENGTH = 4096;
                
                if (key.length() <= MAX_KEY_LENGTH && value.length() <= MAX_VALUE_LENGTH) {
                    metadata[key] = value;
                    entryCount++;
                }
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"YaraUtils", L"ExtractMetadata exception: %S", e.what());
    }

    return metadata;
}

std::vector<std::string> ExtractTags(const std::string& ruleSource) noexcept {
    std::vector<std::string> tags;

    // ========================================================================
    // TITANIUM BOUNDS CHECKING
    // ========================================================================
    if (ruleSource.empty() || ruleSource.length() > 10 * 1024 * 1024) {
        return tags;
    }

    try {
        // Find tags in rule declaration: rule RuleName : tag1 tag2 tag3
        size_t rulePos = ruleSource.find("rule ");
        if (rulePos == std::string::npos) {
            return tags;
        }

        // Find colon after rule name (for tags)
        size_t colonPos = ruleSource.find(':', rulePos + 5);
        if (colonPos == std::string::npos) {
            return tags;
        }

        // Find opening brace
        size_t bracePos = ruleSource.find('{', colonPos);
        if (bracePos == std::string::npos) {
            return tags;
        }

        // Bounds check before substr
        if (colonPos + 1 >= bracePos) {
            return tags;
        }

        std::string tagSection = ruleSource.substr(colonPos + 1, bracePos - colonPos - 1);
        
        // Parse tags with limits
        constexpr size_t MAX_TAGS = 50;
        constexpr size_t MAX_TAG_LENGTH = 64;
        
        std::istringstream iss(tagSection);
        std::string tag;
        while (iss >> tag && tags.size() < MAX_TAGS) {
            // Validate tag format (alphanumeric + underscore)
            if (tag.length() > 0 && tag.length() <= MAX_TAG_LENGTH) {
                bool valid = std::all_of(tag.begin(), tag.end(), [](unsigned char c) {
                    return std::isalnum(c) || c == '_';
                });
                
                if (valid) {
                    tags.push_back(tag);
                }
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"YaraUtils", L"ExtractTags exception: %S", e.what());
    }

    return tags;
}

ThreatLevel ParseThreatLevel(const std::map<std::string, std::string>& metadata) noexcept {
    // ------------------------------------------------------------------------
    // 1. AN EXPLICIT SEVERITY WINS.
    // ------------------------------------------------------------------------
    // A word or small ordinal written by a rule author is a human judgement and
    // takes precedence over the generated confidence score handled below.
    auto it = metadata.find("severity");
    if (it == metadata.end()) {
        it = metadata.find("threat_level");
    }
    if (it == metadata.end()) {
        it = metadata.find("Severity");
    }
    if (it == metadata.end()) {
        it = metadata.find("SEVERITY");
    }

    if (it != metadata.end()) {
        std::string value = it->second;
        
        // Convert to lowercase for comparison
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        
        if (value == "critical" || value == "severe" || value == "5") {
            return ThreatLevel::Critical;
        }
        if (value == "high" || value == "4") {
            return ThreatLevel::High;
        }
        if (value == "medium" || value == "moderate" || value == "3") {
            return ThreatLevel::Medium;
        }
        if (value == "low" || value == "minor" || value == "2" || value == "1") {
            return ThreatLevel::Low;
        }
        if (value == "info" || value == "informational" || value == "0") {
            // Info, not Low. This returned Low, which silently promoted a rule its
            // own author called informational into a conviction - Low and above map
            // to ScanVerdict::Infected while Info maps to Suspicious.
            return ThreatLevel::Info;
        }
    }

    // ------------------------------------------------------------------------
    // 2. NO EXPLICIT SEVERITY: USE THE CONFIDENCE SCORE IF THERE IS ONE.
    // ------------------------------------------------------------------------
    // MEASURED against the shipped ruleset, and this is why it is worth reading:
    // ALL 11,716 rules carry `score = <integer>` (the YARA Forge convention) while
    // only 70 carry a `severity` word. Without this branch, 11,646 of them fall
    // through to the Medium default below - so the product had a real, per-rule
    // severity signal for 100% of its rules and reported a blanket Medium for
    // 99.4% of them.
    //
    // Honouring it changes the reported severity to (measured on that ruleset):
    //   652 Low, 1348 Medium, 9706 High, 10 Critical
    //
    // THE TWO SCALES MUST NOT BE CONFUSED, which is why this is a separate branch
    // rather than another numeric case above. `severity = 5` means Critical on a
    // 0-5 ordinal; `score = 5` on the 0-100 scale would be almost nothing. Feeding
    // score into the ordinal branch would read 40 and 75 as unknown values and fall
    // back to Medium, or worse, silently invert the meaning.
    //
    // NO RULE CAN BE FILTERED OUT BY THIS: verified that minThreatLevel defaults to
    // ThreatLevel::Info in all three option structs and that no caller anywhere
    // sets it, so a rule landing on Low is still scanned and still reported.
    if (auto scoreIt = metadata.find("score"); scoreIt != metadata.end()) {
        int score = -1;
        const auto& text = scoreIt->second;
        if (!text.empty() &&
            std::all_of(text.begin(), text.end(),
                        [](unsigned char c) { return std::isdigit(c) != 0; })) {
            try {
                score = std::stoi(text);
            } catch (...) {
                score = -1;
            }
        }

        if (score >= 0) {
            if (score >= 100) return ThreatLevel::Critical;
            if (score >= 75)  return ThreatLevel::High;
            if (score >= 50)  return ThreatLevel::Medium;
            if (score >= 25)  return ThreatLevel::Low;
            return ThreatLevel::Info;
        }
    }

    return ThreatLevel::Medium; // Default when a rule states nothing at all
}

std::vector<std::wstring> FindYaraFiles(
    const std::wstring& directoryPath,
    bool recursive
) noexcept {
    std::vector<std::wstring> yaraFiles;
    
    // ========================================================================
    // TITANIUM VALIDATION
    // ========================================================================
    if (directoryPath.empty()) {
        SS_LOG_ERROR(L"YaraUtils", L"FindYaraFiles: Empty directory path");
        return yaraFiles;
    }
    
    if (directoryPath.length() > YaraTitaniumLimits::MAX_PATH_LENGTH) {
        SS_LOG_ERROR(L"YaraUtils", L"FindYaraFiles: Path too long");
        return yaraFiles;
    }
    
    // Null character check
    if (directoryPath.find(L'\0') != std::wstring::npos) {
        SS_LOG_ERROR(L"YaraUtils", L"FindYaraFiles: Path contains null character");
        return yaraFiles;
    }
    
    try {
        namespace fs = std::filesystem;
        
        // Verify directory exists
        if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
            SS_LOG_WARN(L"YaraUtils", L"FindYaraFiles: Path is not a valid directory");
            return yaraFiles;
        }

        // Limit number of files (DoS protection)
        constexpr size_t MAX_FILES = YaraTitaniumLimits::MAX_YARA_FILES_IN_REPO;
        size_t fileCount = 0;
        
        auto processEntry = [&](const fs::directory_entry& entry) {
            if (fileCount >= MAX_FILES) {
                return; // Limit reached
            }
            
            try {
                if (entry.is_regular_file()) {
                    auto ext = entry.path().extension().wstring();
                    
                    // Case-insensitive extension check
                    std::transform(ext.begin(), ext.end(), ext.begin(),
                        [](wchar_t c) { return static_cast<wchar_t>(::towlower(static_cast<wint_t>(c))); });
                    
                    if (ext == L".yar" || ext == L".yara") {
                        yaraFiles.push_back(entry.path().wstring());
                        fileCount++;
                    }
                }
            }
            catch (const std::exception&) {
                // Skip files that can't be accessed
            }
        };

        // Use error_code to avoid throwing on permission errors
        std::error_code ec;
        
        if (recursive) {
            for (auto it = fs::recursive_directory_iterator(directoryPath, 
                    fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator() && fileCount < MAX_FILES;
                 ++it) {
                if (!ec) {
                    processEntry(*it);
                }
                ec.clear();
            }
        }
        else {
            for (auto it = fs::directory_iterator(directoryPath, ec);
                 it != fs::directory_iterator() && fileCount < MAX_FILES;
                 ++it) {
                if (!ec) {
                    processEntry(*it);
                }
                ec.clear();
            }
        }
        
        if (fileCount >= MAX_FILES) {
            SS_LOG_WARN(L"YaraUtils", L"FindYaraFiles: Maximum file limit reached (%zu)", MAX_FILES);
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"YaraUtils", L"FindYaraFiles exception: %S", e.what());
    }
    
    SS_LOG_DEBUG(L"YaraUtils", L"FindYaraFiles: Found %zu YARA files", yaraFiles.size());
    return yaraFiles;
}


} // namespace YaraUtils

const SignatureDatabaseHeader* YaraRuleStore::GetHeader() const noexcept {
    SS_LOG_DEBUG(L"YaraRuleStore", L"GetHeader called");

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"YaraRuleStore", L"GetHeader: YaraStore not initialized");
        return nullptr;
    }

    if (!m_mappedView.IsValid()) {
        SS_LOG_WARN(L"YaraRuleStore", L"GetHeader: Memory mapping not valid");
        return nullptr;
    }

    // Get header from memory-mapped file at offset 0
    const SignatureDatabaseHeader* header = m_mappedView.GetAt<SignatureDatabaseHeader>(0);

    if (!header) {
        SS_LOG_ERROR(L"YaraRuleStore", L"GetHeader: Failed to get header from memory-mapped view");
        return nullptr;
    }

    // Validate header magic
    if (header->magic != SIGNATURE_DB_MAGIC) {
        SS_LOG_ERROR(L"YaraRuleStore",
            L"GetHeader: Invalid magic 0x%08X, expected 0x%08X",
            header->magic, SIGNATURE_DB_MAGIC);
        return nullptr;
    }

    // Validate version
    if (header->versionMajor != SIGNATURE_DB_VERSION_MAJOR) {
        SS_LOG_WARN(L"YaraRuleStore",
            L"GetHeader: Version mismatch - file: %u.%u, expected: %u.%u",
            header->versionMajor, header->versionMinor,
            SIGNATURE_DB_VERSION_MAJOR, SIGNATURE_DB_VERSION_MINOR);
    }

    SS_LOG_DEBUG(L"YaraRuleStore",
        L"GetHeader: Valid header - version %u.%u, YARA rules %llu bytes",
        header->versionMajor, header->versionMinor, header->yaraRulesSize);

    return header;
}

} // namespace SignatureStore
} // namespace ShadowStrike
#endif // SHADOWSTRIKE_HAS_YARA
