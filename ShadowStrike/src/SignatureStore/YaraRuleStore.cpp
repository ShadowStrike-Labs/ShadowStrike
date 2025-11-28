/*
 * ============================================================================
 * ShadowStrike YaraRuleStore - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * YARA rule engine integration implementation
 * Memory-mapped compiled rules, zero-copy execution
 * 
 *
 *
 *
 * ============================================================================
 */

#define NOMINMAX

#include "YaraRuleStore.hpp"

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include"../Utils/StringUtils.hpp"
#include"../Utils/MemoryUtils.hpp"
#include"../Utils/JSONUtils.hpp"

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
    int result = yr_compiler_create(&m_compiler);
    if(result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to create YARA compiler instance: %d", result);
        m_compiler = nullptr;
        return;
	}
    SS_LOG_DEBUG(L"YaraCompiler", L"Created compiler instance");
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

    if (!m_compiler) {
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Compiler not initialized"};
    }

    // Read file content
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to open file: %s", filePath.c_str());
        return StoreError{SignatureStoreError::FileNotFound, 0, "Cannot open file"};
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    return AddString(content, namespace_);
}

StoreError YaraCompiler::AddString(
    const std::string& ruleSource,
    const std::string& namespace_
) noexcept {
    if (!m_compiler) {
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Compiler not initialized"};
    }

    if (ruleSource.empty()) {
        return StoreError{SignatureStoreError::InvalidSignature, 0, "Empty rule source"};
    }

    
     int result = yr_compiler_add_string(m_compiler, ruleSource.c_str(), namespace_.c_str());
     if (result != ERROR_SUCCESS) {
         SS_LOG_ERROR(L"YaraCompiler", L"Failed to add rule string (namespace: %S): %d",
             namespace_.c_str(), result);
         return StoreError{SignatureStoreError::InvalidSignature, 
			 static_cast<DWORD>(result), "Failed to add rule string" };
     
     }

    SS_LOG_DEBUG(L"YaraCompiler", L"Added rule string (namespace: %S, length: %zu)",
        namespace_.c_str(), ruleSource.length());

    return StoreError{SignatureStoreError::Success};
}

StoreError YaraCompiler::AddFiles(
    std::span<const std::wstring> filePaths,
    const std::string& namespace_,
    std::function<void(size_t, size_t)> progressCallback
) noexcept {
    size_t successCount = 0;

    for (size_t i = 0; i < filePaths.size(); ++i) {
        StoreError err = AddFile(filePaths[i], namespace_);
        if (err.IsSuccess()) {
            successCount++;
        }

        if (progressCallback) {
            progressCallback(i + 1, filePaths.size());
        }
    }

    if (successCount == 0) {
        return StoreError{SignatureStoreError::InvalidSignature, 0, "No rules added"};
    }

    SS_LOG_INFO(L"YaraCompiler", L"Added %zu/%zu rule files", successCount, filePaths.size());
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
    YR_RULES* rules = GetRules();
    if (!rules) {
        return StoreError{SignatureStoreError::InvalidFormat, 0, "No compiled rules"};
    }

    int result = yr_rules_save(rules,ShadowStrike::Utils::StringUtils::ToNarrow(filePath).c_str());
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to save rules to file: %s (error: %d)",
            filePath.c_str(), result);
        return StoreError{ SignatureStoreError::InvalidSignature,
                          static_cast<DWORD>(result),
                          "Failed to save rules to file" };
    }
    
    SS_LOG_INFO(L"YaraCompiler", L"Saved compiled rules to: %s", filePath.c_str());
    return StoreError{SignatureStoreError::Success};
}

std::optional<std::vector<uint8_t>> YaraCompiler::SaveToBuffer() noexcept {
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"Compiler not initialized");
        return std::nullopt;
    }

    YR_RULES* rules = nullptr;
    int result = yr_compiler_get_rules(m_compiler, &rules);
    if (result != ERROR_SUCCESS || !rules) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to get compiled rules: %d", result);
        return std::nullopt;
    }

    // Use YR_STREAM to write to memory buffer
    std::vector<uint8_t> buffer;

    // Static callback function (YARA API requires function pointer, not lambda)
    static auto writeCallback = [](const void* ptr, size_t size, size_t count, void* user_data) -> size_t {
        auto* vec = static_cast<std::vector<uint8_t>*>(user_data);
        try {
            const uint8_t* bytes = static_cast<const uint8_t*>(ptr);
            size_t totalBytes = size * count;
            vec->insert(vec->end(), bytes, bytes + totalBytes);
            return count; // YARA expects number of items written
        }
        catch (...) {
            return 0;
        }
        };

    // Setup YARA stream structure
    YR_STREAM stream;
    stream.user_data = &buffer;
    stream.write = +writeCallback; // Unary + converts lambda to function pointer

    // Save rules to stream
    result = yr_rules_save_stream(rules, &stream);

    // Cleanup
    yr_rules_destroy(rules);

    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to save rules to buffer: %d", result);
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
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"Compiler not initialized, cannot define string variable: %S", name.c_str());
        return;
    }

    int result = yr_compiler_define_string_variable(m_compiler, name.c_str(), value.c_str());
    if (result != ERROR_SUCCESS) {
        SS_LOG_ERROR(L"YaraCompiler", L"Failed to define external string variable: %S (error: %d)",
            name.c_str(), result);
        return;
    }

    SS_LOG_DEBUG(L"YaraCompiler", L"Defined external string variable: %S = %S",
        name.c_str(), value.c_str());
}

void YaraCompiler::DefineExternalVariable(
    const std::string& name,
    int64_t value
) noexcept {
    if (!m_compiler) {
        SS_LOG_ERROR(L"YaraCompiler", L"Compiler not initialized, cannot define integer variable: %S", name.c_str());
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
    const char* message,
    void* userData
) {
    auto* compiler = static_cast<YaraCompiler*>(userData);
    if (!compiler) return;

    std::ostringstream oss;
    if (fileName) {
        oss << fileName << "(" << lineNumber << "): ";
    }
    oss << message;

    if (errorLevel == 0) { // Error
        compiler->m_errors.push_back(oss.str());
    } else { // Warning
        compiler->m_warnings.push_back(oss.str());
    }
}

// ============================================================================
// YARA RULE STORE IMPLEMENTATION
// ============================================================================

YaraRuleStore::YaraRuleStore() {
    if (!QueryPerformanceFrequency(&m_perfFrequency)) {
        m_perfFrequency.QuadPart = 1000000;
    }
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

    if (m_initialized.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::Success};
    }

    // Ensure YARA is initialized
    StoreError err = InitializeYara();
    if (!err.IsSuccess()) {
        return err;
    }

    m_databasePath = databasePath;
    m_readOnly.store(readOnly, std::memory_order_release);

    // Open memory mapping
    err = OpenMemoryMapping(databasePath, readOnly);
    if (!err.IsSuccess()) {
        return err;
    }

    // Load rules
    err = LoadRulesInternal();
    if (!err.IsSuccess()) {
        CloseMemoryMapping();
        return err;
    }

    m_initialized.store(true, std::memory_order_release);

    SS_LOG_INFO(L"YaraRuleStore", L"Initialized successfully");
    return StoreError{SignatureStoreError::Success};
}

StoreError YaraRuleStore::CreateNew(
    const std::wstring& databasePath,
    uint64_t initialSizeBytes
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"CreateNew: %s", databasePath.c_str());

    HANDLE hFile = CreateFileW(
        databasePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD winErr = GetLastError();
        return StoreError{SignatureStoreError::FileNotFound, winErr, "Cannot create file"};
    }

    LARGE_INTEGER size{};
    size.QuadPart = initialSizeBytes;
    if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN) || !SetEndOfFile(hFile)) {
        CloseHandle(hFile);
        return StoreError{SignatureStoreError::Unknown, GetLastError(), "Cannot set size"};
    }

    CloseHandle(hFile);
    return Initialize(databasePath, false);
}

StoreError YaraRuleStore::LoadCompiledRules(const std::wstring& compiledRulePath) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"LoadCompiledRules: %s", compiledRulePath.c_str());

    
    if (m_rules) {
        int destroyResult = yr_rules_destroy(m_rules);
        if (destroyResult != ERROR_SUCCESS) {
            SS_LOG_ERROR(L"YaraRuleStore", L"Failed to destroy existing rules (error: %d)", destroyResult);
            return StoreError{ SignatureStoreError::Unknown,
                              static_cast<DWORD>(destroyResult),
                              "Failed to destroy existing rules" };
        }
        m_rules = nullptr;
    }

    //load new compiled rules
    int result = yr_rules_load(ShadowStrike::Utils::StringUtils::ToNarrow(compiledRulePath).c_str(), &m_rules);
    if (result != ERROR_SUCCESS || !m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Failed to load compiled rules from %s (error: %d)",
            compiledRulePath.c_str(), result);
        return StoreError{ SignatureStoreError::InvalidFormat,
                          static_cast<DWORD>(result),
                          "Failed to load compiled rules" };
    }

    SS_LOG_INFO(L"YaraRuleStore", L"Loaded compiled rules successfully from %s", compiledRulePath.c_str());
    return StoreError{ SignatureStoreError::Success };
}


void YaraRuleStore::Close() noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    //free the rules if exists
    if (m_rules) {
        int destroyResult = yr_rules_destroy(m_rules);
        if (destroyResult != ERROR_SUCCESS) {
            SS_LOG_ERROR(L"YaraRuleStore", L"Failed to destroy rules during close (error: %d)", destroyResult);
        }
        m_rules = nullptr;
    }

    // clear  Metadata
    m_ruleMetadata.clear();

    //close Memory Mapping
    CloseMemoryMapping();

    // Initialized flag reset
    m_initialized.store(false, std::memory_order_release);

    SS_LOG_INFO(L"YaraRuleStore", L"Closed successfully");
}

// ============================================================================
// SCANNING OPERATIONS
// ============================================================================

std::vector<YaraMatch> YaraRuleStore::ScanBuffer(
    std::span<const uint8_t> buffer,
    const YaraScanOptions& options
) const noexcept {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    return PerformScan(buffer.data(), buffer.size(), options);
}

std::vector<YaraMatch> YaraRuleStore::ScanFile(
    const std::wstring& filePath,
    const YaraScanOptions& options
) const noexcept {
    SS_LOG_DEBUG(L"YaraRuleStore", L"ScanFile: %s", filePath.c_str());

    // Check file size
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
        SS_LOG_ERROR(L"YaraRuleStore", L"Failed to open file");
        return {};
    }

    LARGE_INTEGER fileSize{};
    GetFileSizeEx(hFile, &fileSize);
    CloseHandle(hFile);

    if (static_cast<uint64_t>(fileSize.QuadPart) > options.maxFileSizeBytes) {
        SS_LOG_WARN(L"YaraRuleStore", L"File too large: %lld bytes", fileSize.QuadPart);
        return {};
    }

    // Memory-map file
    StoreError err{};
    MemoryMappedView fileView{};
    
    if (!ShadowStrike::SignatureStore::MemoryMapping::OpenView(filePath,true,fileView,err)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Failed to map file: %S", err.message.c_str());
        return {};
    }

    std::span<const uint8_t> buffer(
        static_cast<const uint8_t*>(fileView.baseAddress),
        static_cast<size_t>(fileView.fileSize)
    );

    auto results = ScanBuffer(buffer, options);
    ShadowStrike::SignatureStore::MemoryMapping::CloseView(fileView);
    
    return results;
}

std::vector<YaraMatch> YaraRuleStore::ScanProcess(
    uint32_t processId,
    const YaraScanOptions& options
) const noexcept {
    SS_LOG_DEBUG(L"YaraRuleStore", L"ScanProcess: PID=%u", processId);

    std::vector<YaraMatch> matches;

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Not initialized");
        return matches;
    }

    if (!m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"No compiled rules loaded");
        return matches;
    }

    // Open process with appropriate access rights
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        processId
    );

    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        DWORD winErr = GetLastError();
        SS_LOG_ERROR(L"YaraRuleStore", L"OpenProcess failed for PID=%u (error: %u)",
            processId, winErr);
        return matches;
    }

    // RAII handle guard
    struct ProcessHandleGuard {
        HANDLE handle;
        ~ProcessHandleGuard() { if (handle) CloseHandle(handle); }
    } guard{ hProcess };

    // Statistics
    m_totalScans.fetch_add(1, std::memory_order_relaxed);

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // Context for callback
    struct ScanCallbackContext {
        const YaraRuleStore* store;
        std::vector<YaraMatch>* matches;
        uint64_t scanStartUs;
        uint32_t maxMatchesPerRule;
        ThreatLevel minThreatLevel;
    };

    ScanCallbackContext ctx{};
    ctx.store = this;
    ctx.matches = &matches;
    ctx.scanStartUs = 0;
    ctx.maxMatchesPerRule = options.maxMatchesPerRule;
    ctx.minThreatLevel = options.minThreatLevel;

    // YARA callback for process scan
    auto callback = [](YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) -> int {
        auto* ctx = static_cast<ScanCallbackContext*>(user_data);

        if (message == CALLBACK_MSG_RULE_MATCHING) {
            auto* rule = static_cast<YR_RULE*>(message_data);

            if (!rule || !rule->identifier) {
                return CALLBACK_CONTINUE;
            }

            std::string ruleName = rule->identifier;

            // Get rule metadata
            auto metadataIt = ctx->store->m_ruleMetadata.find(ruleName);
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
            match.namespace_ = rule->ns ? rule->ns->name : "default";

            // Get metadata
            if (metadataIt != ctx->store->m_ruleMetadata.end()) {
                match.ruleId = metadataIt->second.ruleId;
                match.threatLevel = metadataIt->second.threatLevel;
                match.tags = metadataIt->second.tags;
            }

            // Extract string matches
            YR_STRING* string = nullptr;
            yr_rule_strings_foreach(rule, string) {
                YR_MATCH* match_info = nullptr;
                yr_string_matches_foreach(context, string, match_info) {
                    YaraMatch::StringMatch strMatch{};
                    strMatch.identifier = string->identifier;
                    strMatch.offsets.push_back(match_info->offset);

                    // Add match data if requested and available
                    if (match_info->data && match_info->data_length > 0) {
                        std::string matchData(
                            reinterpret_cast<const char*>(match_info->data),
                            match_info->data_length
                        );
                        strMatch.data.push_back(matchData);
                    }

                    match.stringMatches.push_back(strMatch);

                    // Limit matches per rule
                    if (match.stringMatches.size() >= ctx->maxMatchesPerRule) {
                        break;
                    }
                }

                if (match.stringMatches.size() >= ctx->maxMatchesPerRule) {
                    break;
                }
            }

            // Calculate match time
            LARGE_INTEGER endTime;
            QueryPerformanceCounter(&endTime);
            LARGE_INTEGER freq;
            QueryPerformanceFrequency(&freq);
            match.matchTimeMicroseconds =
                ((endTime.QuadPart - ctx->scanStartUs) * 1000000ULL) / freq.QuadPart;

            ctx->matches->push_back(std::move(match));

            // Update hit count
            const_cast<YaraRuleStore*>(ctx->store)->UpdateRuleHitCount(ruleName);
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

    return matches;
}

YaraRuleStore::ScanContext YaraRuleStore::CreateScanContext(
    const YaraScanOptions& options
) const noexcept {
    ScanContext ctx;
    ctx.m_store = this;
    ctx.m_options = options;
    return ctx;
}

void YaraRuleStore::ScanContext::Reset() noexcept {
    m_buffer.clear();
}

std::vector<YaraMatch> YaraRuleStore::ScanContext::FeedChunk(
    std::span<const uint8_t> chunk
) noexcept {
    m_buffer.insert(m_buffer.end(), chunk.begin(), chunk.end());

    // Scan when buffer reaches threshold
    if (m_buffer.size() >= 10 * 1024 * 1024) { // 10MB
        auto results = m_store->ScanBuffer(m_buffer, m_options);
        m_buffer.clear();
        return results;
    }

    return {};
}

std::vector<YaraMatch> YaraRuleStore::ScanContext::Finalize() noexcept {
    if (m_buffer.empty()) {
        return {};
    }

    auto results = m_store->ScanBuffer(m_buffer, m_options);
    m_buffer.clear();
    return results;
}

// ============================================================================
// RULE MANAGEMENT
// ============================================================================

std::vector<YaraMatch> YaraRuleStore::PerformScan(
    const void* buffer,
    size_t size,
    const YaraScanOptions& options
) const noexcept {
    std::vector<YaraMatch> matches;

    // ========================================================================
    // VALIDATION
    // ========================================================================
    if (!buffer || size == 0) {
        SS_LOG_ERROR(L"YaraRuleStore", L"Invalid buffer");
        return matches;
    }

    if (!m_rules) {
        SS_LOG_ERROR(L"YaraRuleStore", L"No compiled rules loaded");
        return matches;
    }

    // Reserve space to minimize reallocations
    matches.reserve(options.maxMatchesPerRule * 10);

    // ========================================================================
    // STATISTICS & TIMING
    // ========================================================================
    m_totalScans.fetch_add(1, std::memory_order_relaxed);
    m_totalBytesScanned.fetch_add(size, std::memory_order_relaxed);

    LARGE_INTEGER startTime;
    QueryPerformanceCounter(&startTime);

    // ========================================================================
    // CALLBACK CONTEXT SETUP
    // ========================================================================
    struct ScanCallbackContext {
        std::vector<YaraMatch>* matches;
        const YaraRuleStore* store;
        uint32_t maxMatchesPerRule;
        ThreatLevel minThreatLevel;
        bool captureMatchData;
        LARGE_INTEGER perfFrequency;
        LARGE_INTEGER scanStartTime;
    };

    ScanCallbackContext ctx{};
    ctx.matches = &matches;
    ctx.store = this;
    ctx.maxMatchesPerRule = options.maxMatchesPerRule;
    ctx.minThreatLevel = options.minThreatLevel;
    ctx.captureMatchData = options.captureMatchData;
    ctx.perfFrequency = m_perfFrequency;
    ctx.scanStartTime = startTime;

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

            // Add to results
            ctx->matches->push_back(std::move(match));

            // Update hit count (const_cast safe here - we own the mutex)
            const_cast<YaraRuleStore*>(ctx->store)->UpdateRuleHitCount(fullName);

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

    // Execute YARA scan
    int result = yr_rules_scan_mem(
        m_rules,
        static_cast<const uint8_t*>(buffer),
        size,
        scanFlags,
        callback,
        &ctx,
        static_cast<int>(options.timeoutSeconds)
    );

    // ========================================================================
    // POST-PROCESSING
    // ========================================================================
    LARGE_INTEGER endTime;
    QueryPerformanceCounter(&endTime);

    uint64_t totalScanTimeUs =
        ((endTime.QuadPart - startTime.QuadPart) * 1000000ULL) / m_perfFrequency.QuadPart;

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



StoreError YaraRuleStore::AddRulesFromFile(
    const std::wstring& filePath,
    const std::string& namespace_
) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }

    YaraCompiler compiler;
    return compiler.AddFile(filePath, namespace_);
}

StoreError YaraRuleStore::AddRulesFromDirectory(
    const std::wstring& directoryPath,
    const std::string& namespace_,
    std::function<void(size_t, size_t)> progressCallback
) noexcept {
    auto yaraFiles = YaraUtils::FindYaraFiles(directoryPath, true);
    
    if (yaraFiles.empty()) {
        return StoreError{SignatureStoreError::FileNotFound, 0, "No YARA files found"};
    }

    YaraCompiler compiler;
    return compiler.AddFiles(yaraFiles, namespace_, progressCallback);
}

StoreError YaraRuleStore::RemoveRule(
    const std::string& ruleName,
    const std::string& namespace_
) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Remove from metadata
    std::string fullName = namespace_ + "::" + ruleName;
    m_ruleMetadata.erase(fullName);

    SS_LOG_DEBUG(L"YaraRuleStore", L"Removed rule: %S", fullName.c_str());
    return StoreError{SignatureStoreError::Success};
}

StoreError YaraRuleStore::RemoveNamespace(const std::string& namespace_) noexcept {
    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{SignatureStoreError::AccessDenied, 0, "Read-only"};
    }

    std::unique_lock<std::shared_mutex> lock(m_globalLock);

    // Remove all rules in namespace
    for (auto it = m_ruleMetadata.begin(); it != m_ruleMetadata.end(); ) {
        if (it->second.namespace_ == namespace_) {
            it = m_ruleMetadata.erase(it);
        } else {
            ++it;
        }
    }

    SS_LOG_INFO(L"YaraRuleStore", L"Removed namespace: %S", namespace_.c_str());
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
        HANDLE hFile = CreateFileW(
            tempPath.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to create temp file");
            return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot create temp file" };
        }

        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
        } handleGuard{ hFile };

        DWORD bytesWritten = 0;
        if (!WriteFile(hFile, yaraData.data(), static_cast<DWORD>(yaraData.size()), &bytesWritten, nullptr)) {
            SS_LOG_ERROR(L"YaraRuleStore", L"LoadRulesInternal: Failed to write YARA data to temp file");
            return StoreError{ SignatureStoreError::Unknown, GetLastError(), "Cannot write temp file" };
        }

        if (bytesWritten != yaraData.size()) {
            SS_LOG_ERROR(L"YaraRuleStore",
                L"LoadRulesInternal: Partial write to temp file (%u of %llu bytes)",
                bytesWritten, yaraData.size());
            return StoreError{ SignatureStoreError::Unknown, 0, "Incomplete write to temp file" };
        }

        SS_LOG_DEBUG(L"YaraRuleStore", L"LoadRulesInternal: Wrote %u bytes to temp file", bytesWritten);
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
    size_t ruleCount = 0;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(m_rules, rule) {
        if (!rule || !rule->identifier) {
            SS_LOG_WARN(L"YaraRuleStore", L"LoadRulesInternal: Encountered rule with null identifier");
            continue;
        }

        std::string ruleName = rule->identifier;
        std::string ruleNamespace = rule->ns ? rule->ns->name : "default";
        std::string fullName = ruleNamespace + "::" + ruleName;

        // Create metadata entry
        YaraRuleMetadata metadata{};
        metadata.ruleId = static_cast<uint64_t>(std::hash<std::string>{}(fullName));
        metadata.ruleName = ruleName;
        metadata.namespace_ = ruleNamespace;
        metadata.threatLevel = ThreatLevel::Medium;  // Default, can be overridden by database metadata
        metadata.isGlobal = (rule->flags & RULE_FLAGS_GLOBAL) != 0;
        metadata.isPrivate = (rule->flags & RULE_FLAGS_PRIVATE) != 0;
        metadata.lastModified = static_cast<uint64_t>(std::time(nullptr));
        metadata.hitCount = 0;
        metadata.averageMatchTimeMicroseconds = 0;

        // Extract tags
        const char* tag = nullptr;
        yr_rule_tags_foreach(rule, tag) {
            if (tag) {
                metadata.tags.emplace_back(tag);
            }
        }

        // Extract metadata (author, description, reference)
        YR_META* meta = nullptr;
        yr_rule_metas_foreach(rule, meta) {
            if (!meta || !meta->identifier) continue;

            std::string metaKey = meta->identifier;

            if (metaKey == "author" && meta->type == META_TYPE_STRING && meta->string) {
                metadata.author = meta->string;
            }
            else if (metaKey == "description" && meta->type == META_TYPE_STRING && meta->string) {
                metadata.description = meta->string;
            }
            else if (metaKey == "reference" && meta->type == META_TYPE_STRING && meta->string) {
                metadata.reference = meta->string;
            }
            else if (metaKey == "severity" && meta->type == META_TYPE_STRING && meta->string) {
                // Parse threat level from metadata
                metadata.threatLevel = YaraUtils::ParseThreatLevel(
                    std::map<std::string, std::string>{{"severity", meta->string}}
                );
            }
        }

        // Store in cache
        m_ruleMetadata[fullName] = std::move(metadata);
        ruleCount++;
    }

    SS_LOG_INFO(L"YaraRuleStore", L"LoadRulesInternal: Loaded metadata for %zu rules", ruleCount);

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

void YaraRuleStore::UpdateRuleHitCount(const std::string& ruleName) noexcept {
    auto it = m_ruleMetadata.find(ruleName);
    if (it != m_ruleMetadata.end()) {
        it->second.hitCount++;
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
// EXPORT/IMPORT OPERATIONS
// ============================================================================

StoreError YaraRuleStore::ExportCompiled(
    const std::wstring& outputPath
) const noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"ExportCompiled: %s", outputPath.c_str());

    if (!m_rules) {
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "No compiled rules to export" };
    }

    std::ofstream file(outputPath, std::ios::binary);
    if (!file.is_open()) {
        return StoreError{ SignatureStoreError::FileNotFound, 0, "Cannot create export file" };
    }

    uint32_t magic = 0x59415241; // 'YARA'
    file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));

    uint32_t ruleCount = static_cast<uint32_t>(m_ruleMetadata.size());
    file.write(reinterpret_cast<const char*>(&ruleCount), sizeof(ruleCount));

    for (const auto& [name, metadata] : m_ruleMetadata) {
        uint32_t nameLen = static_cast<uint32_t>(name.length());
        file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
        file.write(name.data(), nameLen);

        uint32_t nsLen = static_cast<uint32_t>(metadata.namespace_.length());
        file.write(reinterpret_cast<const char*>(&nsLen), sizeof(nsLen));
        file.write(metadata.namespace_.data(), nsLen);
    }

    file.close();
    SS_LOG_INFO(L"YaraRuleStore", L"Exported %u rules", ruleCount);
    return StoreError{ SignatureStoreError::Success };
}

std::string YaraRuleStore::ExportToJson() const noexcept {
    SS_LOG_DEBUG(L"YaraRuleStore", L"ExportToJson");

    std::ostringstream json;
    json << "{\n  \"version\": \"1.0\",\n";
    json << "  \"yara_version\": \"" << GetYaraVersion() << "\",\n";
    json << "  \"rule_count\": " << m_ruleMetadata.size() << ",\n  \"rules\": [\n";

    bool first = true;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        if (!first) json << ",\n";
        first = false;

        json << "    {\n";
        json << "      \"name\": \"" << name << "\",\n";
        json << "      \"namespace\": \"" << metadata.namespace_ << "\",\n";
        json << "      \"id\": " << metadata.ruleId << ",\n";
        json << "      \"threat_level\": " << static_cast<int>(metadata.threatLevel) << ",\n";
        json << "      \"author\": \"" << metadata.author << "\",\n";
        json << "      \"hit_count\": " << metadata.hitCount << "\n";
        json << "    }";
    }

    json << "\n  ]\n}\n";
    return json.str();
}

StoreError YaraRuleStore::ImportFromYaraRulesRepo(
    const std::wstring& repoPath,
    std::function<void(size_t current, size_t total)> progressCallback
) noexcept {
    SS_LOG_INFO(L"YaraRuleStore", L"ImportFromYaraRulesRepo: %s", repoPath.c_str());

    if (m_readOnly.load(std::memory_order_acquire)) {
        return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
    }

    auto yaraFiles = YaraUtils::FindYaraFiles(repoPath, true);
    if (yaraFiles.empty()) {
        SS_LOG_WARN(L"YaraRuleStore", L"No YARA files found in repository");
        return StoreError{ SignatureStoreError::FileNotFound, 0, "No YARA files found" };
    }

    SS_LOG_INFO(L"YaraRuleStore", L"Found %zu YARA files in repository", yaraFiles.size());

    YaraCompiler compiler;
    size_t successCount = 0;

    for (size_t i = 0; i < yaraFiles.size(); ++i) {
        std::string namespace_ = "default";
        StoreError err = compiler.AddFile(yaraFiles[i], namespace_);

        if (err.IsSuccess()) {
            successCount++;
        }
        else {
            SS_LOG_WARN(L"YaraRuleStore", L"Failed to compile: %s", yaraFiles[i].c_str());
        }

        if (progressCallback) {
            progressCallback(i + 1, yaraFiles.size());
        }
    }

    YR_RULES* newRules = compiler.GetRules();
    if (newRules) {
        if (m_rules) {
            yr_rules_destroy(m_rules);
        }
        m_rules = newRules;
    }

    SS_LOG_INFO(L"YaraRuleStore", L"Import complete: %zu succeeded", successCount);
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

    YaraCompiler compiler;
    for (const auto& [name, metadata] : m_ruleMetadata) {
        SS_LOG_DEBUG(L"YaraRuleStore", L"Recompiling rule: %S", name.c_str());
    }

    YR_RULES* newRules = compiler.GetRules();
    if (!newRules) {
        return StoreError{ SignatureStoreError::Unknown, 0, "Recompilation failed" };
    }

    if (m_rules) {
         yr_rules_destroy(m_rules);
    }
    m_rules = newRules;

    SS_LOG_INFO(L"YaraRuleStore", L"Recompilation complete");
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
// UTILITY FUNCTIONS
// ============================================================================

namespace YaraUtils {

bool ValidateRuleSyntax(
    const std::string& ruleSource,
    std::vector<std::string>& errors
) noexcept {
    YaraCompiler compiler;
    StoreError err = compiler.AddString(ruleSource, "validate");
    
    errors = compiler.GetErrors();
    return err.IsSuccess();
}

std::map<std::string, std::string> ExtractMetadata(
    const std::string& ruleSource
) noexcept {
    std::map<std::string, std::string> metadata;

    // Simple parser: find meta: section
    size_t metaPos = ruleSource.find("meta:");
    if (metaPos == std::string::npos) {
        return metadata;
    }

    size_t conditionPos = ruleSource.find("condition:", metaPos);
    if (conditionPos == std::string::npos) {
        conditionPos = ruleSource.length();
    }

    std::string metaSection = ruleSource.substr(metaPos + 5, conditionPos - metaPos - 5);
    
    // Parse key = value pairs
    std::istringstream iss(metaSection);
    std::string line;
    while (std::getline(iss, line)) {
        size_t eqPos = line.find('=');
        if (eqPos != std::string::npos) {
            std::string key = line.substr(0, eqPos);
            std::string value = line.substr(eqPos + 1);
            
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t\""));
            value.erase(value.find_last_not_of(" \t\"") + 1);
            
            metadata[key] = value;
        }
    }

    return metadata;
}

std::vector<std::string> ExtractTags(const std::string& ruleSource) noexcept {
    std::vector<std::string> tags;

    // Find tags in rule declaration: rule RuleName : tag1 tag2 tag3
    size_t rulePos = ruleSource.find("rule ");
    if (rulePos == std::string::npos) {
        return tags;
    }

    size_t colonPos = ruleSource.find(':', rulePos);
    if (colonPos == std::string::npos) {
        return tags;
    }

    size_t bracePos = ruleSource.find('{', colonPos);
    if (bracePos == std::string::npos) {
        return tags;
    }

    std::string tagSection = ruleSource.substr(colonPos + 1, bracePos - colonPos - 1);
    std::istringstream iss(tagSection);
    std::string tag;
    while (iss >> tag) {
        tags.push_back(tag);
    }

    return tags;
}

ThreatLevel ParseThreatLevel(const std::map<std::string, std::string>& metadata) noexcept {
    auto it = metadata.find("severity");
    if (it == metadata.end()) {
        it = metadata.find("threat_level");
    }

    if (it != metadata.end()) {
        const std::string& value = it->second;
        if (value == "critical") return ThreatLevel::Critical;
        if (value == "high") return ThreatLevel::High;
        if (value == "medium") return ThreatLevel::Medium;
        if (value == "low") return ThreatLevel::Low;
    }

    return ThreatLevel::Medium; // Default
}

std::vector<std::wstring> FindYaraFiles(
    const std::wstring& directoryPath,
    bool recursive
) noexcept {
    std::vector<std::wstring> yaraFiles;
    try {
        namespace fs = std::filesystem;

        auto processEntry = [&](const fs::directory_entry& entry) {
            if (entry.is_regular_file()) {
                auto ext = entry.path().extension();
                if (ext == L".yar" || ext == L".yara") {
                    yaraFiles.push_back(entry.path().wstring());
                }
            }
            };

        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
                processEntry(entry);
            }
        }
        else {
            for (const auto& entry : fs::directory_iterator(directoryPath)) {
                processEntry(entry);
            }
        }
    }
    catch (const std::exception& e) {
        SS_LOG_ERROR(L"YaraUtils", L"FindYaraFiles error: %S", e.what());
    }
    return yaraFiles;
}


} // namespace YaraUtils

} // namespace SignatureStore
} // namespace ShadowStrike
