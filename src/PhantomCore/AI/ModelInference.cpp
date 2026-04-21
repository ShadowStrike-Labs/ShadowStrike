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
 * ShadowStrike PhantomCortex - ONNX RUNTIME INFERENCE WRAPPER (IMPL)
 * ============================================================================
 *
 * @file ModelInference.cpp
 * @brief Complete PIMPL implementation for ModelInference.
 *
 * Wraps the ONNX Runtime C API for loading .onnx models, running single
 * and batched inference, hardware capability detection, and model
 * version tracking.
 *
 * All ORT objects are released through RAII helpers. Every error path
 * logs via the ShadowStrike logging infrastructure and returns gracefully.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * ============================================================================
 */

#include "pch.h"
#include "ModelInference.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/HashUtils.hpp"

// ============================================================================
// ONNX Runtime C API
// ============================================================================

#if __has_include(<onnxruntime_c_api.h>)
#include <onnxruntime_c_api.h>
#define SHADOWSTRIKE_HAS_ONNXRUNTIME 1
#else
#define SHADOWSTRIKE_HAS_ONNXRUNTIME 0
#endif

// ============================================================================
// Windows / SIMD intrinsics
// ============================================================================

#include <intrin.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// Standard library
// ============================================================================

#include <array>
#include <string>
#include <vector>
#include <shared_mutex>
#include <filesystem>
#include <numeric>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <thread>
#include <fstream>

#if SHADOWSTRIKE_HAS_ONNXRUNTIME

namespace ShadowStrike {
namespace AI {

// ============================================================================
// LOGGING TAG
// ============================================================================

static constexpr const wchar_t* kLogTag = L"PhantomCortex";

// ============================================================================
// MODEL FILE NAMES (indexed by CortexModelType ordinal)
// ============================================================================

static constexpr const wchar_t* kModelFileNames[CortexConstants::MODEL_COUNT] = {
    L"cortex_static.onnx",
    L"cortex_behavioral.onnx",
    L"cortex_memory.onnx",
    L"cortex_network.onnx",
    L"cortex_emulation.onnx"
};

static constexpr const wchar_t* kModelTypeNames[CortexConstants::MODEL_COUNT] = {
    L"Static",
    L"Behavioral",
    L"Memory",
    L"Network",
    L"Emulation"
};

// ============================================================================
// RAII HELPERS FOR ORT OBJECTS
// ============================================================================

/// Scoped wrapper for any ORT pointer released via a single-argument Release fn.
template <typename T, void (ORT_API_CALL* ReleaseFn)(T*)>
class OrtScoped final {
public:
    OrtScoped() noexcept = default;
    explicit OrtScoped(T* ptr) noexcept : m_ptr(ptr) {}
    ~OrtScoped() { reset(); }

    OrtScoped(const OrtScoped&)            = delete;
    OrtScoped& operator=(const OrtScoped&) = delete;

    OrtScoped(OrtScoped&& other) noexcept : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }
    OrtScoped& operator=(OrtScoped&& other) noexcept {
        if (this != &other) { reset(); m_ptr = other.m_ptr; other.m_ptr = nullptr; }
        return *this;
    }

    [[nodiscard]] T* get()  const noexcept { return m_ptr; }
    [[nodiscard]] T** put()       noexcept { reset(); return &m_ptr; }
    T* release()                  noexcept { T* p = m_ptr; m_ptr = nullptr; return p; }

    void reset(T* ptr = nullptr) noexcept {
        if (m_ptr) ReleaseFn(m_ptr);
        m_ptr = ptr;
    }

    explicit operator bool() const noexcept { return m_ptr != nullptr; }

private:
    T* m_ptr = nullptr;
};

// ============================================================================
// ORT STATUS HELPER
// ============================================================================

/// Check an OrtStatus, log if non-null, release, and return false.
static bool CheckOrtStatus(const OrtApi* api, OrtStatus* status, const wchar_t* context) noexcept {
    if (status == nullptr) return true;

    const char* msg = api->GetErrorMessage(status);
    if (msg) {
        // Convert narrow ORT message to wide for logging
        wchar_t wbuf[512]{};
        MultiByteToWideChar(CP_UTF8, 0, msg, -1, wbuf, _countof(wbuf) - 1);
        SS_LOG_ERROR(kLogTag, L"%ls: ORT error — %ls", context, wbuf);
    } else {
        SS_LOG_ERROR(kLogTag, L"%ls: ORT returned unknown error", context);
    }
    api->ReleaseStatus(status);
    return false;
}

// ============================================================================
// HELPER: Validate CortexModelType index
// ============================================================================

[[nodiscard]] static bool IsValidModelType(CortexModelType type) noexcept {
    return static_cast<size_t>(type) < CortexConstants::MODEL_COUNT;
}

// ============================================================================
// HELPER: Compute SHA-256 hex digest of a file using HashUtils
// ============================================================================

[[nodiscard]] static std::wstring ComputeModelFileHash(const std::filesystem::path& filePath) noexcept {
    using namespace ShadowStrike::Utils::HashUtils;

    Hasher hasher(Algorithm::SHA256);
    if (!hasher.Init()) {
        SS_LOG_ERROR(kLogTag, L"ComputeModelFileHash: Hasher init failed for %ls",
                     filePath.c_str());
        return {};
    }

    // Read file in chunks to avoid large allocations
    constexpr size_t kChunkSize = 1u << 20; // 1 MB
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs.is_open()) {
        SS_LOG_ERROR(kLogTag, L"ComputeModelFileHash: cannot open %ls", filePath.c_str());
        return {};
    }

    std::vector<char> buf;
    try {
        buf.resize(kChunkSize);
    } catch (...) {
        SS_LOG_ERROR(kLogTag, L"ComputeModelFileHash: allocation failed");
        return {};
    }

    while (ifs.good()) {
        ifs.read(buf.data(), static_cast<std::streamsize>(kChunkSize));
        const auto bytesRead = static_cast<size_t>(ifs.gcount());
        if (bytesRead == 0) break;
        if (!hasher.Update(buf.data(), bytesRead)) {
            SS_LOG_ERROR(kLogTag, L"ComputeModelFileHash: Hasher update failed");
            return {};
        }
    }

    std::vector<uint8_t> digest;
    if (!hasher.Final(digest)) {
        SS_LOG_ERROR(kLogTag, L"ComputeModelFileHash: Hasher finalize failed");
        return {};
    }

    // Convert to lowercase hex wstring
    const std::string hexNarrow = ToHexLower(digest);
    std::wstring hexWide;
    try {
        hexWide.reserve(hexNarrow.size());
        for (char c : hexNarrow) hexWide.push_back(static_cast<wchar_t>(c));
    } catch (...) {
        SS_LOG_ERROR(kLogTag, L"ComputeModelFileHash: wstring conversion failed");
        return {};
    }

    return hexWide;
}

// ============================================================================
// IMPL DEFINITION
// ============================================================================

struct ModelInference::Impl {
    // ----------------------------------------------------------------
    // ORT environment (one per process)
    // ----------------------------------------------------------------
    OrtEnv* env = nullptr;

    // ----------------------------------------------------------------
    // Per-model slots
    // ----------------------------------------------------------------
    struct ModelSlot {
        OrtSession*        session        = nullptr;
        OrtSessionOptions* sessionOptions = nullptr;

        std::vector<std::string>            inputNames;
        std::vector<std::string>            outputNames;
        std::vector<std::vector<int64_t>>   inputShapes;
        std::vector<std::vector<int64_t>>   outputShapes;

        ModelVersion version{};
        bool         loaded = false;
    };
    std::array<ModelSlot, CortexConstants::MODEL_COUNT> slots{};

    // ----------------------------------------------------------------
    // Thread safety — shared for inference, exclusive for load/unload
    // ----------------------------------------------------------------
    mutable std::shared_mutex modelMutex;

    // ----------------------------------------------------------------
    // Hardware caps (immutable after Initialize)
    // ----------------------------------------------------------------
    bool hasAVX2    = false;
    bool hasAVX512  = false;
    bool hasDirectML = false;

    // ----------------------------------------------------------------
    // State
    // ----------------------------------------------------------------
    bool          initialized = false;
    CortexConfig  config{};

    // ----------------------------------------------------------------
    // ORT API handle (immutable after Initialize)
    // ----------------------------------------------------------------
    const OrtApi* ortApi     = nullptr;
    OrtMemoryInfo* memoryInfo = nullptr;

    // ----------------------------------------------------------------
    // Release a single model slot (caller must hold exclusive lock)
    // ----------------------------------------------------------------
    void ReleaseSlot(ModelSlot& slot) noexcept {
        if (!ortApi) return;
        if (slot.session) {
            ortApi->ReleaseSession(slot.session);
            slot.session = nullptr;
        }
        if (slot.sessionOptions) {
            ortApi->ReleaseSessionOptions(slot.sessionOptions);
            slot.sessionOptions = nullptr;
        }
        slot.inputNames.clear();
        slot.outputNames.clear();
        slot.inputShapes.clear();
        slot.outputShapes.clear();
        slot.version = ModelVersion{};
        slot.loaded  = false;
    }

    // ----------------------------------------------------------------
    // Release all ORT resources
    // ----------------------------------------------------------------
    void ReleaseAll() noexcept {
        for (auto& slot : slots) {
            ReleaseSlot(slot);
        }
        if (ortApi && memoryInfo) {
            ortApi->ReleaseMemoryInfo(memoryInfo);
            memoryInfo = nullptr;
        }
        if (ortApi && env) {
            ortApi->ReleaseEnv(env);
            env = nullptr;
        }
        initialized = false;
    }
};

// ============================================================================
// HARDWARE DETECTION
// ============================================================================

namespace {

struct CpuFeatures {
    bool avx2    = false;
    bool avx512f = false;
};

[[nodiscard]] CpuFeatures DetectCpuFeatures() noexcept {
    CpuFeatures feat{};

    // Check max CPUID leaf
    int cpuInfo[4]{};
    __cpuid(cpuInfo, 0);
    const int maxLeaf = cpuInfo[0];

    if (maxLeaf < 7) return feat;

    // CPUID leaf 7, sub-leaf 0 — Extended Features
    __cpuidex(cpuInfo, 7, 0);
    const uint32_t ebx7 = static_cast<uint32_t>(cpuInfo[1]);

    const bool cpuHasAVX2    = (ebx7 & (1u << 5))  != 0;
    const bool cpuHasAVX512F = (ebx7 & (1u << 16)) != 0;

    // Verify OS support via XGETBV (XCR0)
    // Leaf 1 tells us if OSXSAVE is enabled (ECX bit 27)
    __cpuid(cpuInfo, 1);
    const uint32_t ecx1 = static_cast<uint32_t>(cpuInfo[2]);
    const bool osxsave = (ecx1 & (1u << 27)) != 0;

    if (!osxsave) return feat;

    // Read XCR0 to check OS-level register support
    const unsigned long long xcr0 = _xgetbv(0);

    // YMM state: bits 1 (SSE) and 2 (AVX) must be set
    constexpr unsigned long long kYmmMask = 0x06ULL;
    if ((xcr0 & kYmmMask) == kYmmMask && cpuHasAVX2) {
        feat.avx2 = true;
    }

    // ZMM state: bits 5, 6, 7 (opmask, ZMM_Hi256, Hi16_ZMM) plus YMM
    constexpr unsigned long long kZmmMask = 0xE6ULL;
    if ((xcr0 & kZmmMask) == kZmmMask && cpuHasAVX512F) {
        feat.avx512f = true;
    }

    return feat;
}

/// Attempt DirectML probe by trying to set the DML execution provider on
/// a temporary session options object. If this succeeds the GPU is usable.
[[nodiscard]] bool ProbeDirectML(const OrtApi* api) noexcept {
    if (!api) return false;

    OrtSessionOptions* opts = nullptr;
    OrtStatus* st = api->CreateSessionOptions(&opts);
    if (st != nullptr) {
        api->ReleaseStatus(st);
        return false;
    }

    // OrtSessionOptionsAppendExecutionProvider_DML is a standalone C
    // function exported by the DirectML execution provider library.
    // We resolve it dynamically so the core binary can run without
    // the DML provider DLL being present.
    using AppendDmlFn = OrtStatusPtr(ORT_API_CALL*)(OrtSessionOptions*, int);
    HMODULE hDml = GetModuleHandleW(L"onnxruntime_providers_dml.dll");
    if (!hDml) {
        hDml = LoadLibraryExW(L"onnxruntime_providers_dml.dll", nullptr,
                              LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    }

    bool result = false;
    if (hDml) {
        auto appendFn = reinterpret_cast<AppendDmlFn>(
            GetProcAddress(hDml, "OrtSessionOptionsAppendExecutionProvider_DML"));
        if (appendFn) {
            OrtStatus* dmlSt = appendFn(opts, 0);
            if (dmlSt == nullptr) {
                result = true;
            } else {
                api->ReleaseStatus(dmlSt);
            }
        }
    }

    api->ReleaseSessionOptions(opts);
    return result;
}

/// Try to append DirectML provider to a given session options (for real model loading).
bool AppendDirectMLProvider(const OrtApi* api, OrtSessionOptions* opts) noexcept {
    if (!api || !opts) return false;

    using AppendDmlFn = OrtStatusPtr(ORT_API_CALL*)(OrtSessionOptions*, int);
    HMODULE hDml = GetModuleHandleW(L"onnxruntime_providers_dml.dll");
    if (!hDml) return false;

    auto appendFn = reinterpret_cast<AppendDmlFn>(
        GetProcAddress(hDml, "OrtSessionOptionsAppendExecutionProvider_DML"));
    if (!appendFn) return false;

    OrtStatus* st = appendFn(opts, 0);
    if (st != nullptr) {
        const char* msg = api->GetErrorMessage(st);
        if (msg) {
            wchar_t wbuf[256]{};
            MultiByteToWideChar(CP_UTF8, 0, msg, -1, wbuf, _countof(wbuf) - 1);
            SS_LOG_WARN(kLogTag, L"DirectML append failed: %ls", wbuf);
        }
        api->ReleaseStatus(st);
        return false;
    }
    return true;
}

} // anonymous namespace

// ============================================================================
// SINGLETON
// ============================================================================

ModelInference& ModelInference::Instance() noexcept {
    static ModelInference s_instance;
    return s_instance;
}

// ============================================================================
// DESTRUCTOR
// ============================================================================

ModelInference::~ModelInference() {
    Shutdown();
}

// ============================================================================
// Constructor — eagerly create Impl so modelMutex is available immediately
// ============================================================================

ModelInference::ModelInference() {
    try {
        m_impl = std::make_unique<Impl>();
    } catch (...) {
        // m_impl remains null — Initialize() will report the failure.
    }
}

// ============================================================================
// Initialize
// ============================================================================

bool ModelInference::Initialize(const CortexConfig& config) noexcept {
    try {
        if (!m_impl) {
            SS_LOG_ERROR(kLogTag, L"Initialize: Impl allocation failed at construction");
            return false;
        }

        std::unique_lock lock(m_impl->modelMutex);

        if (m_impl->initialized) {
            SS_LOG_INFO(kLogTag, L"Initialize: already initialized, returning true");
            return true;
        }

        // -----------------------------------------------------------
        // 1. Obtain the ORT C API
        // -----------------------------------------------------------
        const OrtApiBase* apiBase = OrtGetApiBase();
        if (!apiBase) {
            SS_LOG_ERROR(kLogTag, L"Initialize: OrtGetApiBase() returned null");
            return false;
        }

        m_impl->ortApi = apiBase->GetApi(ORT_API_VERSION);
        if (!m_impl->ortApi) {
            SS_LOG_ERROR(kLogTag, L"Initialize: GetApi(ORT_API_VERSION=%d) returned null",
                         static_cast<int>(ORT_API_VERSION));
            return false;
        }

        const OrtApi* api = m_impl->ortApi;

        // -----------------------------------------------------------
        // 2. Create ORT environment
        // -----------------------------------------------------------
        if (!CheckOrtStatus(api,
                api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "PhantomCortex", &m_impl->env),
                L"CreateEnv")) {
            return false;
        }

        // Per-session thread-pool spinning is disabled on each SessionOptions
        // in LoadModel() below.  The env-level DisablePerSessionThreads API
        // takes OrtThreadingOptions, which we do not configure here.

        // -----------------------------------------------------------
        // 3. Detect hardware capabilities
        // -----------------------------------------------------------
        const CpuFeatures cpuFeat = DetectCpuFeatures();
        m_impl->hasAVX2   = cpuFeat.avx2;
        m_impl->hasAVX512 = cpuFeat.avx512f;

        SS_LOG_INFO(kLogTag, L"Initialize: CPU caps — AVX2=%d, AVX-512F=%d",
                    static_cast<int>(m_impl->hasAVX2),
                    static_cast<int>(m_impl->hasAVX512));

        // -----------------------------------------------------------
        // 4. Probe DirectML (GPU)
        // -----------------------------------------------------------
        if (config.useGPU) {
            m_impl->hasDirectML = ProbeDirectML(api);
            SS_LOG_INFO(kLogTag, L"Initialize: DirectML available=%d",
                        static_cast<int>(m_impl->hasDirectML));
        } else {
            m_impl->hasDirectML = false;
            SS_LOG_INFO(kLogTag, L"Initialize: GPU disabled by config");
        }

        // -----------------------------------------------------------
        // 5. Create CPU memory info (used for tensor creation)
        // -----------------------------------------------------------
        if (!CheckOrtStatus(api,
                api->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault,
                                         &m_impl->memoryInfo),
                L"CreateCpuMemoryInfo")) {
            m_impl->ReleaseAll();
            return false;
        }

        // -----------------------------------------------------------
        // 6. Store config and mark initialized
        // -----------------------------------------------------------
        m_impl->config      = config;
        m_impl->initialized = true;

        SS_LOG_INFO(kLogTag, L"Initialize: ONNX Runtime environment created successfully");

        // -----------------------------------------------------------
        // 7. Auto-load models from modelDirectory (best-effort)
        // -----------------------------------------------------------
        if (!config.modelDirectory.empty()) {
            // Release the exclusive lock while loading models
            // (LoadModel acquires its own exclusive lock).
            lock.unlock();

            std::error_code ec;
            for (size_t i = 0; i < CortexConstants::MODEL_COUNT; ++i) {
                const auto modelPath = config.modelDirectory / kModelFileNames[i];
                if (std::filesystem::exists(modelPath, ec)) {
                    SS_LOG_INFO(kLogTag, L"Initialize: auto-loading %ls", kModelFileNames[i]);
                    if (!LoadModel(static_cast<CortexModelType>(i), modelPath)) {
                        SS_LOG_WARN(kLogTag, L"Initialize: auto-load failed for %ls",
                                    kModelFileNames[i]);
                    }
                }
            }
        }

        return true;
    } catch (...) {
        SS_LOG_ERROR(kLogTag, L"Initialize: unexpected exception caught");
        return false;
    }
}

// ============================================================================
// Shutdown
// ============================================================================

void ModelInference::Shutdown() noexcept {
    try {
        if (!m_impl) return;

        std::unique_lock lock(m_impl->modelMutex);
        if (!m_impl->initialized) return;

        SS_LOG_INFO(kLogTag, L"Shutdown: releasing all ORT resources");
        m_impl->ReleaseAll();
    } catch (...) {
        // Logging might throw during process teardown — swallow.
    }
}

// ============================================================================
// IsInitialized
// ============================================================================

bool ModelInference::IsInitialized() const noexcept {
    if (!m_impl) return false;
    std::shared_lock lock(m_impl->modelMutex);
    return m_impl->initialized;
}

// ============================================================================
// LoadModel
// ============================================================================

bool ModelInference::LoadModel(CortexModelType type,
                               const std::filesystem::path& onnxPath) noexcept {
    try {
        if (!m_impl) {
            SS_LOG_ERROR(kLogTag, L"LoadModel: not initialized (null impl)");
            return false;
        }

        if (!IsValidModelType(type)) {
            SS_LOG_ERROR(kLogTag, L"LoadModel: invalid model type %d",
                         static_cast<int>(type));
            return false;
        }

        const size_t idx = static_cast<size_t>(type);
        const OrtApi* api = m_impl->ortApi;

        // -----------------------------------------------------------
        // Validate file exists and is within size limits
        // -----------------------------------------------------------
        std::error_code ec;
        if (!std::filesystem::exists(onnxPath, ec) || ec) {
            SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): file does not exist — %ls",
                         kModelTypeNames[idx], onnxPath.c_str());
            return false;
        }

        const auto fileSize = std::filesystem::file_size(onnxPath, ec);
        if (ec) {
            SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): cannot stat file — %ls",
                         kModelTypeNames[idx], onnxPath.c_str());
            return false;
        }
        if (fileSize == 0) {
            SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): model file is empty",
                         kModelTypeNames[idx]);
            return false;
        }
        if (fileSize > CortexConstants::MAX_MODEL_FILE_SIZE) {
            SS_LOG_ERROR(kLogTag,
                L"LoadModel(%ls): model file exceeds size limit (%llu > %llu bytes)",
                kModelTypeNames[idx],
                static_cast<unsigned long long>(fileSize),
                static_cast<unsigned long long>(CortexConstants::MAX_MODEL_FILE_SIZE));
            return false;
        }

        // -----------------------------------------------------------
        // Compute SHA-256 of the model file (before loading into ORT)
        // -----------------------------------------------------------
        const std::wstring modelHash = ComputeModelFileHash(onnxPath);
        if (modelHash.empty()) {
            SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): SHA-256 computation failed",
                         kModelTypeNames[idx]);
            return false;
        }

        // -----------------------------------------------------------
        // Create session options
        // -----------------------------------------------------------
        OrtSessionOptions* rawOpts = nullptr;
        if (!CheckOrtStatus(api, api->CreateSessionOptions(&rawOpts),
                            L"CreateSessionOptions")) {
            return false;
        }

        // Wrap in a scoped handle for exception/error safety.
        // We'll release ownership on success.
        struct ScopedOpts {
            const OrtApi* api; OrtSessionOptions* p;
            ~ScopedOpts() { if (api && p) api->ReleaseSessionOptions(p); }
        } optsGuard{api, rawOpts};

        // Thread pool — use all logical cores
        const unsigned int threadCount = std::max(1u, std::thread::hardware_concurrency());
        if (!CheckOrtStatus(api,
                api->SetIntraOpNumThreads(rawOpts, static_cast<int>(threadCount)),
                L"SetIntraOpNumThreads")) {
            return false;
        }

        // Graph optimization level
        if (!CheckOrtStatus(api,
                api->SetSessionGraphOptimizationLevel(rawOpts, ORT_ENABLE_ALL),
                L"SetSessionGraphOptimizationLevel")) {
            return false;
        }

        // -----------------------------------------------------------
        // Execution provider: DirectML (GPU) if available and enabled
        // -----------------------------------------------------------
        {
            std::shared_lock readLock(m_impl->modelMutex);
            if (m_impl->config.useGPU && m_impl->hasDirectML) {
                readLock.unlock();
                if (AppendDirectMLProvider(api, rawOpts)) {
                    SS_LOG_INFO(kLogTag, L"LoadModel(%ls): DirectML EP attached",
                                kModelTypeNames[idx]);
                } else {
                    SS_LOG_WARN(kLogTag, L"LoadModel(%ls): DirectML unavailable, using CPU",
                                kModelTypeNames[idx]);
                }
            }
        }

        // -----------------------------------------------------------
        // Create ORT session from file
        // -----------------------------------------------------------
        OrtSession* rawSession = nullptr;
        if (!CheckOrtStatus(api,
                api->CreateSession(m_impl->env, onnxPath.c_str(), rawOpts, &rawSession),
                L"CreateSession")) {
            return false;
        }

        // Wrap session for cleanup on error
        struct ScopedSession {
            const OrtApi* api; OrtSession* p;
            ~ScopedSession() { if (api && p) api->ReleaseSession(p); }
        } sessGuard{api, rawSession};

        // -----------------------------------------------------------
        // Query allocator for name retrieval
        // -----------------------------------------------------------
        OrtAllocator* allocator = nullptr;
        if (!CheckOrtStatus(api,
                api->GetAllocatorWithDefaultOptions(&allocator),
                L"GetAllocatorWithDefaultOptions")) {
            return false;
        }

        // -----------------------------------------------------------
        // Query input metadata
        // -----------------------------------------------------------
        size_t numInputs = 0;
        if (!CheckOrtStatus(api,
                api->SessionGetInputCount(rawSession, &numInputs),
                L"SessionGetInputCount")) {
            return false;
        }

        std::vector<std::string>          inputNames;
        std::vector<std::vector<int64_t>> inputShapes;

        try {
            inputNames.reserve(numInputs);
            inputShapes.reserve(numInputs);
        } catch (...) {
            SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): allocation failed for input metadata",
                         kModelTypeNames[idx]);
            return false;
        }

        for (size_t i = 0; i < numInputs; ++i) {
            char* name = nullptr;
            if (!CheckOrtStatus(api,
                    api->SessionGetInputName(rawSession, i, allocator, &name),
                    L"SessionGetInputName")) {
                return false;
            }
            try {
                inputNames.emplace_back(name ? name : "");
            } catch (...) {
                if (name) allocator->Free(allocator, name);
                return false;
            }
            if (name) allocator->Free(allocator, name);

            OrtTypeInfo* typeInfo = nullptr;
            if (!CheckOrtStatus(api,
                    api->SessionGetInputTypeInfo(rawSession, i, &typeInfo),
                    L"SessionGetInputTypeInfo")) {
                return false;
            }

            const OrtTensorTypeAndShapeInfo* tensorInfo = nullptr;
            if (!CheckOrtStatus(api,
                    api->CastTypeInfoToTensorInfo(typeInfo, &tensorInfo),
                    L"CastTypeInfoToTensorInfo")) {
                api->ReleaseTypeInfo(typeInfo);
                return false;
            }

            size_t dimCount = 0;
            if (!CheckOrtStatus(api,
                    api->GetDimensionsCount(tensorInfo, &dimCount),
                    L"GetDimensionsCount")) {
                api->ReleaseTypeInfo(typeInfo);
                return false;
            }

            std::vector<int64_t> dims(dimCount, 0);
            if (dimCount > 0) {
                if (!CheckOrtStatus(api,
                        api->GetDimensions(tensorInfo, dims.data(), dimCount),
                        L"GetDimensions")) {
                    api->ReleaseTypeInfo(typeInfo);
                    return false;
                }
            }

            api->ReleaseTypeInfo(typeInfo);

            try {
                inputShapes.push_back(std::move(dims));
            } catch (...) {
                SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): allocation failed for input shape",
                             kModelTypeNames[idx]);
                return false;
            }
        }

        // -----------------------------------------------------------
        // Query output metadata
        // -----------------------------------------------------------
        size_t numOutputs = 0;
        if (!CheckOrtStatus(api,
                api->SessionGetOutputCount(rawSession, &numOutputs),
                L"SessionGetOutputCount")) {
            return false;
        }

        std::vector<std::string>          outputNames;
        std::vector<std::vector<int64_t>> outputShapes;

        try {
            outputNames.reserve(numOutputs);
            outputShapes.reserve(numOutputs);
        } catch (...) {
            SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): allocation failed for output metadata",
                         kModelTypeNames[idx]);
            return false;
        }

        for (size_t i = 0; i < numOutputs; ++i) {
            char* name = nullptr;
            if (!CheckOrtStatus(api,
                    api->SessionGetOutputName(rawSession, i, allocator, &name),
                    L"SessionGetOutputName")) {
                return false;
            }
            try {
                outputNames.emplace_back(name ? name : "");
            } catch (...) {
                if (name) allocator->Free(allocator, name);
                return false;
            }
            if (name) allocator->Free(allocator, name);

            OrtTypeInfo* typeInfo = nullptr;
            if (!CheckOrtStatus(api,
                    api->SessionGetOutputTypeInfo(rawSession, i, &typeInfo),
                    L"SessionGetOutputTypeInfo")) {
                return false;
            }

            const OrtTensorTypeAndShapeInfo* tensorInfo = nullptr;
            if (!CheckOrtStatus(api,
                    api->CastTypeInfoToTensorInfo(typeInfo, &tensorInfo),
                    L"CastTypeInfoToTensorInfo(output)")) {
                api->ReleaseTypeInfo(typeInfo);
                return false;
            }

            size_t dimCount = 0;
            if (!CheckOrtStatus(api,
                    api->GetDimensionsCount(tensorInfo, &dimCount),
                    L"GetDimensionsCount(output)")) {
                api->ReleaseTypeInfo(typeInfo);
                return false;
            }

            std::vector<int64_t> dims(dimCount, 0);
            if (dimCount > 0) {
                if (!CheckOrtStatus(api,
                        api->GetDimensions(tensorInfo, dims.data(), dimCount),
                        L"GetDimensions(output)")) {
                    api->ReleaseTypeInfo(typeInfo);
                    return false;
                }
            }

            api->ReleaseTypeInfo(typeInfo);

            try {
                outputShapes.push_back(std::move(dims));
            } catch (...) {
                SS_LOG_ERROR(kLogTag, L"LoadModel(%ls): allocation failed for output shape",
                             kModelTypeNames[idx]);
                return false;
            }
        }

        // -----------------------------------------------------------
        // Build ModelVersion
        // -----------------------------------------------------------
        ModelVersion ver{};
        ver.major     = 1;
        ver.minor     = 0;
        ver.patch     = 0;
        ver.modelHash = modelHash;
        ver.trainedAt = std::chrono::system_clock::now();

        // Try to read version from ORT model metadata
        {
            OrtModelMetadata* meta = nullptr;
            OrtStatus* metaSt = api->SessionGetModelMetadata(rawSession, &meta);
            if (metaSt == nullptr && meta) {
                // Read "version" custom metadata key if present
                char* verStr = nullptr;
                OrtStatus* verSt = api->ModelMetadataLookupCustomMetadataMap(
                    meta, allocator, "version", &verStr);
                if (verSt == nullptr && verStr) {
                    // Parse "major.minor.patch"
                    unsigned int maj = 0, min = 0, pat = 0;
                    if (sscanf_s(verStr, "%u.%u.%u", &maj, &min, &pat) >= 1) {
                        ver.major = maj;
                        ver.minor = min;
                        ver.patch = pat;
                    }
                    allocator->Free(allocator, verStr);
                } else if (verSt) {
                    api->ReleaseStatus(verSt);
                }

                api->ReleaseModelMetadata(meta);
            } else if (metaSt) {
                api->ReleaseStatus(metaSt);
            }
        }

        // -----------------------------------------------------------
        // Commit to slot under exclusive lock
        // -----------------------------------------------------------
        size_t committedInputCount  = 0;
        size_t committedOutputCount = 0;
        {
            std::unique_lock lock(m_impl->modelMutex);
            if (!m_impl->initialized) {
                SS_LOG_ERROR(kLogTag,
                    L"LoadModel(%ls): engine was shut down during load",
                    kModelTypeNames[idx]);
                return false;
            }

            Impl::ModelSlot& slot = m_impl->slots[idx];

            // Release previous session if replacing
            m_impl->ReleaseSlot(slot);

            // Transfer ownership
            slot.session        = sessGuard.p;   sessGuard.p = nullptr;
            slot.sessionOptions = optsGuard.p;   optsGuard.p = nullptr;
            slot.inputNames     = std::move(inputNames);
            slot.outputNames    = std::move(outputNames);
            slot.inputShapes    = std::move(inputShapes);
            slot.outputShapes   = std::move(outputShapes);
            slot.version        = std::move(ver);
            slot.loaded         = true;

            // Capture metadata while still under lock to avoid data race
            committedInputCount  = slot.inputNames.size();
            committedOutputCount = slot.outputNames.size();
        }

        SS_LOG_INFO(kLogTag,
            L"LoadModel(%ls): loaded successfully (inputs=%zu, outputs=%zu, hash=%.16ls...)",
            kModelTypeNames[idx],
            committedInputCount,
            committedOutputCount,
            modelHash.c_str());

        return true;
    } catch (...) {
        SS_LOG_ERROR(kLogTag, L"LoadModel: unexpected exception caught");
        return false;
    }
}

// ============================================================================
// UnloadModel
// ============================================================================

void ModelInference::UnloadModel(CortexModelType type) noexcept {
    try {
        if (!m_impl) return;
        if (!IsValidModelType(type)) return;

        const size_t idx = static_cast<size_t>(type);

        std::unique_lock lock(m_impl->modelMutex);
        if (!m_impl->initialized) return;

        Impl::ModelSlot& slot = m_impl->slots[idx];
        if (!slot.loaded) return;

        SS_LOG_INFO(kLogTag, L"UnloadModel(%ls): releasing session",
                    kModelTypeNames[idx]);
        m_impl->ReleaseSlot(slot);
    } catch (...) {
        // Swallow — shutdown path.
    }
}

// ============================================================================
// Infer (single sample)
// ============================================================================

std::optional<std::vector<float>> ModelInference::Infer(
    CortexModelType type,
    std::span<const float> inputData,
    std::span<const int64_t> inputShape) noexcept {
    try {
        if (!m_impl) {
            SS_LOG_ERROR(kLogTag, L"Infer: engine not initialized");
            return std::nullopt;
        }
        if (!IsValidModelType(type)) {
            SS_LOG_ERROR(kLogTag, L"Infer: invalid model type %d",
                         static_cast<int>(type));
            return std::nullopt;
        }

        const size_t idx = static_cast<size_t>(type);
        const OrtApi* api = m_impl->ortApi;

        // Validate input span
        if (inputData.empty() || inputShape.empty()) {
            SS_LOG_ERROR(kLogTag, L"Infer(%ls): empty input data or shape",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }

        // Validate shape product matches data size
        int64_t expectedElems = 1;
        for (auto dim : inputShape) {
            if (dim <= 0) {
                SS_LOG_ERROR(kLogTag,
                    L"Infer(%ls): invalid dimension %lld in input shape",
                    kModelTypeNames[idx], static_cast<long long>(dim));
                return std::nullopt;
            }
            // Overflow check
            if (expectedElems > (std::numeric_limits<int64_t>::max() / dim)) {
                SS_LOG_ERROR(kLogTag, L"Infer(%ls): shape dimension overflow",
                             kModelTypeNames[idx]);
                return std::nullopt;
            }
            expectedElems *= dim;
        }
        if (static_cast<size_t>(expectedElems) != inputData.size()) {
            SS_LOG_ERROR(kLogTag,
                L"Infer(%ls): shape product (%lld) != data size (%zu)",
                kModelTypeNames[idx],
                static_cast<long long>(expectedElems),
                inputData.size());
            return std::nullopt;
        }

        // -----------------------------------------------------------
        // Shared lock — ORT sessions are thread-safe for Run()
        // -----------------------------------------------------------
        std::shared_lock lock(m_impl->modelMutex);

        if (!m_impl->initialized) {
            SS_LOG_ERROR(kLogTag, L"Infer(%ls): engine not initialized",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }

        const Impl::ModelSlot& slot = m_impl->slots[idx];
        if (!slot.loaded || !slot.session) {
            SS_LOG_ERROR(kLogTag, L"Infer(%ls): model not loaded", kModelTypeNames[idx]);
            return std::nullopt;
        }
        if (slot.inputNames.empty() || slot.outputNames.empty()) {
            SS_LOG_ERROR(kLogTag, L"Infer(%ls): model has no input/output names",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }

        // Reject multi-input/output models — current API handles exactly one
        if (slot.inputNames.size() != 1 || slot.outputNames.size() != 1) {
            SS_LOG_ERROR(kLogTag,
                L"Infer(%ls): expected single-input/single-output model "
                L"(got %zu inputs, %zu outputs)",
                kModelTypeNames[idx],
                slot.inputNames.size(), slot.outputNames.size());
            return std::nullopt;
        }

        // Validate caller's shape against model's expected input dimensions
        if (!slot.inputShapes.empty()) {
            const auto& expected = slot.inputShapes[0];
            if (inputShape.size() != expected.size()) {
                SS_LOG_ERROR(kLogTag,
                    L"Infer(%ls): shape rank mismatch (model expects %zu dims, got %zu)",
                    kModelTypeNames[idx], expected.size(), inputShape.size());
                return std::nullopt;
            }
            for (size_t d = 0; d < expected.size(); ++d) {
                // Dynamic dimensions (<=0 in ONNX) are skipped
                if (expected[d] > 0 && inputShape[d] != expected[d]) {
                    SS_LOG_ERROR(kLogTag,
                        L"Infer(%ls): dim[%zu] mismatch (model expects %lld, got %lld)",
                        kModelTypeNames[idx], d,
                        static_cast<long long>(expected[d]),
                        static_cast<long long>(inputShape[d]));
                    return std::nullopt;
                }
            }
        }

        // -----------------------------------------------------------
        // Create input tensor
        // -----------------------------------------------------------
        OrtValue* inputTensor = nullptr;
        if (!CheckOrtStatus(api,
                api->CreateTensorWithDataAsOrtValue(
                    m_impl->memoryInfo,
                    // ORT C API takes void* but does not modify input tensor data
                    const_cast<float*>(inputData.data()),
                    inputData.size_bytes(),
                    inputShape.data(),
                    inputShape.size(),
                    ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
                    &inputTensor),
                L"CreateTensorWithDataAsOrtValue")) {
            return std::nullopt;
        }

        // RAII release for input tensor
        struct TensorGuard {
            const OrtApi* api; OrtValue* v;
            ~TensorGuard() { if (api && v) api->ReleaseValue(v); }
        } inputGuard{api, inputTensor};

        // -----------------------------------------------------------
        // Prepare name arrays for Run()
        // -----------------------------------------------------------
        const char* inName  = slot.inputNames[0].c_str();
        const char* outName = slot.outputNames[0].c_str();

        // -----------------------------------------------------------
        // Create run options with timeout termination
        // -----------------------------------------------------------
        OrtRunOptions* runOpts = nullptr;
        if (!CheckOrtStatus(api, api->CreateRunOptions(&runOpts),
                            L"CreateRunOptions")) {
            return std::nullopt;
        }
        struct RunOptsGuard {
            const OrtApi* a; OrtRunOptions* p;
            ~RunOptsGuard() { if (a && p) a->ReleaseRunOptions(p); }
        } runOptsGuard{api, runOpts};

        const uint32_t timeoutMs = m_impl->config.inferenceTimeoutMs;
        std::atomic<bool> inferDone{false};
        std::thread timeoutWatcher;
        if (timeoutMs > 0) {
            try {
                timeoutWatcher = std::thread(
                    [api, runOpts, timeoutMs, &inferDone]() noexcept {
                        const auto deadline = std::chrono::steady_clock::now()
                                            + std::chrono::milliseconds(timeoutMs);
                        while (std::chrono::steady_clock::now() < deadline) {
                            if (inferDone.load(std::memory_order_acquire)) return;
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        }
                        if (!inferDone.load(std::memory_order_acquire)) {
                            api->RunOptionsSetTerminate(runOpts);
                        }
                    });
            } catch (...) {
                SS_LOG_WARN(kLogTag, L"Infer(%ls): timeout thread creation failed",
                            kModelTypeNames[idx]);
            }
        }

        // -----------------------------------------------------------
        // Run inference
        // -----------------------------------------------------------
        OrtValue* outputTensor = nullptr;
        const bool runOk = CheckOrtStatus(api,
                api->Run(slot.session,
                         runOpts,
                         &inName, &inputTensor, 1,
                         &outName, 1, &outputTensor),
                L"Run");

        // Signal timeout thread to exit and wait for it
        inferDone.store(true, std::memory_order_release);
        if (timeoutWatcher.joinable()) timeoutWatcher.join();

        if (!runOk) return std::nullopt;

        TensorGuard outputGuard{api, outputTensor};

        // -----------------------------------------------------------
        // Extract output data
        // -----------------------------------------------------------
        float* outputData = nullptr;
        if (!CheckOrtStatus(api,
                api->GetTensorMutableData(outputTensor, reinterpret_cast<void**>(&outputData)),
                L"GetTensorMutableData")) {
            return std::nullopt;
        }

        // Determine output element count
        OrtTensorTypeAndShapeInfo* outInfo = nullptr;
        if (!CheckOrtStatus(api,
                api->GetTensorTypeAndShape(outputTensor, &outInfo),
                L"GetTensorTypeAndShape")) {
            return std::nullopt;
        }

        size_t outElemCount = 0;
        OrtStatus* countSt = api->GetTensorShapeElementCount(outInfo, &outElemCount);
        api->ReleaseTensorTypeAndShapeInfo(outInfo);
        if (!CheckOrtStatus(api, countSt, L"GetTensorShapeElementCount")) {
            return std::nullopt;
        }

        if (outElemCount == 0 || !outputData) {
            SS_LOG_ERROR(kLogTag, L"Infer(%ls): output tensor is empty",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }

        // Copy to result vector
        try {
            return std::vector<float>(outputData, outputData + outElemCount);
        } catch (...) {
            SS_LOG_ERROR(kLogTag, L"Infer(%ls): output vector allocation failed",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }
    } catch (...) {
        SS_LOG_ERROR(kLogTag, L"Infer: unexpected exception");
        return std::nullopt;
    }
}

// ============================================================================
// InferBatch
// ============================================================================

std::optional<std::vector<std::vector<float>>> ModelInference::InferBatch(
    CortexModelType type,
    std::span<const float> batchData,
    std::span<const int64_t> batchShape) noexcept {
    try {
        if (!m_impl) {
            SS_LOG_ERROR(kLogTag, L"InferBatch: engine not initialized");
            return std::nullopt;
        }
        if (!IsValidModelType(type)) {
            SS_LOG_ERROR(kLogTag, L"InferBatch: invalid model type %d",
                         static_cast<int>(type));
            return std::nullopt;
        }

        const size_t idx = static_cast<size_t>(type);

        // Validate batch shape has at least 2 dimensions
        if (batchShape.size() < 2) {
            SS_LOG_ERROR(kLogTag,
                L"InferBatch(%ls): batchShape must have >= 2 dimensions (got %zu)",
                kModelTypeNames[idx], batchShape.size());
            return std::nullopt;
        }

        const int64_t batchSize = batchShape[0];
        if (batchSize <= 0) {
            SS_LOG_ERROR(kLogTag, L"InferBatch(%ls): batch size must be > 0",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }
        if (batchSize > static_cast<int64_t>(CortexConstants::MAX_BATCH_SIZE)) {
            SS_LOG_ERROR(kLogTag,
                L"InferBatch(%ls): batch size %lld exceeds MAX_BATCH_SIZE (%u)",
                kModelTypeNames[idx],
                static_cast<long long>(batchSize),
                CortexConstants::MAX_BATCH_SIZE);
            return std::nullopt;
        }

        // Validate total element count
        int64_t totalExpected = 1;
        for (auto dim : batchShape) {
            if (dim <= 0) {
                SS_LOG_ERROR(kLogTag,
                    L"InferBatch(%ls): invalid dimension %lld",
                    kModelTypeNames[idx], static_cast<long long>(dim));
                return std::nullopt;
            }
            if (totalExpected > (std::numeric_limits<int64_t>::max() / dim)) {
                SS_LOG_ERROR(kLogTag, L"InferBatch(%ls): shape overflow",
                             kModelTypeNames[idx]);
                return std::nullopt;
            }
            totalExpected *= dim;
        }
        if (static_cast<size_t>(totalExpected) != batchData.size()) {
            SS_LOG_ERROR(kLogTag,
                L"InferBatch(%ls): shape product (%lld) != data size (%zu)",
                kModelTypeNames[idx],
                static_cast<long long>(totalExpected),
                batchData.size());
            return std::nullopt;
        }

        // -----------------------------------------------------------
        // Run full batch through ORT in a single call
        // -----------------------------------------------------------
        const OrtApi* api = m_impl->ortApi;

        std::shared_lock lock(m_impl->modelMutex);

        if (!m_impl->initialized) {
            SS_LOG_ERROR(kLogTag, L"InferBatch(%ls): engine not initialized",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }

        const Impl::ModelSlot& slot = m_impl->slots[idx];
        if (!slot.loaded || !slot.session) {
            SS_LOG_ERROR(kLogTag, L"InferBatch(%ls): model not loaded",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }
        if (slot.inputNames.empty() || slot.outputNames.empty()) {
            SS_LOG_ERROR(kLogTag, L"InferBatch(%ls): no input/output names",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }

        // Reject multi-input/output models — current API handles exactly one
        if (slot.inputNames.size() != 1 || slot.outputNames.size() != 1) {
            SS_LOG_ERROR(kLogTag,
                L"InferBatch(%ls): expected single-input/single-output model "
                L"(got %zu inputs, %zu outputs)",
                kModelTypeNames[idx],
                slot.inputNames.size(), slot.outputNames.size());
            return std::nullopt;
        }

        // Validate caller's shape against model's expected input dimensions
        // (skip dim[0] = batch, which is expected to vary)
        if (!slot.inputShapes.empty()) {
            const auto& expected = slot.inputShapes[0];
            if (batchShape.size() != expected.size()) {
                SS_LOG_ERROR(kLogTag,
                    L"InferBatch(%ls): shape rank mismatch (model expects %zu dims, got %zu)",
                    kModelTypeNames[idx], expected.size(), batchShape.size());
                return std::nullopt;
            }
            for (size_t d = 1; d < expected.size(); ++d) {
                if (expected[d] > 0 && batchShape[d] != expected[d]) {
                    SS_LOG_ERROR(kLogTag,
                        L"InferBatch(%ls): dim[%zu] mismatch (model expects %lld, got %lld)",
                        kModelTypeNames[idx], d,
                        static_cast<long long>(expected[d]),
                        static_cast<long long>(batchShape[d]));
                    return std::nullopt;
                }
            }
        }

        // Create input tensor
        OrtValue* inputTensor = nullptr;
        if (!CheckOrtStatus(api,
                api->CreateTensorWithDataAsOrtValue(
                    m_impl->memoryInfo,
                    // ORT C API takes void* but does not modify input tensor data
                    const_cast<float*>(batchData.data()),
                    batchData.size_bytes(),
                    batchShape.data(),
                    batchShape.size(),
                    ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
                    &inputTensor),
                L"CreateTensorWithDataAsOrtValue(batch)")) {
            return std::nullopt;
        }

        struct TensorGuard {
            const OrtApi* api; OrtValue* v;
            ~TensorGuard() { if (api && v) api->ReleaseValue(v); }
        } inputGuard{api, inputTensor};

        const char* inName  = slot.inputNames[0].c_str();
        const char* outName = slot.outputNames[0].c_str();

        // -----------------------------------------------------------
        // Create run options with timeout termination
        // -----------------------------------------------------------
        OrtRunOptions* runOpts = nullptr;
        if (!CheckOrtStatus(api, api->CreateRunOptions(&runOpts),
                            L"CreateRunOptions(batch)")) {
            return std::nullopt;
        }
        struct RunOptsGuard {
            const OrtApi* a; OrtRunOptions* p;
            ~RunOptsGuard() { if (a && p) a->ReleaseRunOptions(p); }
        } runOptsGuard{api, runOpts};

        const uint32_t timeoutMs = m_impl->config.inferenceTimeoutMs;
        std::atomic<bool> inferDone{false};
        std::thread timeoutWatcher;
        if (timeoutMs > 0) {
            try {
                timeoutWatcher = std::thread(
                    [api, runOpts, timeoutMs, &inferDone]() noexcept {
                        const auto deadline = std::chrono::steady_clock::now()
                                            + std::chrono::milliseconds(timeoutMs);
                        while (std::chrono::steady_clock::now() < deadline) {
                            if (inferDone.load(std::memory_order_acquire)) return;
                            std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        }
                        if (!inferDone.load(std::memory_order_acquire)) {
                            api->RunOptionsSetTerminate(runOpts);
                        }
                    });
            } catch (...) {
                SS_LOG_WARN(kLogTag, L"InferBatch(%ls): timeout thread creation failed",
                            kModelTypeNames[idx]);
            }
        }

        OrtValue* outputTensor = nullptr;
        const bool runOk = CheckOrtStatus(api,
                api->Run(slot.session,
                         runOpts,
                         &inName, &inputTensor, 1,
                         &outName, 1, &outputTensor),
                L"Run(batch)");

        // Signal timeout thread to exit and wait for it
        inferDone.store(true, std::memory_order_release);
        if (timeoutWatcher.joinable()) timeoutWatcher.join();

        if (!runOk) return std::nullopt;

        TensorGuard outputGuard{api, outputTensor};

        // Extract output
        float* outputData = nullptr;
        if (!CheckOrtStatus(api,
                api->GetTensorMutableData(outputTensor,
                                          reinterpret_cast<void**>(&outputData)),
                L"GetTensorMutableData(batch)")) {
            return std::nullopt;
        }

        // Get output shape to split into per-sample vectors
        OrtTensorTypeAndShapeInfo* outInfo = nullptr;
        if (!CheckOrtStatus(api,
                api->GetTensorTypeAndShape(outputTensor, &outInfo),
                L"GetTensorTypeAndShape(batch)")) {
            return std::nullopt;
        }

        size_t outDimCount = 0;
        if (!CheckOrtStatus(api,
                api->GetDimensionsCount(outInfo, &outDimCount),
                L"GetDimensionsCount(batch output)")) {
            api->ReleaseTensorTypeAndShapeInfo(outInfo);
            return std::nullopt;
        }

        std::vector<int64_t> outDims(outDimCount, 0);
        if (outDimCount > 0) {
            if (!CheckOrtStatus(api,
                    api->GetDimensions(outInfo, outDims.data(), outDimCount),
                    L"GetDimensions(batch output)")) {
                api->ReleaseTensorTypeAndShapeInfo(outInfo);
                return std::nullopt;
            }
        }

        size_t outElemCount = 0;
        OrtStatus* countSt = api->GetTensorShapeElementCount(outInfo, &outElemCount);
        api->ReleaseTensorTypeAndShapeInfo(outInfo);
        if (!CheckOrtStatus(api, countSt, L"GetTensorShapeElementCount(batch)")) {
            return std::nullopt;
        }

        if (outElemCount == 0 || !outputData) {
            SS_LOG_ERROR(kLogTag, L"InferBatch(%ls): empty output", kModelTypeNames[idx]);
            return std::nullopt;
        }

        // -----------------------------------------------------------
        // Split flat output into per-sample vectors
        // -----------------------------------------------------------
        // The output batch dimension should equal input batch dimension.
        // Per-sample element count = total / batchSize
        const int64_t actualBatch = (outDimCount > 0 && outDims[0] > 0)
                                    ? outDims[0] : batchSize;
        if (actualBatch <= 0 || static_cast<size_t>(actualBatch) > outElemCount) {
            SS_LOG_ERROR(kLogTag,
                L"InferBatch(%ls): unexpected output batch dim %lld",
                kModelTypeNames[idx], static_cast<long long>(actualBatch));
            return std::nullopt;
        }

        const size_t perSample = outElemCount / static_cast<size_t>(actualBatch);
        if (perSample == 0 ||
            perSample * static_cast<size_t>(actualBatch) != outElemCount) {
            SS_LOG_ERROR(kLogTag,
                L"InferBatch(%ls): output size %zu not divisible by batch %lld",
                kModelTypeNames[idx], outElemCount, static_cast<long long>(actualBatch));
            return std::nullopt;
        }

        try {
            std::vector<std::vector<float>> result;
            result.reserve(static_cast<size_t>(actualBatch));

            for (int64_t b = 0; b < actualBatch; ++b) {
                const float* start = outputData + (static_cast<size_t>(b) * perSample);
                result.emplace_back(start, start + perSample);
            }
            return result;
        } catch (...) {
            SS_LOG_ERROR(kLogTag, L"InferBatch(%ls): result allocation failed",
                         kModelTypeNames[idx]);
            return std::nullopt;
        }
    } catch (...) {
        SS_LOG_ERROR(kLogTag, L"InferBatch: unexpected exception");
        return std::nullopt;
    }
}

// ============================================================================
// GetModelVersion
// ============================================================================

std::optional<ModelVersion> ModelInference::GetModelVersion(
    CortexModelType type) const noexcept {
    try {
        if (!m_impl) return std::nullopt;
        if (!IsValidModelType(type)) return std::nullopt;

        const size_t idx = static_cast<size_t>(type);

        std::shared_lock lock(m_impl->modelMutex);
        if (!m_impl->initialized) return std::nullopt;

        const Impl::ModelSlot& slot = m_impl->slots[idx];
        if (!slot.loaded) return std::nullopt;

        return slot.version;
    } catch (...) {
        return std::nullopt;
    }
}

// ============================================================================
// IsModelLoaded
// ============================================================================

bool ModelInference::IsModelLoaded(CortexModelType type) const noexcept {
    if (!m_impl) return false;
    if (!IsValidModelType(type)) return false;

    const size_t idx = static_cast<size_t>(type);

    try {
        std::shared_lock lock(m_impl->modelMutex);
        if (!m_impl->initialized) return false;
        return m_impl->slots[idx].loaded;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// Hardware capability queries
// ============================================================================

bool ModelInference::HasAVX2() const noexcept {
    if (!m_impl) return false;
    return m_impl->hasAVX2;
}

bool ModelInference::HasAVX512() const noexcept {
    if (!m_impl) return false;
    return m_impl->hasAVX512;
}

bool ModelInference::HasDirectML() const noexcept {
    if (!m_impl) return false;
    return m_impl->hasDirectML;
}

}  // namespace AI
}  // namespace ShadowStrike

#else

namespace ShadowStrike {
namespace AI {

namespace {
    static constexpr const wchar_t* kLogTag = L"PhantomCortex";

    [[nodiscard]] const wchar_t* ModelTypeName(CortexModelType type) noexcept {
        switch (type) {
            case CortexModelType::Static: return L"Static";
            case CortexModelType::Behavioral: return L"Behavioral";
            case CortexModelType::Memory: return L"Memory";
            case CortexModelType::Network: return L"Network";
            case CortexModelType::Emulation: return L"Emulation";
            default: return L"Unknown";
        }
    }
}

struct ModelInference::Impl {};

ModelInference& ModelInference::Instance() noexcept {
    static ModelInference instance;
    return instance;
}

ModelInference::ModelInference()
    : m_impl(std::make_unique<Impl>()) {}

ModelInference::~ModelInference() = default;

bool ModelInference::Initialize(const CortexConfig&) noexcept {
    SS_LOG_ERROR(kLogTag, L"ONNX Runtime SDK is not available; ModelInference remains disabled");
    return false;
}

void ModelInference::Shutdown() noexcept {}

bool ModelInference::IsInitialized() const noexcept {
    return false;
}

bool ModelInference::LoadModel(CortexModelType type, const std::filesystem::path& onnxPath) noexcept {
    SS_LOG_ERROR(kLogTag,
        L"Cannot load model %ls from %ls because ONNX Runtime SDK is not available",
        ModelTypeName(type),
        onnxPath.c_str());
    return false;
}

void ModelInference::UnloadModel(CortexModelType) noexcept {}

std::optional<std::vector<float>> ModelInference::Infer(
    CortexModelType type,
    std::span<const float>,
    std::span<const int64_t>) noexcept
{
    SS_LOG_ERROR(kLogTag,
        L"Infer(%ls) rejected because ONNX Runtime SDK is not available",
        ModelTypeName(type));
    return std::nullopt;
}

std::optional<std::vector<std::vector<float>>> ModelInference::InferBatch(
    CortexModelType type,
    std::span<const float>,
    std::span<const int64_t>) noexcept
{
    SS_LOG_ERROR(kLogTag,
        L"InferBatch(%ls) rejected because ONNX Runtime SDK is not available",
        ModelTypeName(type));
    return std::nullopt;
}

std::optional<ModelVersion> ModelInference::GetModelVersion(CortexModelType) const noexcept {
    return std::nullopt;
}

bool ModelInference::IsModelLoaded(CortexModelType) const noexcept {
    return false;
}

bool ModelInference::HasAVX2() const noexcept {
    return false;
}

bool ModelInference::HasAVX512() const noexcept {
    return false;
}

bool ModelInference::HasDirectML() const noexcept {
    return false;
}

}  // namespace AI
}  // namespace ShadowStrike

#endif
