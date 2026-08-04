/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

// ── Windows / COM prerequisites ───────────────────────────────────────────────
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <combaseapi.h>
#include <amsi.h>

// ── Standard library (must precede Logger.hpp which uses std::format) ─────────
#include <atomic>
#include <cstdint>
#include <format>
#include <limits>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <string>
#include <vector>

// ── Own header ────────────────────────────────────────────────────────────────
#include "AmsiProvider.hpp"
#include "PhantomCore/Utils/DataStorePaths.hpp"   // shared signature DB location

// ── PhantomCore infrastructure ────────────────────────────────────────────────
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Config/ConfigManager.hpp"
#include "PhantomCore/SignatureStore/SignatureStore.hpp"
#include "PhantomCore/SignatureStore/SignatureFormat.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelStore.hpp"
#include "PhantomCore/AI/PhantomCortex.hpp"

namespace ShadowStrike {
namespace Products {
namespace Home {

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

namespace {

constexpr const wchar_t* kLogCategory   = L"AmsiProvider";
constexpr ULONGLONG      kMaxContentSize = 64ULL * 1024 * 1024;  // 64 MiB cap
constexpr ULONG          kAmsiReadChunkSize = 1UL * 1024 * 1024;  // 1 MiB bounded COM reads

// ConfigManager key naming the on-disk signatures database used by the
// SignatureStore. When the key is absent or empty, hash/pattern scanning is
// silently disabled and the provider relies on ThreatIntel + AI only.
constexpr const char* kSignatureDbPathKey = "Phantom/SignatureStore/DatabasePath";

// Minimal PE header probe: PhantomCortex::AnalyzeFile() is a PE-only path
// (extracts PE features). Passing non-PE script bytes wastes CPU and produces
// an unreliable benign-with-error verdict. We only invoke the model when the
// payload begins with the "MZ" DOS header and is large enough to plausibly
// hold an IMAGE_DOS_HEADER + IMAGE_NT_HEADERS pair.
constexpr std::size_t kMinPeProbeSize = 64u;

[[nodiscard]] bool LooksLikePeImage(std::span<const std::uint8_t> bytes) noexcept {
    return bytes.size() >= kMinPeProbeSize &&
           bytes[0] == static_cast<std::uint8_t>('M') &&
           bytes[1] == static_cast<std::uint8_t>('Z');
}

// IID for IAntimalwareProvider (from amsi.h / SDK)
// {b2cabfe3-fe04-42b1-a5df-08d483d4d125}
static const IID IID_IAntimalwareProvider_local = {
    0xb2cabfe3, 0xfe04, 0x42b1,
    { 0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25 }
};

[[nodiscard]] bool ReadAmsiContent(IAmsiStream& stream,
                                   ULONGLONG contentSize,
                                   std::vector<std::uint8_t>& out) noexcept {
    out.clear();

    if (contentSize == 0) {
        return true;
    }

    if (contentSize > kMaxContentSize ||
        contentSize > static_cast<ULONGLONG>(std::numeric_limits<std::size_t>::max())) {
        SS_LOG_WARN(kLogCategory,
            L"ReadAmsiContent: content size %llu bytes exceeds bounded scan limits",
            static_cast<unsigned long long>(contentSize));
        return false;
    }

    try {
        out.resize(static_cast<std::size_t>(contentSize));
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(kLogCategory,
            L"ReadAmsiContent: unable to allocate %llu-byte AMSI scan buffer",
            static_cast<unsigned long long>(contentSize));
        return false;
    }

    ULONGLONG offset = 0;
    while (offset < contentSize) {
        const ULONGLONG remaining = contentSize - offset;
        const ULONG request = static_cast<ULONG>(
            (remaining < kAmsiReadChunkSize) ? remaining : kAmsiReadChunkSize);

        ULONG bytesRead = 0;
        const HRESULT hr = stream.Read(
            offset,
            request,
            out.data() + static_cast<std::size_t>(offset),
            &bytesRead);

        if (FAILED(hr)) {
            SS_LOG_WARN(kLogCategory,
                L"ReadAmsiContent: IAmsiStream::Read failed at offset %llu hr=0x%08X",
                static_cast<unsigned long long>(offset),
                static_cast<unsigned>(hr));
            out.clear();
            return false;
        }

        if (bytesRead == 0 || bytesRead > request ||
            bytesRead > static_cast<ULONG>(contentSize - offset)) {
            SS_LOG_WARN(kLogCategory,
                L"ReadAmsiContent: invalid read size %lu at offset %llu (requested %lu)",
                bytesRead,
                static_cast<unsigned long long>(offset),
                request);
            out.clear();
            return false;
        }

        offset += bytesRead;
    }

    return true;
}

}  // namespace

// ─────────────────────────────────────────────────────────────────────────────
// PIMPL
// ─────────────────────────────────────────────────────────────────────────────

struct AmsiProvider::Impl {
    std::atomic<ULONG>          refCount{1};
    std::atomic<ProtectionMode> mode{ProtectionMode::Balanced};

    // Stats (relaxed order — no sequencing dependency needed)
    std::atomic<std::uint64_t>  scans{0};
    std::atomic<std::uint64_t>  blocked{0};
    std::atomic<std::uint64_t>  clean{0};

    // Detection infrastructure (initialised once in Initialize())
    std::unique_ptr<SignatureStore::SignatureStore>  sigStore;
    std::unique_ptr<ThreatIntel::ThreatIntelStore>  threatIntel;
    mutable std::shared_mutex                        lifecycleMutex;
    bool                                            initialized{false};
};

// ─────────────────────────────────────────────────────────────────────────────
// Construction / destruction
// ─────────────────────────────────────────────────────────────────────────────

AmsiProvider::AmsiProvider()
    : m_impl(std::make_unique<Impl>()) {}

AmsiProvider::~AmsiProvider() = default;

// ─────────────────────────────────────────────────────────────────────────────
// IUnknown
// ─────────────────────────────────────────────────────────────────────────────

HRESULT STDMETHODCALLTYPE AmsiProvider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_IAntimalwareProvider_local) {
        *ppv = static_cast<IAntimalwareProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE AmsiProvider::AddRef() {
    ULONG current = m_impl->refCount.load(std::memory_order_acquire);
    for (;;) {
        if (current == std::numeric_limits<ULONG>::max()) {
            SS_LOG_ERROR(kLogCategory, L"AddRef: COM reference count overflow refused");
            return current;
        }
        if (m_impl->refCount.compare_exchange_weak(
                current,
                current + 1u,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return current + 1u;
        }
    }
}

ULONG STDMETHODCALLTYPE AmsiProvider::Release() {
    ULONG current = m_impl->refCount.load(std::memory_order_acquire);
    for (;;) {
        if (current == 0u) {
            SS_LOG_ERROR(kLogCategory, L"Release: COM reference count underflow refused");
            return 0u;
        }

        const ULONG next = current - 1u;
        if (m_impl->refCount.compare_exchange_weak(
                current,
                next,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            if (next == 0u) {
                delete this;
            }
            return next;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAntimalwareProvider::DisplayName
// ─────────────────────────────────────────────────────────────────────────────

HRESULT STDMETHODCALLTYPE AmsiProvider::DisplayName(LPWSTR* displayName) {
    if (!displayName) return E_INVALIDARG;
    *displayName = nullptr;
    const wchar_t* kName = L"ShadowStrike PhantomHome AMSI Provider";
    const size_t   kLen  = wcslen(kName) + 1u;
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(kLen * sizeof(wchar_t)));
    if (!*displayName) return E_OUTOFMEMORY;
    const errno_t copyResult = wcscpy_s(*displayName, kLen, kName);
    if (copyResult != 0) {
        CoTaskMemFree(*displayName);
        *displayName = nullptr;
        SS_LOG_ERROR(kLogCategory,
            L"DisplayName: wcscpy_s failed errno=%d",
            static_cast<int>(copyResult));
        return E_FAIL;
    }
    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// IAntimalwareProvider::CloseSession
// ─────────────────────────────────────────────────────────────────────────────

void STDMETHODCALLTYPE AmsiProvider::CloseSession(ULONGLONG /*session*/) {
    // Session state is stateless in this implementation; nothing to free.
}

// ─────────────────────────────────────────────────────────────────────────────
// IAntimalwareProvider::Scan  (hot path)
// ─────────────────────────────────────────────────────────────────────────────

HRESULT STDMETHODCALLTYPE AmsiProvider::Scan(IAmsiStream* stream,
                                              AMSI_RESULT* result) {
    if (!stream || !result) return E_INVALIDARG;
    *result = AMSI_RESULT_NOT_DETECTED;

    // Mode check — lock-free atomic read on every call
    const ProtectionMode mode =
        m_impl->mode.load(std::memory_order_acquire);
    if (mode == ProtectionMode::Off) return S_OK;

    m_impl->scans.fetch_add(1u, std::memory_order_relaxed);

    // ── Read content size ─────────────────────────────────────────────────────
    ULONGLONG contentSize = 0;
    ULONG retData = 0;
    HRESULT hr = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_SIZE,
        static_cast<ULONG>(sizeof(ULONGLONG)),
        reinterpret_cast<PBYTE>(&contentSize),
        &retData);
    if (FAILED(hr) || retData != sizeof(contentSize)) {
        SS_LOG_WARN(kLogCategory,
            L"Scan: GetAttribute(CONTENT_SIZE) failed hr=0x%08X retData=%lu; "
            L"treating content as clean",
            static_cast<unsigned>(hr),
            retData);
        m_impl->clean.fetch_add(1u, std::memory_order_relaxed);
        return S_OK;
    }

    // ── Cap at 64 MiB ─────────────────────────────────────────────────────────
    if (contentSize > kMaxContentSize) {
        SS_LOG_WARN(kLogCategory,
            L"Scan: content size %llu bytes exceeds 64 MiB cap; "
            L"returning NOT_DETECTED without scanning",
            static_cast<unsigned long long>(contentSize));
        m_impl->clean.fetch_add(1u, std::memory_order_relaxed);
        return S_OK;
    }

    std::shared_lock lifecycleLock(m_impl->lifecycleMutex);
    if (!m_impl->initialized) {
        SS_LOG_WARN(kLogCategory,
            L"Scan: provider is not initialized; returning NOT_DETECTED");
        m_impl->clean.fetch_add(1u, std::memory_order_relaxed);
        return S_OK;
    }

    std::vector<std::uint8_t> content;
    if (!ReadAmsiContent(*stream, contentSize, content)) {
        m_impl->clean.fetch_add(1u, std::memory_order_relaxed);
        return S_OK;
    }

    const std::span<const uint8_t> bytes(content.data(), content.size());

    // ── Compute SHA-256 ───────────────────────────────────────────────────────
    std::string sha256Hex;
    {
        Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
        if (!hasher.Init() ||
            !hasher.Update(bytes.data(), bytes.size()) ||
            !hasher.FinalHex(sha256Hex)) {
            SS_LOG_WARN(kLogCategory,
                L"Scan: SHA-256 computation failed; ThreatIntel lookup skipped");
        }
    }

    // ── SignatureStore scan ───────────────────────────────────────────────────
    bool hashHit    = false;
    bool patternHit = false;

    if (m_impl->sigStore && m_impl->sigStore->IsInitialized()) {
        SignatureStore::ScanOptions opts;
        opts.enableHashLookup  = true;
        opts.enablePatternScan = (mode == ProtectionMode::Aggressive ||
                                  mode == ProtectionMode::Balanced);
        opts.enableYaraScan    = false;
        opts.stopOnFirstMatch  = true;

        const auto sigResult = m_impl->sigStore->ScanBuffer(bytes, opts);
        hashHit    = !sigResult.hashMatches.empty();
        patternHit = !sigResult.patternMatches.empty();
    }

    // ── ThreatIntel reputation lookup ─────────────────────────────────────────
    ThreatIntel::StoreLookupResult tiResult;
    if (!sha256Hex.empty() &&
        m_impl->threatIntel &&
        m_impl->threatIntel->IsInitialized()) {
        tiResult = m_impl->threatIntel->LookupHash(
            "SHA256", sha256Hex, ThreatIntel::StoreLookupOptions::FastLookup());
    }

    // ── PhantomCortex AI scan ─────────────────────────────────────────────────
    // DESIGN: AnalyzeFile() is the PE classifier path; it extracts PE features
    // and rejects non-PE payloads with a Benign/zero-confidence verdict. AMSI
    // delivers mostly scripts (PowerShell, VBA, JS) which would always be
    // misclassified as benign here, so we gate the call on a PE probe.
    AI::CortexVerdict cortexVerdict;
    bool              aiScanned = false;

    if ((mode == ProtectionMode::Balanced ||
         mode == ProtectionMode::Aggressive) &&
        LooksLikePeImage(bytes) &&
        AI::PhantomCortex::Instance().IsOperational()) {
        cortexVerdict = AI::PhantomCortex::Instance().AnalyzeFile(bytes);
        aiScanned     = true;
    }

    // ── Apply mode policy → AMSI_RESULT ──────────────────────────────────────
    AMSI_RESULT finalResult = AMSI_RESULT_NOT_DETECTED;

    switch (mode) {
    case ProtectionMode::Passive:
        // Never block; emit telemetry log if any indicator is found
        if (hashHit || tiResult.IsMalicious() ||
            (aiScanned &&
             cortexVerdict.verdict == AI::ThreatVerdict::Malicious)) {
            SS_LOG_INFO(kLogCategory,
                L"Scan[Passive]: threat indicators detected "
                L"hash=%hs tiMalicious=%d aiVerdict=%d; telemetry only",
                sha256Hex.c_str(),
                static_cast<int>(tiResult.IsMalicious()),
                aiScanned ? static_cast<int>(cortexVerdict.verdict) : -1);
        }
        finalResult = AMSI_RESULT_NOT_DETECTED;
        break;

    case ProtectionMode::Balanced:
        // Block only on definitive hash/ThreatIntel match
        if (hashHit || tiResult.IsMalicious()) {
            finalResult = AMSI_RESULT_BLOCKED_BY_ADMIN_START;
            SS_LOG_WARN(kLogCategory,
                L"Scan[Balanced]: blocking on hash/ThreatIntel match hash=%hs",
                sha256Hex.c_str());
        } else if (patternHit ||
                   (aiScanned &&
                    cortexVerdict.verdict == AI::ThreatVerdict::Malicious)) {
            // Ambiguous — log but do not block per Balanced policy
            SS_LOG_INFO(kLogCategory,
                L"Scan[Balanced]: ambiguous pattern/AI indicator; not blocking "
                L"hash=%hs patternHit=%d aiVerdict=%d",
                sha256Hex.c_str(),
                static_cast<int>(patternHit),
                aiScanned ? static_cast<int>(cortexVerdict.verdict) : -1);
            finalResult = AMSI_RESULT_NOT_DETECTED;
        }
        break;

    case ProtectionMode::Aggressive:
        if (hashHit || tiResult.IsMalicious()) {
            finalResult = AMSI_RESULT_DETECTED;
        } else if (patternHit || tiResult.IsSuspicious()) {
            finalResult = AMSI_RESULT_DETECTED;
        } else if (aiScanned &&
                   (cortexVerdict.verdict == AI::ThreatVerdict::Malicious ||
                    (cortexVerdict.verdict == AI::ThreatVerdict::Suspicious &&
                     cortexVerdict.confidence >= 0.50f))) {
            finalResult = AMSI_RESULT_DETECTED;
        }
        if (static_cast<unsigned>(finalResult) >=
            static_cast<unsigned>(AMSI_RESULT_BLOCKED_BY_ADMIN_START)) {
            SS_LOG_WARN(kLogCategory,
                L"Scan[Aggressive]: blocking hash=%hs patternHit=%d "
                L"tiMalicious=%d tiSuspicious=%d aiVerdict=%d aiConf=%.2f",
                sha256Hex.c_str(),
                static_cast<int>(patternHit),
                static_cast<int>(tiResult.IsMalicious()),
                static_cast<int>(tiResult.IsSuspicious()),
                aiScanned ? static_cast<int>(cortexVerdict.verdict) : -1,
                aiScanned ? static_cast<double>(cortexVerdict.confidence) : 0.0);
        }
        break;

    default:
        break;
    }

    // ── Update stats ──────────────────────────────────────────────────────────
    if (static_cast<unsigned>(finalResult) >=
        static_cast<unsigned>(AMSI_RESULT_BLOCKED_BY_ADMIN_START)) {
        m_impl->blocked.fetch_add(1u, std::memory_order_relaxed);
    } else {
        m_impl->clean.fetch_add(1u, std::memory_order_relaxed);
    }

    *result = finalResult;
    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Module lifecycle
// ─────────────────────────────────────────────────────────────────────────────

bool AmsiProvider::Initialize() {
    std::unique_lock lifecycleLock(m_impl->lifecycleMutex);
    if (m_impl->initialized) return true;

    // SignatureStore — best-effort; provider still functions without it.
    // Default-construction alone leaves IsInitialized()==false (and therefore
    // ScanBuffer() returns a no-op result), so the store MUST be opened
    // against the on-disk signatures database. The DB path is taken from
    // ConfigManager; absent/empty path or open failure are non-fatal.
    m_impl->sigStore = std::make_unique<SignatureStore::SignatureStore>();
    {
        auto& cfg = ::ShadowStrike::Config::ConfigManager::Instance();
        std::wstring sigDbPath =
            cfg.GetValue<std::wstring>(std::string(kSignatureDbPathKey), std::wstring{});

        if (sigDbPath.empty()) {
            // An unset config key is not a decision to run without signatures.
            // AMSI is the interception point for PowerShell, JScript, VBScript and
            // Office macro content, so dropping the store here left script
            // scanning with no hash or pattern matching whatsoever - and it said so
            // only once, at INFO, on a line that reads like a normal status
            // message. Fall back to the same hardened database the scan engine
            // uses (ScanEngine.hpp:578), leaving the config key as an override
            // rather than a prerequisite.
            sigDbPath = ::ShadowStrike::Utils::DataStorePaths::SignatureDatabase();
            SS_LOG_INFO(kLogCategory,
                L"Initialize: '%hs' is unset; using the shared signature database "
                L"at '%ls'",
                kSignatureDbPathKey, sigDbPath.c_str());
        }

        {
            const auto sigStatus =
                m_impl->sigStore->Initialize(sigDbPath, /*readOnly=*/true);
            if (!sigStatus.IsSuccess()) {
                SS_LOG_WARN(kLogCategory,
                    L"Initialize: SignatureStore::Initialize('%ls') failed "
                    L"code=%u win32=%lu; hash/pattern scanning disabled",
                    sigDbPath.c_str(),
                    static_cast<unsigned>(sigStatus.code),
                    static_cast<unsigned long>(sigStatus.win32Error));
                m_impl->sigStore.reset();
            } else {
                SS_LOG_INFO(kLogCategory,
                    L"Initialize: SignatureStore opened (path='%ls')",
                    sigDbPath.c_str());
            }
        }
    }

    // ThreatIntelStore — best-effort; null out if init fails
    m_impl->threatIntel =
        std::make_unique<ThreatIntel::ThreatIntelStore>();
    if (!m_impl->threatIntel->Initialize()) {
        SS_LOG_WARN(kLogCategory,
            L"Initialize: ThreatIntelStore failed to initialise; "
            L"hash reputation lookups will be skipped");
        m_impl->threatIntel.reset();
    }

    m_impl->initialized = true;
    SS_LOG_INFO(kLogCategory,
        L"AmsiProvider initialised (mode=%hs)",
        HomeProductOrchestrator::ToString(
            m_impl->mode.load(std::memory_order_relaxed)).data());
    return true;
}

void AmsiProvider::Shutdown() noexcept {
    std::unique_lock lifecycleLock(m_impl->lifecycleMutex);
    m_impl->threatIntel.reset();
    m_impl->sigStore.reset();
    m_impl->initialized = false;
    SS_LOG_INFO(kLogCategory, L"AmsiProvider shut down");
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode
// ─────────────────────────────────────────────────────────────────────────────

void AmsiProvider::SetMode(ProtectionMode m) noexcept {
    m_impl->mode.store(m, std::memory_order_release);
    SS_LOG_INFO(kLogCategory, L"SetMode → %hs",
        HomeProductOrchestrator::ToString(m).data());
}

ProtectionMode AmsiProvider::Mode() const noexcept {
    return m_impl->mode.load(std::memory_order_acquire);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────────────────────

AmsiProvider::Stats AmsiProvider::GetStats() const noexcept {
    return Stats{
        m_impl->scans.load(std::memory_order_relaxed),
        m_impl->blocked.load(std::memory_order_relaxed),
        m_impl->clean.load(std::memory_order_relaxed),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

HRESULT CreateAmsiProvider(IAntimalwareProvider** ppv) noexcept {
    if (!ppv) return E_INVALIDARG;
    *ppv = nullptr;
    try {
        // COM ref starts at 1 inside the Impl ctor; caller owns the result.
        auto* p = new AmsiProvider();
        *ppv    = static_cast<IAntimalwareProvider*>(p);
        return S_OK;
    } catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"AmsiProvider",
            L"CreateAmsiProvider: allocation failed (E_OUTOFMEMORY)");
        return E_OUTOFMEMORY;
    } catch (...) {
        SS_LOG_ERROR(L"AmsiProvider",
            L"CreateAmsiProvider: unexpected exception (E_FAIL)");
        return E_FAIL;
    }
}

}  // namespace Home
}  // namespace Products
}  // namespace ShadowStrike
