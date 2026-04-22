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
#include <memory>
#include <span>
#include <string>

// ── Own header ────────────────────────────────────────────────────────────────
#include "AmsiProvider.hpp"

// ── PhantomCore infrastructure ────────────────────────────────────────────────
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/SignatureStore/SignatureStore.hpp"
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

// IID for IAntimalwareProvider (from amsi.h / SDK)
// {b2cabfe3-fe04-42b1-a5df-08d483d4d125}
static const IID IID_IAntimalwareProvider_local = {
    0xb2cabfe3, 0xfe04, 0x42b1,
    { 0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25 }
};

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
    return m_impl->refCount.fetch_add(1u, std::memory_order_acq_rel) + 1u;
}

ULONG STDMETHODCALLTYPE AmsiProvider::Release() {
    const ULONG prev =
        m_impl->refCount.fetch_sub(1u, std::memory_order_acq_rel);
    if (prev == 1u) delete this;
    return prev - 1u;
}

// ─────────────────────────────────────────────────────────────────────────────
// IAntimalwareProvider::DisplayName
// ─────────────────────────────────────────────────────────────────────────────

HRESULT STDMETHODCALLTYPE AmsiProvider::DisplayName(LPWSTR* displayName) {
    if (!displayName) return E_INVALIDARG;
    const wchar_t* kName = L"ShadowStrike PhantomHome AMSI Provider";
    const size_t   kLen  = wcslen(kName) + 1u;
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(kLen * sizeof(wchar_t)));
    if (!*displayName) return E_OUTOFMEMORY;
    wcscpy_s(*displayName, kLen, kName);
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

    // ── Read content address ──────────────────────────────────────────────────
    PBYTE contentAddr = nullptr;
    ULONG retData     = 0;
    HRESULT hr = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_ADDRESS,
        static_cast<ULONG>(sizeof(PBYTE)),
        reinterpret_cast<PBYTE>(&contentAddr),
        &retData);
    if (FAILED(hr) || !contentAddr) {
        SS_LOG_WARN(kLogCategory,
            L"Scan: GetAttribute(CONTENT_ADDRESS) failed hr=0x%08X; "
            L"treating content as clean",
            static_cast<unsigned>(hr));
        m_impl->clean.fetch_add(1u, std::memory_order_relaxed);
        return S_OK;
    }

    // ── Read content size ─────────────────────────────────────────────────────
    ULONGLONG contentSize = 0;
    hr = stream->GetAttribute(
        AMSI_ATTRIBUTE_CONTENT_SIZE,
        static_cast<ULONG>(sizeof(ULONGLONG)),
        reinterpret_cast<PBYTE>(&contentSize),
        &retData);
    if (FAILED(hr)) {
        SS_LOG_WARN(kLogCategory,
            L"Scan: GetAttribute(CONTENT_SIZE) failed hr=0x%08X; "
            L"treating content as clean",
            static_cast<unsigned>(hr));
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

    const std::span<const uint8_t> bytes(
        contentAddr, static_cast<size_t>(contentSize));

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
    AI::CortexVerdict cortexVerdict;
    bool              aiScanned = false;

    if ((mode == ProtectionMode::Balanced ||
         mode == ProtectionMode::Aggressive) &&
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
    if (m_impl->initialized) return true;

    // SignatureStore — best-effort; provider still functions without it
    m_impl->sigStore = std::make_unique<SignatureStore::SignatureStore>();

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
