/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "MemoryForensics.hpp"
#include "../Core/Memory/VirtualMemory.hpp"
#include "../Core/Memory/MemoryTracker.hpp"
#include "../Common/Constants.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <mutex>
#include <numeric>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Hard Caps — prevent resource exhaustion during analysis
// ============================================================================

static constexpr uint32_t kMaxFindings            = 10'000;
static constexpr uint32_t kMaxExtractedPayloads   = 256;
static constexpr GuestSize kMaxScanRegionSize     = 64ULL * 1024 * 1024; // 64 MB per scan
static constexpr GuestSize kMaxPayloadExtractSize = 16ULL * 1024 * 1024; // 16 MB per payload
static constexpr uint32_t kMaxSampleBytes         = 256;
static constexpr uint32_t kNopSledThreshold       = 16;
static constexpr uint32_t kHeapSprayMinDupes      = 5;
static constexpr uint32_t kHeapSprayHashBytes     = 64;
static constexpr uint32_t kROPMinGadgets          = 4;
static constexpr double   kHighEntropyThreshold   = 7.0;
static constexpr double   kPackedEntropyLow       = 6.0;
static constexpr uint32_t kMinXORBlockSize        = 32;
static constexpr uint32_t kMaxXORKeySize          = 8;
static constexpr uint32_t kMinBase64Run           = 32;
static constexpr uint32_t kMinStringTableEntries  = 4;
static constexpr uint32_t kPageScanBuffer         = 4096;
static constexpr uint32_t kMaxPagesPerScan        = 16384; // 64 MB / 4KB

// ============================================================================
// Internal Helpers — NOP-equivalence, PE validation, hashing
// ============================================================================

namespace {

// ---- NOP-equivalent detection (32-bit context) ----------------------------

[[nodiscard]] bool IsNopEquivalent32(uint8_t byte) noexcept {
    if (byte == 0x90) return true;                  // NOP
    if (byte >= 0x91 && byte <= 0x97) return true;  // XCHG EAX, reg
    if (byte >= 0x40 && byte <= 0x4F) return true;  // INC/DEC reg (32-bit)
    if (byte == 0xFC || byte == 0xFD) return true;  // CLD / STD
    return false;
}

// Two-byte NOP-equivalent patterns
[[nodiscard]] bool IsTwoByteNop(uint8_t a, uint8_t b) noexcept {
    // MOV reg, reg (same register)
    if (a == 0x89 || a == 0x8B) {
        // ModRM mod=11 (register-register), same src/dst
        if ((b & 0xC0) == 0xC0) {
            uint8_t src = (b >> 3) & 0x07;
            uint8_t dst = b & 0x07;
            if (src == dst) return true;
        }
    }
    // XCHG reg, reg (same register)
    if (a == 0x87 && (b & 0xC0) == 0xC0) {
        uint8_t src = (b >> 3) & 0x07;
        uint8_t dst = b & 0x07;
        if (src == dst) return true;
    }
    // 66 90 = 2-byte NOP (operand-size prefix + NOP)
    if (a == 0x66 && b == 0x90) return true;
    return false;
}

// ---- Simple FNV-1a 64-bit for heap-spray dedup ----------------------------

[[nodiscard]] uint64_t FnvHash64(const uint8_t* data, size_t len) noexcept {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 0x100000001B3ULL;
    }
    return h;
}

// ---- Base64 character check -----------------------------------------------

[[nodiscard]] bool IsBase64Char(uint8_t c) noexcept {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=';
}

// ---- Printable ASCII check ------------------------------------------------

[[nodiscard]] bool IsPrintableAscii(uint8_t c) noexcept {
    return c >= 0x20 && c <= 0x7E;
}

// ---- Collect a sample (first N bytes) from guest memory -------------------

[[nodiscard]] std::vector<uint8_t> CollectSample(
    const VirtualMemory& memory,
    GuestAddress addr,
    GuestSize regionSize,
    uint32_t maxSample) noexcept
{
    uint32_t sampleLen = static_cast<uint32_t>(
        std::min<GuestSize>(regionSize, maxSample));
    std::vector<uint8_t> buf(sampleLen);
    if (memory.Read(addr, buf.data(), sampleLen) != ErrorCode::Success) {
        buf.clear();
    }
    return buf;
}

// ---- Read a contiguous block from guest memory into a host buffer ---------
// Returns empty vector on failure or if size exceeds cap.

[[nodiscard]] std::vector<uint8_t> ReadGuestBlock(
    const VirtualMemory& memory,
    GuestAddress addr,
    GuestSize size) noexcept
{
    if (size == 0 || size > kMaxScanRegionSize) return {};
    std::vector<uint8_t> buf;
    try {
        buf.resize(static_cast<size_t>(size));
    } catch (...) {
        return {};
    }
    if (memory.Read(addr, buf.data(), static_cast<uint32_t>(
            std::min<GuestSize>(size, UINT32_MAX))) != ErrorCode::Success) {
        return {};
    }
    return buf;
}

// ---- Suspicious C2/malware string fragments (lowercase) -------------------

static constexpr std::array<const char*, 16> kSuspiciousStrings = {{
    "cmd.exe",
    "powershell",
    "wscript",
    "cscript",
    "/c whoami",
    "net user",
    "mimikatz",
    "sekurlsa",
    "invoke-",
    "downloadstring",
    "downloadfile",
    "urlmon",
    "winhttp",
    "socket",
    "connect(",
    "recv(",
}};

} // anonymous namespace

// ============================================================================
// MemoryForensics::Impl — PIMPL body
// ============================================================================

struct MemoryForensics::Impl {
    // Configuration snapshot (immutable after construction)
    double entropyThreshold       = kHighEntropyThreshold;
    bool   enabled                = true;

    // Results (guarded by m_mutex)
    std::vector<MemoryFindingDetail> findings;
    std::vector<ExtractedPayload>    payloads;

    // Heap-spray tracking: hash → count of allocations with that hash
    std::unordered_map<uint64_t, uint32_t> heapSprayHashes;
    // Addresses already flagged (avoid duplicate findings)
    std::unordered_set<GuestAddress>       flaggedAddresses;

    // Protection-change log for W→X analysis
    struct ProtChangeEntry {
        GuestAddress base;
        GuestSize    size;
        MemProt      oldProt;
        MemProt      newProt;
    };
    std::vector<ProtChangeEntry> protChanges;
    static constexpr uint32_t kMaxProtChanges = 100'000;

    mutable std::shared_mutex mutex;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    bool AddFinding(MemoryFindingDetail&& f) noexcept {
        if (findings.size() >= kMaxFindings) return false;
        findings.push_back(std::move(f));
        return true;
    }

    bool AddPayload(ExtractedPayload&& p) noexcept {
        if (payloads.size() >= kMaxExtractedPayloads) return false;
        payloads.push_back(std::move(p));
        return true;
    }

    bool IsAlreadyFlagged(GuestAddress addr) const noexcept {
        return flaggedAddresses.count(addr) > 0;
    }

    void MarkFlagged(GuestAddress addr) noexcept {
        if (flaggedAddresses.size() < kMaxFindings) {
            flaggedAddresses.insert(addr);
        }
    }

    // -----------------------------------------------------------------------
    // Core scan routines — called under exclusive lock
    // -----------------------------------------------------------------------

    void ScanBufferForShellcode(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr,
        const VirtualMemory& memory) noexcept;

    void ScanBufferForPE(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr,
        const VirtualMemory& memory) noexcept;

    void ScanBufferForEntropy(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    void ScanBufferForXOREncoding(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    void ScanBufferForBase64(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    void ScanBufferForROPChain(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr,
        const VirtualMemory& memory) noexcept;

    void ScanBufferForTrampolines(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    void ScanBufferForSuspiciousStrings(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    // NOP sled sub-scanner
    void DetectNopSleds(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    // Decoder stub sub-scanner
    void DetectDecoderStubs(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    // Egg hunter sub-scanner
    void DetectEggHunters(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;

    // Stack shellcode sub-scanner
    void DetectStackShellcode(
        const uint8_t* data, size_t len,
        GuestAddress baseAddr) noexcept;
};

// ============================================================================
// Shannon Entropy — static, thread-safe, no allocations beyond stack
// ============================================================================

double MemoryForensics::CalculateEntropy(
    const uint8_t* data, size_t size) noexcept
{
    if (!data || size == 0) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (size_t i = 0; i < size; ++i) {
        ++freq[data[i]];
    }

    const double total = static_cast<double>(size);
    double entropy = 0.0;
    for (uint32_t count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

double MemoryForensics::CalculateEntropy(ByteSpan data) noexcept {
    return CalculateEntropy(data.data(), data.size());
}

// ============================================================================
// Construction / Destruction / Reset
// ============================================================================

MemoryForensics::MemoryForensics(
    const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>())
{
    m_impl->entropyThreshold = config.entropyThreshold;
    m_impl->enabled          = config.enableMemoryForensics;
    m_impl->findings.reserve(256);
    m_impl->payloads.reserve(16);
}

MemoryForensics::~MemoryForensics() noexcept = default;

void MemoryForensics::Reset() noexcept {
    std::unique_lock lock(m_impl->mutex);
    m_impl->findings.clear();
    m_impl->payloads.clear();
    m_impl->heapSprayHashes.clear();
    m_impl->flaggedAddresses.clear();
    m_impl->protChanges.clear();
}

// ============================================================================
// Results Accessors
// ============================================================================

const std::vector<MemoryFindingDetail>&
MemoryForensics::GetFindings() const noexcept {
    // Caller expected to call after scanning completes; shared lock for safety.
    std::shared_lock lock(m_impl->mutex);
    return m_impl->findings;
}

uint32_t MemoryForensics::GetFindingCount() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return static_cast<uint32_t>(m_impl->findings.size());
}

std::vector<const MemoryFindingDetail*>
MemoryForensics::GetFindingsByType(MemoryFinding type) const noexcept {
    std::shared_lock lock(m_impl->mutex);
    std::vector<const MemoryFindingDetail*> result;
    for (const auto& f : m_impl->findings) {
        if (f.type == type) {
            result.push_back(&f);
        }
    }
    return result;
}

const std::vector<ExtractedPayload>&
MemoryForensics::GetExtractedPayloads() const noexcept {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->payloads;
}

// ============================================================================
// Payload Extraction
// ============================================================================

void MemoryForensics::ExtractPayload(
    const VirtualMemory& memory,
    GuestAddress base,
    GuestSize size,
    const std::string& desc) noexcept
{
    std::unique_lock lock(m_impl->mutex);

    if (m_impl->payloads.size() >= kMaxExtractedPayloads) return;
    if (size == 0 || size > kMaxPayloadExtractSize) return;

    std::vector<uint8_t> buf;
    try {
        buf.resize(static_cast<size_t>(size));
    } catch (...) {
        return;
    }

    uint32_t readSize = static_cast<uint32_t>(
        std::min<GuestSize>(size, UINT32_MAX));
    if (memory.Read(base, buf.data(), readSize) != ErrorCode::Success) {
        return;
    }

    double ent = CalculateEntropy(buf.data(), buf.size());

    bool isPE = false;
    if (buf.size() >= 64) {
        isPE = (buf[0] == 0x4D && buf[1] == 0x5A);
    }

    // Simple shellcode heuristic: starts with common shellcode prefixes
    bool isSC = false;
    if (!isPE && buf.size() >= 4) {
        // Common shellcode entry: CLD (0xFC), NOP sled, CALL/POP GetPC
        if (buf[0] == 0xFC ||
            buf[0] == 0x90 ||
            (buf[0] == 0xE8 && buf[1] == 0x00 && buf[2] == 0x00 &&
             buf[3] == 0x00)) {
            isSC = true;
        }
    }

    ExtractedPayload payload;
    payload.data          = std::move(buf);
    payload.sourceAddress = base;
    payload.originalSize  = size;
    payload.description   = desc;
    payload.entropy       = ent;
    payload.isPE          = isPE;
    payload.isShellcode   = isSC;

    m_impl->AddPayload(std::move(payload));
}

// ============================================================================
// Event-Driven Analysis
// ============================================================================

void MemoryForensics::OnWXTransition(
    const VirtualMemory& memory, GuestAddress page) noexcept
{
    if (!m_impl->enabled) return;

    std::unique_lock lock(m_impl->mutex);
    GuestAddress aligned = PageBase(page);

    if (m_impl->IsAlreadyFlagged(aligned)) return;
    m_impl->MarkFlagged(aligned);

    // Read page contents for entropy + shellcode scan
    std::array<uint8_t, kPageScanBuffer> buf{};
    if (memory.Read(aligned, buf.data(), kPageScanBuffer) != ErrorCode::Success) {
        return;
    }

    double ent = CalculateEntropy(buf.data(), kPageScanBuffer);

    MemoryFindingDetail finding;
    finding.type        = MemoryFinding::WriteExecuteTransition;
    finding.address     = aligned;
    finding.size        = kPageSize;
    finding.confidence  = 0.85f;
    finding.entropy     = ent;
    finding.description = "Page written then executed — W→X transition at 0x"
                          + std::to_string(aligned);

    uint32_t sampleLen = std::min<uint32_t>(kMaxSampleBytes, kPageScanBuffer);
    finding.sample.assign(buf.begin(), buf.begin() + sampleLen);

    m_impl->AddFinding(std::move(finding));

    // Sub-scan this page for shellcode and PE
    m_impl->ScanBufferForShellcode(buf.data(), kPageScanBuffer, aligned, memory);
    m_impl->ScanBufferForPE(buf.data(), kPageScanBuffer, aligned, memory);
}

void MemoryForensics::OnProtectionChange(
    GuestAddress base, GuestSize size,
    MemProt oldProt, MemProt newProt) noexcept
{
    if (!m_impl->enabled) return;

    std::unique_lock lock(m_impl->mutex);

    if (m_impl->protChanges.size() < Impl::kMaxProtChanges) {
        m_impl->protChanges.push_back({base, size, oldProt, newProt});
    }

    // Detect Read/Write → Execute transitions (VirtualProtect-based unpacking)
    bool wasWritable  = HasProt(oldProt, MemProt::Write);
    bool nowExecute   = HasProt(newProt, MemProt::Execute);
    if (wasWritable && nowExecute) {
        GuestAddress aligned = PageBase(base);
        if (!m_impl->IsAlreadyFlagged(aligned)) {
            m_impl->MarkFlagged(aligned);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::SelfModifyingCode;
            finding.address     = base;
            finding.size        = size;
            finding.confidence  = 0.75f;
            finding.description =
                "Protection changed from writable to executable — "
                "possible unpacking / self-modifying code";

            m_impl->AddFinding(std::move(finding));
        }
    }
}

void MemoryForensics::OnAllocation(
    GuestAddress base, GuestSize size, MemProt prot) noexcept
{
    if (!m_impl->enabled) return;

    std::unique_lock lock(m_impl->mutex);

    // Track for heap spray: if allocation is small-ish, hash first bytes later
    // For now, flag RWX allocations immediately
    if (HasProt(prot, MemProt::Read) &&
        HasProt(prot, MemProt::Write) &&
        HasProt(prot, MemProt::Execute))
    {
        MemoryFindingDetail finding;
        finding.type        = MemoryFinding::WriteExecuteTransition;
        finding.address     = base;
        finding.size        = size;
        finding.confidence  = 0.70f;
        finding.description = "RWX allocation — commonly used for "
                              "shellcode injection or unpacking";

        m_impl->AddFinding(std::move(finding));
    }
}

void MemoryForensics::OnStackPivot(
    GuestAddress oldRSP, GuestAddress newRSP) noexcept
{
    if (!m_impl->enabled) return;

    std::unique_lock lock(m_impl->mutex);

    // Stack pivot: RSP jumped more than 1MB away from its previous value
    GuestAddress diff = (newRSP > oldRSP)
                        ? (newRSP - oldRSP)
                        : (oldRSP - newRSP);

    float conf = 0.0f;
    if (diff > 4 * 1024 * 1024) {
        conf = 0.95f;
    } else if (diff > 1024 * 1024) {
        conf = 0.85f;
    } else if (diff > 256 * 1024) {
        conf = 0.65f;
    } else {
        return; // Small adjustment — not suspicious
    }

    MemoryFindingDetail finding;
    finding.type        = MemoryFinding::StackPivotDetected;
    finding.address     = newRSP;
    finding.size        = diff;
    finding.confidence  = conf;
    finding.description = "Stack pivot: RSP moved from 0x"
                          + std::to_string(oldRSP) + " to 0x"
                          + std::to_string(newRSP);

    m_impl->AddFinding(std::move(finding));
}

// ============================================================================
// Full-Memory Scan
// ============================================================================

void MemoryForensics::ScanAll(
    const VirtualMemory& memory,
    const MemoryTracker& tracker) noexcept
{
    if (!m_impl->enabled) return;

    // 1. Scan all W→X pages
    auto wxPages = tracker.GetWriteExecutePages();
    for (GuestAddress page : wxPages) {
        OnWXTransition(memory, page);
    }

    // 2. Scan all RWX allocations
    auto rwxAllocs = tracker.GetRWXAllocations();
    for (const auto& [base, size] : rwxAllocs) {
        ScanRegion(memory, base, size);
    }

    // 3. Heap spray analysis on recent allocations
    {
        std::unique_lock lock(m_impl->mutex);
        // Check for duplicate content across RWX allocations
        for (const auto& [base, size] : rwxAllocs) {
            if (size < kHeapSprayHashBytes) continue;

            std::array<uint8_t, kHeapSprayHashBytes> hashBuf{};
            if (memory.Read(base, hashBuf.data(), kHeapSprayHashBytes)
                != ErrorCode::Success) {
                continue;
            }

            uint64_t h = FnvHash64(hashBuf.data(), kHeapSprayHashBytes);
            auto& count = m_impl->heapSprayHashes[h];
            ++count;

            if (count == kHeapSprayMinDupes &&
                !m_impl->IsAlreadyFlagged(base))
            {
                m_impl->MarkFlagged(base);

                MemoryFindingDetail finding;
                finding.type        = MemoryFinding::HeapSprayPattern;
                finding.address     = base;
                finding.size        = size;
                finding.confidence  = 0.90f;
                finding.description =
                    "Heap spray detected: " + std::to_string(count)
                    + " identical allocations";
                finding.sample.assign(hashBuf.begin(), hashBuf.end());

                m_impl->AddFinding(std::move(finding));
            }
        }
    }
}

// ============================================================================
// Region Scan
// ============================================================================

void MemoryForensics::ScanRegion(
    const VirtualMemory& memory,
    GuestAddress base,
    GuestSize size) noexcept
{
    if (!m_impl->enabled) return;
    if (size == 0) return;

    GuestSize scanSize = std::min(size, kMaxScanRegionSize);

    // Read in page-sized chunks to avoid massive single allocation
    GuestAddress cursor = base;
    GuestSize remaining = scanSize;

    while (remaining > 0) {
        uint32_t chunkSize = static_cast<uint32_t>(
            std::min<GuestSize>(remaining, kPageScanBuffer));

        std::array<uint8_t, kPageScanBuffer> buf{};
        if (memory.Read(cursor, buf.data(), chunkSize) != ErrorCode::Success) {
            cursor += chunkSize;
            remaining -= chunkSize;
            continue;
        }

        std::unique_lock lock(m_impl->mutex);
        m_impl->ScanBufferForShellcode(buf.data(), chunkSize, cursor, memory);
        m_impl->ScanBufferForPE(buf.data(), chunkSize, cursor, memory);
        m_impl->ScanBufferForEntropy(buf.data(), chunkSize, cursor);
        m_impl->ScanBufferForXOREncoding(buf.data(), chunkSize, cursor);
        m_impl->ScanBufferForBase64(buf.data(), chunkSize, cursor);
        m_impl->ScanBufferForROPChain(buf.data(), chunkSize, cursor, memory);
        m_impl->ScanBufferForTrampolines(buf.data(), chunkSize, cursor);
        m_impl->ScanBufferForSuspiciousStrings(buf.data(), chunkSize, cursor);
        lock.unlock();

        cursor += chunkSize;
        remaining -= chunkSize;
    }
}

// ============================================================================
// AnalyzeAllRegions — summary per W→X page / RWX allocation
// ============================================================================

std::vector<RegionAnalysis> MemoryForensics::AnalyzeAllRegions(
    const VirtualMemory& memory,
    const MemoryTracker& tracker) const noexcept
{
    std::vector<RegionAnalysis> results;

    auto wxPages = tracker.GetWriteExecutePages();
    auto rwxAllocs = tracker.GetRWXAllocations();

    // Collect unique bases
    std::unordered_set<GuestAddress> seen;

    auto analyzeOne = [&](GuestAddress base, GuestSize sz) {
        if (seen.count(base)) return;
        seen.insert(base);

        RegionAnalysis ra;
        ra.base = base;
        ra.size = sz;
        ra.protection = memory.GetProtection(base).value_or(MemProt::None);
        ra.isWrittenThenExecuted = true;

        std::array<uint8_t, kPageScanBuffer> buf{};
        uint32_t readLen = static_cast<uint32_t>(
            std::min<GuestSize>(sz, kPageScanBuffer));
        if (memory.Read(base, buf.data(), readLen) == ErrorCode::Success) {
            ra.entropy = CalculateEntropy(buf.data(), readLen);
            ra.containsPE = (readLen >= 2 &&
                             buf[0] == 0x4D && buf[1] == 0x5A);
            // Shellcode heuristic: high entropy + starts with common prefix
            ra.containsShellcode =
                (ra.entropy > kPackedEntropyLow) &&
                !ra.containsPE &&
                readLen >= 4 &&
                (buf[0] == 0xFC || buf[0] == 0x90 ||
                 (buf[0] == 0xE8 && buf[1] == 0x00 &&
                  buf[2] == 0x00 && buf[3] == 0x00));
        }

        // Count findings for this region
        {
            std::shared_lock lock(m_impl->mutex);
            for (const auto& f : m_impl->findings) {
                if (f.address >= base && f.address < base + sz) {
                    ++ra.findingCount;
                }
            }
        }

        results.push_back(ra);
    };

    for (GuestAddress page : wxPages) {
        analyzeOne(PageBase(page), kPageSize);
    }
    for (const auto& [base, sz] : rwxAllocs) {
        analyzeOne(base, sz);
    }

    return results;
}

// ============================================================================
// Shellcode Detection — NOP Sleds
// ============================================================================

void MemoryForensics::Impl::DetectNopSleds(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < kNopSledThreshold) return;

    size_t runStart = 0;
    size_t runLen   = 0;

    auto emitSled = [&](size_t start, size_t length) {
        if (length < kNopSledThreshold) return;
        GuestAddress addr = baseAddr + start;
        if (IsAlreadyFlagged(addr)) return;
        MarkFlagged(addr);

        float conf = 0.0f;
        if (length >= 256) conf = 0.95f;
        else if (length >= 64)  conf = 0.85f;
        else if (length >= 32)  conf = 0.75f;
        else                    conf = 0.60f;

        MemoryFindingDetail finding;
        finding.type        = MemoryFinding::ShellcodeNopSled;
        finding.address     = addr;
        finding.size        = length;
        finding.confidence  = conf;
        finding.description =
            "NOP sled: " + std::to_string(length)
            + " consecutive NOP-equivalent bytes";
        uint32_t sLen = static_cast<uint32_t>(
            std::min<size_t>(length, kMaxSampleBytes));
        finding.sample.assign(data + start, data + start + sLen);

        AddFinding(std::move(finding));
    };

    size_t i = 0;
    while (i < len) {
        bool isNop = false;

        // Check two-byte NOP first
        if (i + 1 < len && IsTwoByteNop(data[i], data[i + 1])) {
            isNop = true;
            if (runLen == 0) runStart = i;
            runLen += 2;
            i += 2;
        } else if (IsNopEquivalent32(data[i])) {
            isNop = true;
            if (runLen == 0) runStart = i;
            ++runLen;
            ++i;
        }

        if (!isNop) {
            emitSled(runStart, runLen);
            runLen = 0;
            ++i;
        }
    }
    emitSled(runStart, runLen);
}

// ============================================================================
// Shellcode Detection — Decoder Stubs
// ============================================================================

void MemoryForensics::Impl::DetectDecoderStubs(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < 7) return;

    // --- Pattern table: each entry is {bytes, mask, length, description, confidence}
    struct Pattern {
        const uint8_t* bytes;
        const uint8_t* mask; // 0xFF = exact match, 0x00 = wildcard
        uint32_t length;
        const char* desc;
        float confidence;
    };

    // CALL/POP GetPC: E8 00 00 00 00 5x (pop reg)
    static constexpr uint8_t kCallPop[]     = {0xE8, 0x00, 0x00, 0x00, 0x00, 0x58};
    static constexpr uint8_t kCallPopMask[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8};

    // FNSTENV GetPC: D9 EE D9 74 24 F4 5x
    static constexpr uint8_t kFnstenv[]     = {0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4, 0x58};
    static constexpr uint8_t kFnstenvMask[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8};

    // XOR decoder loop: 80 34 0E xx 46 E2 FA
    // xor byte [esi+ecx], KEY; inc esi; loop -6
    static constexpr uint8_t kXorLoop[]     = {0x80, 0x34, 0x0E, 0x00, 0x46, 0xE2, 0xFA};
    static constexpr uint8_t kXorLoopMask[] = {0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF};

    // XOR decoder (variant): 80 30 xx 40 E2 FB
    // xor byte [eax], KEY; inc eax; loop -5
    static constexpr uint8_t kXorLoop2[]     = {0x80, 0x30, 0x00, 0x40, 0xE2, 0xFB};
    static constexpr uint8_t kXorLoop2Mask[] = {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF};

    // SUB decoder loop: 80 2E xx 46 E2 FB
    // sub byte [esi], KEY; inc esi; loop -5
    static constexpr uint8_t kSubLoop[]     = {0x80, 0x2E, 0x00, 0x46, 0xE2, 0xFB};
    static constexpr uint8_t kSubLoopMask[] = {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF};

    // ADD decoder loop: 80 06 xx 46 E2 FB
    // add byte [esi], KEY; inc esi; loop -5
    static constexpr uint8_t kAddLoop[]     = {0x80, 0x06, 0x00, 0x46, 0xE2, 0xFB};
    static constexpr uint8_t kAddLoopMask[] = {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF};

    // ROL decoder: C0 06 xx 46 E2 FB
    // rol byte [esi], N; inc esi; loop
    static constexpr uint8_t kRolLoop[]     = {0xC0, 0x06, 0x00, 0x46, 0xE2, 0xFB};
    static constexpr uint8_t kRolLoopMask[] = {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF};

    // ROR decoder: C0 0E xx 46 E2 FB
    static constexpr uint8_t kRorLoop[]     = {0xC0, 0x0E, 0x00, 0x46, 0xE2, 0xFB};
    static constexpr uint8_t kRorLoopMask[] = {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF};

    // Shikata ga nai (Metasploit): FPU GetPC + counter + XOR loop
    // D9 74 24 F4 — FNSTENV [esp-0xC]
    static constexpr uint8_t kShikata[]     = {0xD9, 0x74, 0x24, 0xF4};
    static constexpr uint8_t kShikataMask[] = {0xFF, 0xFF, 0xFF, 0xFF};

    // JMP/CALL/POP: EB xx E8 xx xx xx xx 5x
    static constexpr uint8_t kJmpCallPop[]     = {0xEB, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58};
    static constexpr uint8_t kJmpCallPopMask[] = {0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xF8};

    static const Pattern patterns[] = {
        {kCallPop,    kCallPopMask,    6, "CALL/POP GetPC shellcode stub",            0.90f},
        {kFnstenv,    kFnstenvMask,    7, "FNSTENV GetPC shellcode decoder",          0.92f},
        {kXorLoop,    kXorLoopMask,    7, "XOR decoder loop (ESI+ECX variant)",       0.88f},
        {kXorLoop2,   kXorLoop2Mask,   6, "XOR decoder loop (EAX variant)",           0.88f},
        {kSubLoop,    kSubLoopMask,    6, "SUB decoder loop",                         0.85f},
        {kAddLoop,    kAddLoopMask,    6, "ADD decoder loop",                         0.85f},
        {kRolLoop,    kRolLoopMask,    6, "ROL decoder loop",                         0.83f},
        {kRorLoop,    kRorLoopMask,    6, "ROR decoder loop",                         0.83f},
        {kShikata,    kShikataMask,    4, "Shikata ga nai (Metasploit) FPU GetPC",    0.94f},
        {kJmpCallPop, kJmpCallPopMask, 8, "JMP/CALL/POP GetPC shellcode stub",       0.87f},
    };

    for (const auto& pat : patterns) {
        if (pat.length > len) continue;

        for (size_t i = 0; i <= len - pat.length; ++i) {
            bool match = true;
            for (uint32_t j = 0; j < pat.length; ++j) {
                if ((data[i + j] & pat.mask[j]) != (pat.bytes[j] & pat.mask[j])) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;

            GuestAddress addr = baseAddr + i;
            if (IsAlreadyFlagged(addr)) continue;
            MarkFlagged(addr);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::ShellcodeDecoderStub;
            finding.address     = addr;
            finding.size        = pat.length;
            finding.confidence  = pat.confidence;
            finding.description = pat.desc;

            uint32_t sLen = static_cast<uint32_t>(
                std::min<size_t>(len - i, kMaxSampleBytes));
            finding.sample.assign(data + i, data + i + sLen);

            AddFinding(std::move(finding));

            // Check if there's an encoded payload following the stub
            size_t payloadStart = i + pat.length;
            if (payloadStart + kMinXORBlockSize <= len) {
                double ent = MemoryForensics::CalculateEntropy(
                    data + payloadStart,
                    std::min<size_t>(len - payloadStart, kPageScanBuffer));
                if (ent > kPackedEntropyLow) {
                    GuestAddress pAddr = baseAddr + payloadStart;
                    if (!IsAlreadyFlagged(pAddr)) {
                        MarkFlagged(pAddr);

                        MemoryFindingDetail pf;
                        pf.type        = MemoryFinding::ShellcodeEncodedPayload;
                        pf.address     = pAddr;
                        pf.size        = len - payloadStart;
                        pf.confidence  = 0.80f;
                        pf.entropy     = ent;
                        pf.description =
                            "Encoded payload after decoder stub — "
                            "entropy " + std::to_string(ent).substr(0, 4);

                        uint32_t psLen = static_cast<uint32_t>(
                            std::min<size_t>(len - payloadStart, kMaxSampleBytes));
                        pf.sample.assign(
                            data + payloadStart,
                            data + payloadStart + psLen);

                        AddFinding(std::move(pf));
                    }
                }
            }

            break; // One match per pattern per buffer is sufficient
        }
    }
}

// ============================================================================
// Shellcode Detection — Egg Hunters
// ============================================================================

void MemoryForensics::Impl::DetectEggHunters(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < 16) return;

    // Egg hunter signatures (partial matching with wildcards)
    // NtAccessCheckAndAuditAlarm egg hunter:
    //   66 81 CA FF 0F  — or dx, 0FFFh
    //   42              — inc edx
    //   52              — push edx
    //   6A 02           — push 2
    //   58              — pop eax
    //   CD 2E           — int 2Eh
    //   3C 05           — cmp al, 5
    //   5A              — pop edx
    //   74 EF           — je short (loop)
    //   B8 xx xx xx xx  — mov eax, <egg>
    //   8B FA           — mov edi, edx
    //   AF              — scasd
    //   75 EA           — jne short (loop)
    //   AF              — scasd
    //   75 E7           — jne short (loop)
    //   FF E7           — jmp edi
    static constexpr uint8_t kNtAudit[]     = {
        0x66, 0x81, 0xCA, 0xFF, 0x0F, 0x42, 0x52, 0x6A,
        0x02, 0x58, 0xCD, 0x2E, 0x3C, 0x05, 0x5A, 0x74
    };
    static constexpr uint8_t kNtAuditMask[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    // SEH-based egg hunter preamble: EB 21 ... 64 FF 35 00 00 00 00
    static constexpr uint8_t kSEH[]     = {0xEB, 0x21};
    static constexpr uint8_t kSEHMask[] = {0xFF, 0xFF};

    // IsBadReadPtr egg hunter: BB xx xx xx xx (mov ebx, <egg>)
    // followed by comparison/scasd loop
    // We look for: BB xx xx xx xx ... AF 75 xx AF 75 xx FF E7
    static constexpr uint8_t kIsBadReadEnd[]     = {0xAF, 0x75, 0x00, 0xAF, 0x75, 0x00, 0xFF, 0xE7};
    static constexpr uint8_t kIsBadReadEndMask[] = {0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF};

    struct EggPattern {
        const uint8_t* bytes;
        const uint8_t* mask;
        uint32_t length;
        const char* desc;
        float confidence;
    };

    static const EggPattern eggPatterns[] = {
        {kNtAudit, kNtAuditMask, 16,
         "NtAccessCheckAndAuditAlarm egg hunter", 0.93f},
        {kSEH, kSEHMask, 2,
         "SEH-based egg hunter (preamble)", 0.50f},
        {kIsBadReadEnd, kIsBadReadEndMask, 8,
         "Egg hunter SCASD/JMP EDI terminator", 0.88f},
    };

    for (const auto& pat : eggPatterns) {
        if (pat.length > len) continue;

        for (size_t i = 0; i <= len - pat.length; ++i) {
            bool match = true;
            for (uint32_t j = 0; j < pat.length; ++j) {
                if ((data[i + j] & pat.mask[j]) !=
                    (pat.bytes[j] & pat.mask[j])) {
                    match = false;
                    break;
                }
            }
            if (!match) continue;

            // For the SEH preamble, require additional context:
            // Look for FS segment prefix (0x64) nearby
            if (pat.bytes == kSEH) {
                bool foundFS = false;
                size_t searchEnd = std::min(i + 0x30, len);
                for (size_t k = i + 2; k < searchEnd; ++k) {
                    if (data[k] == 0x64 && k + 6 < len &&
                        data[k + 1] == 0xFF && data[k + 2] == 0x35 &&
                        data[k + 3] == 0x00 && data[k + 4] == 0x00 &&
                        data[k + 5] == 0x00 && data[k + 6] == 0x00)
                    {
                        foundFS = true;
                        break;
                    }
                }
                if (!foundFS) continue;
            }

            GuestAddress addr = baseAddr + i;
            if (IsAlreadyFlagged(addr)) continue;
            MarkFlagged(addr);

            float adjustedConf = pat.confidence;
            // Boost confidence if we find a 4-byte repeated egg marker nearby
            if (i + pat.length + 8 <= len) {
                // Check for repeated egg tag: mov eax, TAG (B8 xx xx xx xx)
                // followed eventually by scasd (AF) twice
                for (size_t k = i; k + 5 <= len && k < i + 40; ++k) {
                    if (data[k] == 0xB8) {
                        // Found potential egg load
                        adjustedConf = std::min(adjustedConf + 0.10f, 0.98f);
                        break;
                    }
                }
            }

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::ShellcodeEggHunter;
            finding.address     = addr;
            finding.size        = pat.length;
            finding.confidence  = adjustedConf;
            finding.description = pat.desc;

            uint32_t sLen = static_cast<uint32_t>(
                std::min<size_t>(len - i, kMaxSampleBytes));
            finding.sample.assign(data + i, data + i + sLen);

            AddFinding(std::move(finding));
            break;
        }
    }
}

// ============================================================================
// Shellcode Detection — Stack-Based Shellcode
// ============================================================================

void MemoryForensics::Impl::DetectStackShellcode(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < 4) return;

    // push-ret technique: 68 xx xx xx xx C3
    for (size_t i = 0; i + 5 < len; ++i) {
        if (data[i] == 0x68 && data[i + 5] == 0xC3) {
            GuestAddress addr = baseAddr + i;
            if (IsAlreadyFlagged(addr)) continue;
            MarkFlagged(addr);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::StackShellcode;
            finding.address     = addr;
            finding.size        = 6;
            finding.confidence  = 0.80f;
            finding.description = "PUSH/RET shellcode technique";

            uint32_t sLen = static_cast<uint32_t>(
                std::min<size_t>(len - i, kMaxSampleBytes));
            finding.sample.assign(data + i, data + i + sLen);

            AddFinding(std::move(finding));
            return; // One per buffer
        }
    }

    // call esp: FF D4 / jmp esp: FF E4
    for (size_t i = 0; i + 1 < len; ++i) {
        if (data[i] == 0xFF &&
            (data[i + 1] == 0xD4 || data[i + 1] == 0xE4))
        {
            GuestAddress addr = baseAddr + i;
            if (IsAlreadyFlagged(addr)) continue;
            MarkFlagged(addr);

            const char* desc = (data[i + 1] == 0xD4)
                               ? "CALL ESP — stack execution"
                               : "JMP ESP — stack execution";

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::StackShellcode;
            finding.address     = addr;
            finding.size        = 2;
            finding.confidence  = 0.85f;
            finding.description = desc;
            finding.sample.assign(data + i, data + i + 2);

            AddFinding(std::move(finding));
            return;
        }
    }
}

// ============================================================================
// Shellcode Scan Dispatcher
// ============================================================================

void MemoryForensics::Impl::ScanBufferForShellcode(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr,
    const VirtualMemory& /*memory*/) noexcept
{
    if (len < 4) return;

    DetectNopSleds(data, len, baseAddr);
    DetectDecoderStubs(data, len, baseAddr);
    DetectEggHunters(data, len, baseAddr);
    DetectStackShellcode(data, len, baseAddr);
}

// ============================================================================
// PE Injection Detection
// ============================================================================

void MemoryForensics::Impl::ScanBufferForPE(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr,
    const VirtualMemory& memory) noexcept
{
    if (len < 64) return;

    // Scan for MZ header (DOS signature)
    for (size_t i = 0; i + 64 <= len; ++i) {
        if (data[i] != 0x4D || data[i + 1] != 0x5A) continue;

        GuestAddress mzAddr = baseAddr + i;

        // Validate e_lfanew (offset to PE header) at +0x3C
        if (i + 0x3C + 4 > len) continue;
        uint32_t eLfanew = 0;
        std::memcpy(&eLfanew, data + i + 0x3C, sizeof(uint32_t));

        // Sanity: e_lfanew should be within a reasonable range
        if (eLfanew < 0x40 || eLfanew > 0x1000) continue;

        // Check for PE\0\0 signature at e_lfanew
        bool hasPEsig = false;
        if (i + eLfanew + 4 <= len) {
            hasPEsig = (data[i + eLfanew] == 0x50 &&
                        data[i + eLfanew + 1] == 0x45 &&
                        data[i + eLfanew + 2] == 0x00 &&
                        data[i + eLfanew + 3] == 0x00);
        } else {
            // PE sig might be beyond this buffer — read from guest memory
            uint32_t sig = 0;
            if (memory.Read(mzAddr + eLfanew, &sig, 4) == ErrorCode::Success) {
                hasPEsig = (sig == PEConst::kNTSignature);
            }
        }

        if (!hasPEsig) continue;

        // We have a valid MZ + PE signature — flag it
        if (IsAlreadyFlagged(mzAddr)) continue;
        MarkFlagged(mzAddr);

        float confidence = 0.90f;

        // Validate further: check machine type at PE+4
        uint16_t machine = 0;
        if (i + eLfanew + 6 <= len) {
            std::memcpy(&machine, data + i + eLfanew + 4, 2);
        } else {
            memory.Read(mzAddr + eLfanew + 4, &machine, 2);
        }
        if (machine == PEConst::kMachineI386 ||
            machine == PEConst::kMachineAMD64) {
            confidence = 0.95f;
        }

        MemoryFindingDetail finding;
        finding.type        = MemoryFinding::PEHeaderInMemory;
        finding.address     = mzAddr;
        finding.size        = std::min<GuestSize>(len - i, kPageScanBuffer);
        finding.confidence  = confidence;
        finding.description = "PE header (MZ+PE) in non-image memory";

        uint32_t sLen = static_cast<uint32_t>(
            std::min<size_t>(len - i, kMaxSampleBytes));
        finding.sample.assign(data + i, data + i + sLen);

        AddFinding(std::move(finding));

        // Flag DOS stub
        if (eLfanew > 0x40 && i + 0x40 <= len) {
            GuestAddress dosAddr = mzAddr + 0x40;
            if (!IsAlreadyFlagged(dosAddr)) {
                MarkFlagged(dosAddr);

                MemoryFindingDetail dos;
                dos.type        = MemoryFinding::PEDOSStub;
                dos.address     = dosAddr;
                dos.size        = eLfanew - 0x40;
                dos.confidence  = 0.80f;
                dos.description = "DOS stub present in injected PE";

                AddFinding(std::move(dos));
            }
        }

        // Check for import table (data directory index 1)
        // PE optional header starts at eLfanew + 24
        uint32_t optHdrOff = eLfanew + 24;

        // Read optional header magic to determine 32/64-bit
        uint16_t optMagic = 0;
        bool haveOptMagic = false;
        if (i + optHdrOff + 2 <= len) {
            std::memcpy(&optMagic, data + i + optHdrOff, 2);
            haveOptMagic = true;
        } else if (memory.Read(mzAddr + optHdrOff, &optMagic, 2)
                   == ErrorCode::Success) {
            haveOptMagic = true;
        }

        if (haveOptMagic) {
            // Import table RVA is at offset 104 (PE32) or 120 (PE64)
            // from start of optional header
            uint32_t importRVAoff = 0;
            if (optMagic == PEConst::kOptionalHdr32) {
                importRVAoff = optHdrOff + 104;
            } else if (optMagic == PEConst::kOptionalHdr64) {
                importRVAoff = optHdrOff + 120;
            }

            if (importRVAoff > 0) {
                uint32_t importRVA = 0;
                uint32_t importSize = 0;
                bool haveImport = false;

                if (i + importRVAoff + 8 <= len) {
                    std::memcpy(&importRVA, data + i + importRVAoff, 4);
                    std::memcpy(&importSize, data + i + importRVAoff + 4, 4);
                    haveImport = true;
                } else {
                    if (memory.Read(mzAddr + importRVAoff, &importRVA, 4)
                            == ErrorCode::Success &&
                        memory.Read(mzAddr + importRVAoff + 4, &importSize, 4)
                            == ErrorCode::Success) {
                        haveImport = true;
                    }
                }

                if (haveImport && importRVA > 0 && importSize > 0 &&
                    importSize < 0x100000)
                {
                    GuestAddress importAddr = mzAddr + importRVA;
                    if (!IsAlreadyFlagged(importAddr)) {
                        MarkFlagged(importAddr);

                        MemoryFindingDetail imp;
                        imp.type        = MemoryFinding::PEImportTable;
                        imp.address     = importAddr;
                        imp.size        = importSize;
                        imp.confidence  = 0.85f;
                        imp.description =
                            "Import table in injected PE — RVA 0x"
                            + std::to_string(importRVA);

                        AddFinding(std::move(imp));
                    }
                }

                // Export table (data directory index 0): 8 bytes before import
                uint32_t exportRVAoff = importRVAoff - 8;
                uint32_t exportRVA = 0;
                uint32_t exportSize = 0;
                bool haveExport = false;

                if (i + exportRVAoff + 8 <= len) {
                    std::memcpy(&exportRVA, data + i + exportRVAoff, 4);
                    std::memcpy(&exportSize, data + i + exportRVAoff + 4, 4);
                    haveExport = true;
                } else {
                    if (memory.Read(mzAddr + exportRVAoff, &exportRVA, 4)
                            == ErrorCode::Success &&
                        memory.Read(mzAddr + exportRVAoff + 4, &exportSize, 4)
                            == ErrorCode::Success) {
                        haveExport = true;
                    }
                }

                if (haveExport && exportRVA > 0 && exportSize > 0 &&
                    exportSize < 0x100000)
                {
                    GuestAddress exportAddr = mzAddr + exportRVA;
                    if (!IsAlreadyFlagged(exportAddr)) {
                        MarkFlagged(exportAddr);

                        MemoryFindingDetail exp;
                        exp.type        = MemoryFinding::PEExportTable;
                        exp.address     = exportAddr;
                        exp.size        = exportSize;
                        exp.confidence  = 0.85f;
                        exp.description =
                            "Export table in injected PE — RVA 0x"
                            + std::to_string(exportRVA);

                        AddFinding(std::move(exp));
                    }
                }
            }
        }

        // Check section headers for plausible names
        // Number of sections is at PE+6
        uint16_t numSections = 0;
        bool haveNumSect = false;
        if (i + eLfanew + 8 <= len) {
            std::memcpy(&numSections, data + i + eLfanew + 6, 2);
            haveNumSect = true;
        } else {
            haveNumSect = (memory.Read(mzAddr + eLfanew + 6, &numSections, 2)
                           == ErrorCode::Success);
        }

        if (haveNumSect && numSections > 0 &&
            numSections <= PEConst::kMaxSections)
        {
            // SizeOfOptionalHeader at PE+20
            uint16_t sizeOfOpt = 0;
            if (i + eLfanew + 22 <= len) {
                std::memcpy(&sizeOfOpt, data + i + eLfanew + 20, 2);
            } else {
                memory.Read(mzAddr + eLfanew + 20, &sizeOfOpt, 2);
            }

            // Section headers start at eLfanew + 24 + sizeOfOpt
            uint32_t sectStart = eLfanew + 24 + sizeOfOpt;

            // Check if section header area has zero VirtualSize (code cave)
            for (uint16_t s = 0; s < numSections && s < 16; ++s) {
                uint32_t sectOff = sectStart + s * 40;
                // Each section header: 8 bytes name, 4 bytes VirtualSize,
                // 4 bytes VirtualAddress, 4 bytes SizeOfRawData, ...

                uint32_t virtualSize = 0;
                uint32_t rawSize = 0;
                bool haveSecInfo = false;

                if (i + sectOff + 24 <= len) {
                    std::memcpy(&virtualSize, data + i + sectOff + 8, 4);
                    std::memcpy(&rawSize, data + i + sectOff + 16, 4);
                    haveSecInfo = true;
                } else {
                    haveSecInfo =
                        (memory.Read(mzAddr + sectOff + 8, &virtualSize, 4)
                             == ErrorCode::Success) &&
                        (memory.Read(mzAddr + sectOff + 16, &rawSize, 4)
                             == ErrorCode::Success);
                }

                // Code cave: rawSize > virtualSize (padding exists) or
                // large gap between consecutive sections
                if (haveSecInfo && rawSize > virtualSize &&
                    (rawSize - virtualSize) > 64)
                {
                    GuestAddress caveAddr = mzAddr + sectOff;
                    if (!IsAlreadyFlagged(caveAddr)) {
                        MarkFlagged(caveAddr);

                        MemoryFindingDetail cave;
                        cave.type        = MemoryFinding::CodeCaveUsed;
                        cave.address     = caveAddr;
                        cave.size        = rawSize - virtualSize;
                        cave.confidence  = 0.55f;
                        cave.description =
                            "Potential code cave — section rawSize ("
                            + std::to_string(rawSize)
                            + ") exceeds virtualSize ("
                            + std::to_string(virtualSize) + ")";

                        AddFinding(std::move(cave));
                    }
                }
            }
        }

        // Detect reflective DLL loader: look for pattern of walking PE
        // headers in code (typical reflective loader resolves its own base)
        // Common sequence: mov reg, [reg+0x3C] (read e_lfanew)
        // We look for: 8B xx 3C (mov reg, [reg+0x3C]) in nearby code
        // This is a heuristic — the mere presence of a PE in non-image
        // memory with executable protection is suspicious enough.
        auto prot = memory.GetProtection(mzAddr);
        if (prot.has_value() && HasProt(*prot, MemProt::Execute)) {
            GuestAddress reflAddr = mzAddr;
            if (!IsAlreadyFlagged(reflAddr + 1)) {
                MarkFlagged(reflAddr + 1);

                MemoryFindingDetail refl;
                refl.type        = MemoryFinding::ReflectiveDLLStub;
                refl.address     = reflAddr;
                refl.size        = std::min<GuestSize>(len - i, kPageScanBuffer);
                refl.confidence  = 0.80f;
                refl.description =
                    "PE in executable non-image memory — "
                    "possible reflective DLL loading";

                AddFinding(std::move(refl));
            }
        }

        // Skip past this PE to avoid re-scanning its internal structure
        i += std::min<size_t>(eLfanew + 256, len - i - 1);
    }
}

// ============================================================================
// Entropy Analysis — per-page scan
// ============================================================================

void MemoryForensics::Impl::ScanBufferForEntropy(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < 64) return;

    // Compute entropy for the whole buffer
    double ent = MemoryForensics::CalculateEntropy(data, len);

    if (ent >= entropyThreshold) {
        GuestAddress addr = baseAddr;
        if (!IsAlreadyFlagged(addr + 0x80000000ULL)) { // Offset to avoid clash
            MarkFlagged(addr + 0x80000000ULL);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::HighEntropyRegion;
            finding.address     = addr;
            finding.size        = len;
            finding.confidence  = 0.75f;
            finding.entropy     = ent;
            finding.description =
                "High entropy region (" + std::to_string(ent).substr(0, 4)
                + " bits/byte) — likely encrypted or compressed";

            uint32_t sLen = static_cast<uint32_t>(
                std::min<size_t>(len, kMaxSampleBytes));
            finding.sample.assign(data, data + sLen);

            AddFinding(std::move(finding));
        }
    }
}

// ============================================================================
// XOR Encoding Detection
// ============================================================================

void MemoryForensics::Impl::ScanBufferForXOREncoding(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < kMinXORBlockSize) return;

    // Cap the scan length to avoid excessive CPU usage
    size_t scanLen = std::min<size_t>(len, kPageScanBuffer);

    // Temporary buffer for XOR decoding (stack-allocated for small sizes)
    std::array<uint8_t, kPageScanBuffer> decoded{};

    // Single-byte XOR keys (skip 0x00 — identity)
    for (uint16_t key = 0x01; key <= 0xFF; ++key) {
        uint8_t k = static_cast<uint8_t>(key);

        // XOR-decode
        for (size_t j = 0; j < scanLen; ++j) {
            decoded[j] = data[j] ^ k;
        }

        // Check if decoded data contains MZ header
        bool foundPE = false;
        if (scanLen >= 2 && decoded[0] == 0x4D && decoded[1] == 0x5A) {
            foundPE = true;
        }

        // Check if decoded data has significantly lower entropy
        double origEnt = MemoryForensics::CalculateEntropy(data, scanLen);
        double decEnt  = MemoryForensics::CalculateEntropy(
            decoded.data(), scanLen);

        bool entropyDrop = (origEnt - decEnt) > 2.0 && decEnt < 5.0;

        // Check for readable ASCII strings in decoded data
        uint32_t printableRun = 0;
        uint32_t maxPrintable = 0;
        for (size_t j = 0; j < scanLen; ++j) {
            if (IsPrintableAscii(decoded[j])) {
                ++printableRun;
                if (printableRun > maxPrintable) maxPrintable = printableRun;
            } else {
                printableRun = 0;
            }
        }
        bool hasStrings = maxPrintable >= 8;

        if (foundPE || entropyDrop || hasStrings) {
            GuestAddress addr = baseAddr;

            // Use a distinct flag offset per key to allow multiple key findings
            // but still deduplicate same key+address
            GuestAddress flagKey = addr + 0xA0000000ULL + key;
            if (IsAlreadyFlagged(flagKey)) continue;
            MarkFlagged(flagKey);

            float conf = 0.0f;
            if (foundPE)       conf = 0.92f;
            else if (entropyDrop && hasStrings) conf = 0.85f;
            else if (entropyDrop) conf = 0.70f;
            else               conf = 0.60f;

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::XOREncodedBlock;
            finding.address     = addr;
            finding.size        = scanLen;
            finding.confidence  = conf;
            finding.entropy     = origEnt;
            finding.description =
                "XOR-encoded block (key=0x"
                + std::to_string(key) + ")";
            if (foundPE)
                finding.description += " — decodes to PE";
            if (hasStrings)
                finding.description += " — contains readable strings";

            uint32_t sLen = static_cast<uint32_t>(
                std::min<size_t>(scanLen, kMaxSampleBytes));
            finding.sample.assign(decoded.data(), decoded.data() + sLen);

            AddFinding(std::move(finding));

            // Only report the best single-byte key match
            return;
        }
    }

    // Multi-byte XOR keys (2, 4, 8 bytes)
    // Detect by checking for repeating patterns in plaintext
    for (uint32_t keyLen = 2; keyLen <= kMaxXORKeySize; keyLen *= 2) {
        // Heuristic: derive candidate key from assumption that original data
        // contains NULL bytes at regular intervals (common in PE/data)
        // Key = first keyLen bytes XOR'd with 0x00 = first keyLen bytes
        // Better heuristic: look for repeating byte pattern
        //
        // We check if XORing with the first keyLen bytes yields low entropy

        if (scanLen < keyLen * 4) continue;

        // Try the first keyLen bytes as the key
        for (size_t j = 0; j < scanLen; ++j) {
            decoded[j] = data[j] ^ data[j % keyLen];
        }

        // This will always produce zeros for the first keyLen bytes,
        // so instead: try a statistical approach — find the most common
        // byte at each key position in blocks that are likely zero-padded

        // Alternative: just check pairs of positions at key-stride intervals
        // If data[i] == data[i+keyLen] for many i, data may be uniform (bad)
        // But if data[i] ^ data[i+stride] == data[j] ^ data[j+stride] for
        // most i,j → possible multi-byte XOR of structured data

        uint32_t repeatCount = 0;
        size_t checkLen = std::min<size_t>(scanLen - keyLen, 256);
        for (size_t j = 0; j < checkLen; ++j) {
            if (data[j] == data[j + keyLen]) {
                ++repeatCount;
            }
        }

        // If more than 40% of bytes repeat at key interval → likely XOR
        float repeatRatio = static_cast<float>(repeatCount) /
                            static_cast<float>(checkLen);
        if (repeatRatio > 0.40f && repeatRatio < 0.95f) {
            GuestAddress flagKey = baseAddr + 0xB0000000ULL + keyLen;
            if (IsAlreadyFlagged(flagKey)) continue;
            MarkFlagged(flagKey);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::XOREncodedBlock;
            finding.address     = baseAddr;
            finding.size        = scanLen;
            finding.confidence  = 0.55f + repeatRatio * 0.30f;
            finding.entropy     =
                MemoryForensics::CalculateEntropy(data, scanLen);
            finding.description =
                "Possible multi-byte XOR encoding (keyLen="
                + std::to_string(keyLen) + ", repeat="
                + std::to_string(static_cast<int>(repeatRatio * 100))
                + "%)";

            uint32_t sLen = static_cast<uint32_t>(
                std::min<size_t>(scanLen, kMaxSampleBytes));
            finding.sample.assign(data, data + sLen);

            AddFinding(std::move(finding));
        }
    }
}

// ============================================================================
// Base64 Encoding Detection
// ============================================================================

void MemoryForensics::Impl::ScanBufferForBase64(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < kMinBase64Run) return;

    size_t runStart = 0;
    size_t runLen   = 0;

    for (size_t i = 0; i < len; ++i) {
        if (IsBase64Char(data[i])) {
            if (runLen == 0) runStart = i;
            ++runLen;
        } else {
            if (runLen >= kMinBase64Run) {
                // Verify it looks like actual Base64 (length % 4 == 0 or
                // has padding)
                bool valid = (runLen % 4 == 0);
                if (!valid && runLen > 4) {
                    // Check for padding at end
                    size_t end = runStart + runLen - 1;
                    if (data[end] == '=' ||
                        (end > 0 && data[end - 1] == '=')) {
                        valid = true;
                    }
                }

                if (valid) {
                    GuestAddress addr = baseAddr + runStart;
                    if (!IsAlreadyFlagged(addr + 0xC0000000ULL)) {
                        MarkFlagged(addr + 0xC0000000ULL);

                        MemoryFindingDetail finding;
                        finding.type        = MemoryFinding::Base64EncodedBlock;
                        finding.address     = addr;
                        finding.size        = runLen;
                        finding.confidence  =
                            (runLen >= 128) ? 0.85f :
                            (runLen >= 64)  ? 0.70f : 0.55f;
                        finding.description =
                            "Base64-encoded block (" +
                            std::to_string(runLen) + " chars)";

                        uint32_t sLen = static_cast<uint32_t>(
                            std::min<size_t>(runLen, kMaxSampleBytes));
                        finding.sample.assign(
                            data + runStart,
                            data + runStart + sLen);

                        AddFinding(std::move(finding));
                    }
                }
            }
            runLen = 0;
        }
    }

    // Trailing run
    if (runLen >= kMinBase64Run) {
        bool valid = (runLen % 4 == 0);
        if (!valid && runLen > 4) {
            size_t end = runStart + runLen - 1;
            if (data[end] == '=' || (end > 0 && data[end - 1] == '=')) {
                valid = true;
            }
        }
        if (valid) {
            GuestAddress addr = baseAddr + runStart;
            if (!IsAlreadyFlagged(addr + 0xC0000000ULL)) {
                MarkFlagged(addr + 0xC0000000ULL);

                MemoryFindingDetail finding;
                finding.type        = MemoryFinding::Base64EncodedBlock;
                finding.address     = addr;
                finding.size        = runLen;
                finding.confidence  =
                    (runLen >= 128) ? 0.85f :
                    (runLen >= 64)  ? 0.70f : 0.55f;
                finding.description =
                    "Base64-encoded block (" +
                    std::to_string(runLen) + " chars)";

                uint32_t sLen = static_cast<uint32_t>(
                    std::min<size_t>(runLen, kMaxSampleBytes));
                finding.sample.assign(
                    data + runStart,
                    data + runStart + sLen);

                AddFinding(std::move(finding));
            }
        }
    }
}

// ============================================================================
// ROP Chain Detection
// ============================================================================

void MemoryForensics::Impl::ScanBufferForROPChain(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr,
    const VirtualMemory& memory) noexcept
{
    // ROP chains live on the stack: sequences of 4-byte or 8-byte addresses
    // each pointing to a gadget ending in RET (0xC3) or RET N (0xC2 xx xx)
    // or JMP [reg] (FF 2x).
    //
    // We scan the buffer as an array of pointers and check if each target
    // address contains a ret-like instruction.

    if (len < kROPMinGadgets * 4) return;

    // Try 8-byte (x64) pointers first, then 4-byte (x86)
    for (uint32_t ptrSize : {8u, 4u}) {
        uint32_t ptrCount = static_cast<uint32_t>(len / ptrSize);
        if (ptrCount < kROPMinGadgets) continue;

        // Cap iteration to avoid excessive reads
        uint32_t maxCheck = std::min(ptrCount, 512u);

        uint32_t gadgetRun = 0;
        GuestAddress runStartAddr = 0;

        for (uint32_t idx = 0; idx < maxCheck; ++idx) {
            GuestAddress target = 0;
            size_t offset = static_cast<size_t>(idx) * ptrSize;

            if (ptrSize == 8) {
                std::memcpy(&target, data + offset, 8);
            } else {
                uint32_t target32 = 0;
                std::memcpy(&target32, data + offset, 4);
                target = target32;
            }

            // Skip NULL and obviously invalid pointers
            if (target == 0 || target == kGuestInvalid) {
                if (gadgetRun >= kROPMinGadgets) {
                    goto emit_rop;
                }
                gadgetRun = 0;
                continue;
            }

            // Check if target address is executable
            {
            auto prot = memory.GetProtection(target);
            if (!prot.has_value() || !HasProt(*prot, MemProt::Execute)) {
                if (gadgetRun >= kROPMinGadgets) {
                    goto emit_rop;
                }
                gadgetRun = 0;
                continue;
            }

            // Read a few bytes at the target to look for RET/RET N/JMP [reg]
            // We look backwards from the target (gadgets end with RET)
            // But also check the target itself — ROP gadgets point to the
            // start of the gadget, which ends with RET within ~16 bytes
            std::array<uint8_t, 20> gadgetBuf{};
            if (memory.Read(target, gadgetBuf.data(), 20) != ErrorCode::Success) {
                if (gadgetRun >= kROPMinGadgets) {
                    goto emit_rop;
                }
                gadgetRun = 0;
                continue;
            }

            bool isGadget = false;
            for (uint32_t g = 0; g < 16; ++g) {
                // RET
                if (gadgetBuf[g] == 0xC3) {
                    isGadget = true;
                    break;
                }
                // RET imm16
                if (gadgetBuf[g] == 0xC2 && g + 2 < 20) {
                    isGadget = true;
                    break;
                }
                // JMP [reg] / CALL [reg]: FF /4 or FF /2
                if (gadgetBuf[g] == 0xFF && g + 1 < 20) {
                    uint8_t modrm = gadgetBuf[g + 1];
                    uint8_t reg = (modrm >> 3) & 0x07;
                    if (reg == 4 || reg == 2) {
                        isGadget = true;
                        break;
                    }
                }
            }

            if (isGadget) {
                if (gadgetRun == 0) {
                    runStartAddr = baseAddr + offset;
                }
                ++gadgetRun;
            } else {
                if (gadgetRun >= kROPMinGadgets) {
                    goto emit_rop;
                }
                gadgetRun = 0;
            }
            continue;
            } // end block scoping prot/gadgetBuf/isGadget

        emit_rop:
            {
                if (IsAlreadyFlagged(runStartAddr)) {
                    gadgetRun = 0;
                    continue;
                }
                MarkFlagged(runStartAddr);

                float conf = 0.0f;
                if (gadgetRun >= 10) conf = 0.95f;
                else if (gadgetRun >= 6) conf = 0.85f;
                else conf = 0.70f;

                MemoryFindingDetail finding;
                finding.type        = MemoryFinding::ROPGadgetChain;
                finding.address     = runStartAddr;
                finding.size        = gadgetRun * ptrSize;
                finding.confidence  = conf;
                finding.description =
                    "ROP gadget chain: " + std::to_string(gadgetRun)
                    + " consecutive gadget pointers ("
                    + std::to_string(ptrSize) + "-byte)";

                // Sample: the raw pointer bytes
                size_t sOff = static_cast<size_t>(
                    runStartAddr - baseAddr);
                uint32_t sLen = static_cast<uint32_t>(std::min<size_t>(
                    static_cast<size_t>(gadgetRun) * ptrSize,
                    kMaxSampleBytes));
                if (sOff + sLen <= len) {
                    finding.sample.assign(
                        data + sOff, data + sOff + sLen);
                }

                AddFinding(std::move(finding));
                gadgetRun = 0;
            }
        }

        // Check trailing run
        if (gadgetRun >= kROPMinGadgets && !IsAlreadyFlagged(runStartAddr)) {
            MarkFlagged(runStartAddr);

            float conf = 0.0f;
            if (gadgetRun >= 10) conf = 0.95f;
            else if (gadgetRun >= 6) conf = 0.85f;
            else conf = 0.70f;

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::ROPGadgetChain;
            finding.address     = runStartAddr;
            finding.size        = gadgetRun * ptrSize;
            finding.confidence  = conf;
            finding.description =
                "ROP gadget chain: " + std::to_string(gadgetRun)
                + " consecutive gadget pointers ("
                + std::to_string(ptrSize) + "-byte)";

            size_t sOff = static_cast<size_t>(
                runStartAddr - baseAddr);
            uint32_t sLen = static_cast<uint32_t>(std::min<size_t>(
                static_cast<size_t>(gadgetRun) * ptrSize,
                kMaxSampleBytes));
            if (sOff + sLen <= len) {
                finding.sample.assign(
                    data + sOff, data + sOff + sLen);
            }

            AddFinding(std::move(finding));
        }
    }
}

// ============================================================================
// Trampoline / Hook Detection
// ============================================================================

void MemoryForensics::Impl::ScanBufferForTrampolines(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < 5) return;

    // Detect JMP rel32 (E9 xx xx xx xx) or CALL rel32 (E8 xx xx xx xx)
    // at buffer start — common for function hooks / trampolines
    // Also detect: FF 25 xx xx xx xx (JMP [rip+disp32]) — IAT-style
    // and: 48 B8 xx xx xx xx xx xx xx xx FF E0 (mov rax, imm64; jmp rax)

    // We focus on the first instruction of each page-aligned boundary
    for (size_t i = 0; i + 5 <= len; i += kPageSize) {
        // JMP rel32
        if (data[i] == 0xE9) {
            GuestAddress addr = baseAddr + i;
            if (IsAlreadyFlagged(addr + 0xD0000000ULL)) continue;
            MarkFlagged(addr + 0xD0000000ULL);

            int32_t rel32 = 0;
            std::memcpy(&rel32, data + i + 1, 4);
            GuestAddress target = addr + 5 + rel32;

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::TrampolineCode;
            finding.address     = addr;
            finding.size        = 5;
            finding.confidence  = 0.70f;
            finding.description =
                "JMP trampoline at page boundary → 0x"
                + std::to_string(target);
            finding.sample.assign(data + i, data + i + 5);

            AddFinding(std::move(finding));
        }

        // JMP [rip+disp32]: FF 25 xx xx xx xx
        if (i + 6 <= len && data[i] == 0xFF && data[i + 1] == 0x25) {
            GuestAddress addr = baseAddr + i;
            if (IsAlreadyFlagged(addr + 0xD0000000ULL)) continue;
            MarkFlagged(addr + 0xD0000000ULL);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::TrampolineCode;
            finding.address     = addr;
            finding.size        = 6;
            finding.confidence  = 0.65f;
            finding.description = "JMP [RIP+disp32] trampoline (IAT-style)";
            finding.sample.assign(data + i, data + i + 6);

            AddFinding(std::move(finding));
        }

        // MOV RAX, imm64; JMP RAX: 48 B8 <8 bytes> FF E0
        if (i + 12 <= len &&
            data[i] == 0x48 && data[i + 1] == 0xB8 &&
            data[i + 10] == 0xFF && data[i + 11] == 0xE0)
        {
            GuestAddress addr = baseAddr + i;
            if (IsAlreadyFlagged(addr + 0xD0000000ULL)) continue;
            MarkFlagged(addr + 0xD0000000ULL);

            uint64_t target = 0;
            std::memcpy(&target, data + i + 2, 8);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::TrampolineCode;
            finding.address     = addr;
            finding.size        = 12;
            finding.confidence  = 0.80f;
            finding.description =
                "MOV RAX, imm64; JMP RAX trampoline → 0x"
                + std::to_string(target);
            finding.sample.assign(data + i, data + i + 12);

            AddFinding(std::move(finding));
        }
    }
}

// ============================================================================
// Suspicious String Table Detection
// ============================================================================

void MemoryForensics::Impl::ScanBufferForSuspiciousStrings(
    const uint8_t* data, size_t len,
    GuestAddress baseAddr) noexcept
{
    if (len < 8) return;

    // Case-insensitive search for known malware/C2 strings
    // Build a lowercase copy of the buffer for searching
    size_t scanLen = std::min<size_t>(len, kPageScanBuffer);

    // We do inline lowercase comparison to avoid allocating a copy
    uint32_t matchCount = 0;
    GuestAddress firstMatchAddr = 0;

    for (const char* needle : kSuspiciousStrings) {
        size_t needleLen = std::strlen(needle);
        if (needleLen == 0 || needleLen > scanLen) continue;

        for (size_t i = 0; i <= scanLen - needleLen; ++i) {
            bool match = true;
            for (size_t j = 0; j < needleLen; ++j) {
                uint8_t c = data[i + j];
                // Lowercase ASCII
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != static_cast<uint8_t>(needle[j])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                if (matchCount == 0) {
                    firstMatchAddr = baseAddr + i;
                }
                ++matchCount;
                break; // One match per needle string
            }
        }
    }

    if (matchCount >= kMinStringTableEntries) {
        if (!IsAlreadyFlagged(firstMatchAddr + 0xE0000000ULL)) {
            MarkFlagged(firstMatchAddr + 0xE0000000ULL);

            MemoryFindingDetail finding;
            finding.type        = MemoryFinding::SuspiciousStringTable;
            finding.address     = baseAddr;
            finding.size        = scanLen;
            finding.confidence  =
                (matchCount >= 8) ? 0.90f :
                (matchCount >= 6) ? 0.80f : 0.65f;
            finding.description =
                "Suspicious string table: " + std::to_string(matchCount)
                + " known malware/C2 strings found";

            uint32_t sLen = static_cast<uint32_t>(
                std::min<size_t>(scanLen, kMaxSampleBytes));
            finding.sample.assign(data, data + sLen);

            AddFinding(std::move(finding));
        }
    }
}

} // namespace Phantom
