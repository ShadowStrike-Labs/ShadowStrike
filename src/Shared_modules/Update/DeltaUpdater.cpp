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
#include "pch.h"
#include "DeltaUpdater.hpp"
#include "../Utils/HashUtils.hpp"

#include <unordered_map>
#include <cstring>

// ============================================================================
// ANONYMOUS NAMESPACE – Internal helpers, constants, serialization
// ============================================================================

namespace {

constexpr const wchar_t* kLogCategory = L"DeltaUpdater";

constexpr uint8_t  kFlagCompressed  = 0x01;
constexpr size_t   kDiffBlockSize   = 4096;
constexpr int      kMaxHashProbes   = 16;

constexpr uint64_t kMaxPatchBytes =
    static_cast<uint64_t>(ShadowStrike::Update::DeltaConstants::MAX_PATCH_SIZE_MB)
        * 1024ULL * 1024ULL;

constexpr uint64_t kMaxFileBytes =
    static_cast<uint64_t>(ShadowStrike::Update::DeltaConstants::MAX_FILE_SIZE_GB)
        * 1024ULL * 1024ULL * 1024ULL;

// magic(4)+ver(2)+alg(1)+flags(1)+srcSz(8)+tgtSz(8)+patchSz(8)+srcH(32)+tgtH(32)
constexpr size_t kHeaderBytes = 96;

constexpr int kErrInvalidHeader  = 1;
constexpr int kErrSrcChecksum    = 2;
constexpr int kErrOutChecksum    = 3;
constexpr int kErrPatchTooLarge  = 4;
constexpr int kErrFileTooLarge   = 5;
constexpr int kErrCompression    = 6;
constexpr int kErrDecompression  = 7;
constexpr int kErrIO             = 8;
constexpr int kErrNotSupported   = 9;
constexpr int kErrInvalidOp      = 10;
constexpr int kErrNotInitialized = 11;
constexpr int kErrSizeMismatch   = 12;

namespace HU = ::ShadowStrike::Utils::HashUtils;
namespace FU = ::ShadowStrike::Utils::FileUtils;

// ============================================================================
// Little-endian serialization (memcpy-safe, no aliasing violations)
// ============================================================================

inline void PutU16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v));
    b.push_back(static_cast<uint8_t>(v >> 8));
}

inline void PutU32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        b.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

inline void PutU64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        b.push_back(static_cast<uint8_t>(v >> (i * 8)));
}

[[nodiscard]] inline uint16_t GetU16(const uint8_t* p) noexcept {
    uint16_t v = 0;
    std::memcpy(&v, p, 2);
    return v;
}

[[nodiscard]] inline uint32_t GetU32(const uint8_t* p) noexcept {
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

[[nodiscard]] inline uint64_t GetU64(const uint8_t* p) noexcept {
    uint64_t v = 0;
    std::memcpy(&v, p, 8);
    return v;
}

// ============================================================================
// SSDP header wire-format
// ============================================================================

void SerializeHeader(const ShadowStrike::Update::PatchHeader& h,
                     std::vector<uint8_t>& buf) {
    buf.reserve(buf.size() + kHeaderBytes);
    PutU32(buf, h.magic);
    PutU16(buf, h.version);
    buf.push_back(static_cast<uint8_t>(h.algorithm));
    buf.push_back(h.flags);
    PutU64(buf, h.sourceSize);
    PutU64(buf, h.targetSize);
    PutU64(buf, h.patchSize);
    buf.insert(buf.end(), h.sourceChecksum.begin(), h.sourceChecksum.end());
    buf.insert(buf.end(), h.targetChecksum.begin(), h.targetChecksum.end());
}

[[nodiscard]] bool DeserializeHeader(const uint8_t* data, size_t len,
                                     ShadowStrike::Update::PatchHeader& h) noexcept {
    if (len < kHeaderBytes) return false;
    const uint8_t* p = data;
    h.magic     = GetU32(p); p += 4;
    h.version   = GetU16(p); p += 2;
    h.algorithm = static_cast<ShadowStrike::Update::PatchAlgorithm>(*p++);
    h.flags     = *p++;
    h.sourceSize = GetU64(p); p += 8;
    h.targetSize = GetU64(p); p += 8;
    h.patchSize  = GetU64(p); p += 8;
    std::memcpy(h.sourceChecksum.data(), p, 32); p += 32;
    std::memcpy(h.targetChecksum.data(), p, 32);
    return true;
}

// ============================================================================
// Ntdll XPRESS-Huffman compression
// ============================================================================

constexpr USHORT kXpressHuff    = 0x0004;
constexpr USHORT kEngineMaximum = 0x0100;

using FnCompress   = NTSTATUS(NTAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);
using FnDecompress = NTSTATUS(NTAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
using FnGetWsSize  = NTSTATUS(NTAPI*)(USHORT, PULONG, PULONG);

struct NtdllCompress {
    FnCompress   pCompress     = nullptr;
    FnDecompress pDecompressEx = nullptr;
    FnGetWsSize  pGetWsSize    = nullptr;
    std::atomic<bool> resolved{false};

    static NtdllCompress& Get() noexcept {
        static NtdllCompress s;
        return s;
    }

    bool Resolve() noexcept {
        if (resolved.load(std::memory_order_acquire))
            return pCompress && pDecompressEx && pGetWsSize;
        HMODULE h = ::GetModuleHandleW(L"ntdll.dll");
        if (h) {
            pCompress     = reinterpret_cast<FnCompress>(
                                ::GetProcAddress(h, "RtlCompressBuffer"));
            pDecompressEx = reinterpret_cast<FnDecompress>(
                                ::GetProcAddress(h, "RtlDecompressBufferEx"));
            pGetWsSize    = reinterpret_cast<FnGetWsSize>(
                                ::GetProcAddress(h, "RtlGetCompressionWorkSpaceSize"));
        }
        resolved.store(true, std::memory_order_release);
        return pCompress && pDecompressEx && pGetWsSize;
    }
};

[[nodiscard]] bool CompressPayload(const uint8_t* in, size_t inLen,
                                   std::vector<uint8_t>& out) {
    auto& nt = NtdllCompress::Get();
    if (!nt.Resolve() || inLen == 0) return false;

    const auto fmt = static_cast<USHORT>(kXpressHuff | kEngineMaximum);
    ULONG cwsSize = 0, fwsSize = 0;
    if (nt.pGetWsSize(fmt, &cwsSize, &fwsSize) < 0) return false;

    auto ws = std::make_unique<uint8_t[]>(cwsSize);
    size_t outCap = inLen + (inLen >> 4) + 512;
    if (outCap > kMaxPatchBytes) outCap = static_cast<size_t>(kMaxPatchBytes);
    out.resize(outCap);

    ULONG finalSz = 0;
    NTSTATUS st = nt.pCompress(fmt,
        const_cast<PUCHAR>(in), static_cast<ULONG>(inLen),
        out.data(), static_cast<ULONG>(outCap),
        4096, &finalSz, ws.get());
    if (st < 0) { out.clear(); return false; }
    out.resize(finalSz);
    return true;
}

[[nodiscard]] bool DecompressPayload(const uint8_t* in, size_t inLen,
                                     size_t expectedLen,
                                     std::vector<uint8_t>& out) {
    auto& nt = NtdllCompress::Get();
    if (!nt.Resolve() || inLen == 0) return false;
    if (expectedLen > kMaxFileBytes) return false;

    const auto fmtEng = static_cast<USHORT>(kXpressHuff | kEngineMaximum);
    ULONG cwsSize = 0, fwsSize = 0;
    if (nt.pGetWsSize(fmtEng, &cwsSize, &fwsSize) < 0) return false;

    auto ws = std::make_unique<uint8_t[]>(fwsSize);
    out.resize(expectedLen);

    ULONG finalSz = 0;
    NTSTATUS st = nt.pDecompressEx(kXpressHuff,
        out.data(), static_cast<ULONG>(expectedLen),
        const_cast<PUCHAR>(in), static_cast<ULONG>(inLen),
        &finalSz, ws.get());
    if (st < 0) { out.clear(); return false; }
    out.resize(finalSz);
    return true;
}

// ============================================================================
// FNV-1a block hash
// ============================================================================

[[nodiscard]] inline uint32_t Fnv1aBlock(const uint8_t* d, size_t n) noexcept {
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < n; ++i) { h ^= d[i]; h *= 0x01000193u; }
    return h;
}

// ============================================================================
// File I/O helpers (std::byte ↔ uint8_t bridge)
// ============================================================================

[[nodiscard]] bool ReadFileBytes(const std::filesystem::path& p,
                                 std::vector<uint8_t>& out) {
    std::vector<std::byte> raw;
    FU::Error err;
    if (!FU::ReadAllBytes(p.wstring(), raw, &err)) return false;
    out.resize(raw.size());
    if (!raw.empty()) std::memcpy(out.data(), raw.data(), raw.size());
    return true;
}

[[nodiscard]] bool WriteFileBytes(const std::filesystem::path& p,
                                  const std::vector<uint8_t>& d) {
    FU::Error err;
    return FU::WriteAllBytesAtomic(p.wstring(),
        reinterpret_cast<const std::byte*>(d.data()), d.size(), &err);
}

// ============================================================================
// SHA-256 convenience
// ============================================================================

[[nodiscard]] bool Sha256Data(const void* data, size_t len,
                              std::array<uint8_t, 32>& out) {
    std::vector<uint8_t> hash;
    if (!HU::Compute(HU::Algorithm::SHA256, data, len, hash)) return false;
    if (hash.size() != 32) return false;
    std::memcpy(out.data(), hash.data(), 32);
    return true;
}

[[nodiscard]] bool Sha256File(const std::filesystem::path& path,
                              std::array<uint8_t, 32>& out) {
    std::vector<uint8_t> hash;
    if (!HU::ComputeFile(HU::Algorithm::SHA256, path.wstring(), hash)) return false;
    if (hash.size() != 32) return false;
    std::memcpy(out.data(), hash.data(), 32);
    return true;
}

} // anonymous namespace

// ============================================================================
//
//  ShadowStrike::Update namespace — full implementation
//
// ============================================================================

namespace ShadowStrike {
namespace Update {

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

bool PatchHeader::IsValid() const noexcept {
    if (magic != DeltaConstants::PATCH_MAGIC) return false;
    if (version == 0 || version > 10)         return false;
    if (static_cast<uint8_t>(algorithm) >
        static_cast<uint8_t>(PatchAlgorithm::Custom)) return false;
    if (sourceSize > kMaxFileBytes)  return false;
    if (targetSize > kMaxFileBytes)  return false;
    if (patchSize  > kMaxPatchBytes) return false;
    return true;
}

std::string PatchHeader::ToJson() const {
    auto srcHex = HU::ToHexLower(sourceChecksum.data(), 32);
    auto tgtHex = HU::ToHexLower(targetChecksum.data(), 32);
    std::string j = "{";
    j += "\"magic\":"       + std::to_string(magic);
    j += ",\"version\":"    + std::to_string(version);
    j += ",\"algorithm\":"  + std::to_string(static_cast<int>(algorithm));
    j += ",\"flags\":"      + std::to_string(flags);
    j += ",\"sourceSize\":" + std::to_string(sourceSize);
    j += ",\"targetSize\":" + std::to_string(targetSize);
    j += ",\"patchSize\":"  + std::to_string(patchSize);
    j += ",\"sourceChecksum\":\"" + srcHex + "\"";
    j += ",\"targetChecksum\":\"" + tgtHex + "\"";
    j += "}";
    return j;
}

std::string PatchInfo::ToJson() const {
    std::string j = "{";
    j += "\"patchPath\":\"" + patchPath.string() + "\"";
    j += ",\"header\":"     + header.ToJson();
    j += ",\"sourceFile\":\"" + sourceFile.string() + "\"";
    j += ",\"targetFile\":\"" + targetFile.string() + "\"";
    j += ",\"compressionRatio\":" + std::to_string(compressionRatio);
    j += ",\"estimatedMemory\":"  + std::to_string(estimatedMemory);
    j += "}";
    return j;
}

std::string PatchProgress::ToJson() const {
    std::string j = "{";
    j += "\"state\":"            + std::to_string(static_cast<int>(state));
    j += ",\"progressPercent\":" + std::to_string(progressPercent);
    j += ",\"bytesProcessed\":"  + std::to_string(bytesProcessed);
    j += ",\"totalBytes\":"      + std::to_string(totalBytes);
    j += ",\"currentOperation\":\"" + currentOperation + "\"";
    j += ",\"speedBps\":"   + std::to_string(speedBps);
    j += ",\"etaSeconds\":" + std::to_string(etaSeconds);
    j += "}";
    return j;
}

std::string PatchResult::ToJson() const {
    std::string j = "{";
    j += "\"success\":"   + std::string(success ? "true" : "false");
    j += ",\"sourceFile\":\"" + sourceFile.string() + "\"";
    j += ",\"outputFile\":\"" + outputFile.string() + "\"";
    j += ",\"algorithmUsed\":" + std::to_string(static_cast<int>(algorithmUsed));
    j += ",\"bytesSaved\":"   + std::to_string(bytesSaved);
    j += ",\"durationMs\":"   + std::to_string(durationMs);
    j += ",\"outputVerified\":" + std::string(outputVerified ? "true" : "false");
    j += ",\"errorMessage\":\"" + errorMessage + "\"";
    j += "}";
    return j;
}

void DeltaStatistics::Reset() noexcept {
    patchesApplied = 0;
    patchesFailed = 0;
    bytesProcessed = 0;
    bytesSaved = 0;
    totalDurationMs = 0;
    for (auto& a : byAlgorithm) a = 0;
    startTime = Clock::now();
}

std::string DeltaStatistics::ToJson() const {
    std::string j = "{";
    j += "\"patchesApplied\":" + std::to_string(patchesApplied);
    j += ",\"patchesFailed\":" + std::to_string(patchesFailed);
    j += ",\"bytesProcessed\":" + std::to_string(bytesProcessed);
    j += ",\"bytesSaved\":"     + std::to_string(bytesSaved);
    j += ",\"totalDurationMs\":" + std::to_string(totalDurationMs);
    j += ",\"byAlgorithm\":[";
    for (size_t i = 0; i < byAlgorithm.size(); ++i) {
        if (i > 0) j += ",";
        j += std::to_string(byAlgorithm[i]);
    }
    j += "]}";
    return j;
}

bool DeltaUpdaterConfiguration::IsValid() const noexcept {
    if (maxPatchSizeMB == 0 || maxPatchSizeMB > DeltaConstants::MAX_PATCH_SIZE_MB)
        return false;
    if (maxFileSizeGB == 0 || maxFileSizeGB > DeltaConstants::MAX_FILE_SIZE_GB)
        return false;
    if (streamBufferSize < 4096)
        return false;
    return true;
}

// ============================================================================
// DELTA UPDATER IMPL (PIMPL)
// ============================================================================

class DeltaUpdaterImpl {
public:
    DeltaUpdaterConfiguration          m_config;
    mutable std::shared_mutex          m_mutex;
    DeltaUpdaterStatus                 m_status{DeltaUpdaterStatus::Uninitialized};
    std::atomic<bool>                  m_initialized{false};

    PatchProgress                      m_progress;
    mutable std::mutex                 m_progressMutex;

    DeltaStatistics                    m_stats;

    PatchProgressCallback              m_progressCb;
    PatchCompletionCallback            m_completionCb;
    ErrorCallback                      m_errorCb;
    mutable std::mutex                 m_callbackMutex;

    fs::path                           m_tempDir;

    // ====================================================================
    // Callback dispatch (exception-safe)
    // ====================================================================

    void NotifyProgress(const PatchProgress& p) {
        std::lock_guard lk(m_callbackMutex);
        if (m_progressCb) {
            try { m_progressCb(p); } catch (...) {}
        }
    }

    void NotifyCompletion(const PatchResult& r) {
        std::lock_guard lk(m_callbackMutex);
        if (m_completionCb) {
            try { m_completionCb(r); } catch (...) {}
        }
    }

    void NotifyError(const std::string& msg, int code) {
        std::lock_guard lk(m_callbackMutex);
        if (m_errorCb) {
            try { m_errorCb(msg, code); } catch (...) {}
        }
    }

    // ====================================================================
    // Progress tracking
    // ====================================================================

    void SetProgress(PatchState state, uint8_t pct, uint64_t processed,
                     uint64_t total, const std::string& op) {
        PatchProgress snap;
        {
            std::lock_guard lk(m_progressMutex);
            m_progress.state            = state;
            m_progress.progressPercent  = pct;
            m_progress.bytesProcessed   = processed;
            m_progress.totalBytes       = total;
            m_progress.currentOperation = op;

            if (processed > 0 && m_stats.startTime != TimePoint{}) {
                auto elapsed = Clock::now() - m_stats.startTime;
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
                if (ms > 0) {
                    m_progress.speedBps = static_cast<uint64_t>(
                        (static_cast<double>(processed) / static_cast<double>(ms)) * 1000.0);
                    if (m_progress.speedBps > 0 && total > processed) {
                        m_progress.etaSeconds = static_cast<uint32_t>(
                            (total - processed) / m_progress.speedBps);
                    }
                }
            }
            snap = m_progress;
        }
        NotifyProgress(snap);
    }

    // ====================================================================
    // Core: apply operations from decoded ops buffer onto source
    // ====================================================================

    [[nodiscard]] bool ExecuteOps(std::span<const uint8_t> source,
                                  std::span<const uint8_t> ops,
                                  uint64_t targetSize,
                                  std::vector<uint8_t>& output) {
        if (targetSize > kMaxFileBytes) return false;
        output.resize(static_cast<size_t>(targetSize));

        size_t opPos     = 0;
        size_t outPos    = 0;
        size_t sourcePos = 0; // tracked for Add operations

        while (opPos < ops.size()) {
            if (ops.size() - opPos < 5) {
                SS_LOG_ERROR(kLogCategory,
                    L"Truncated operation at offset %zu", opPos);
                return false;
            }

            const auto opcode = static_cast<PatchOperation>(ops[opPos]);
            const uint32_t length = GetU32(ops.data() + opPos + 1);
            opPos += 5;

            switch (opcode) {
            case PatchOperation::Add: {
                if (length > ops.size() - opPos) return false;
                if (sourcePos > source.size() ||
                    length > source.size() - sourcePos) return false;
                if (outPos > targetSize ||
                    length > targetSize - outPos) return false;

                for (uint32_t i = 0; i < length; ++i)
                    output[outPos + i] =
                        static_cast<uint8_t>(source[sourcePos + i] ^ ops[opPos + i]);

                sourcePos += length;
                outPos    += length;
                opPos     += length;
                break;
            }
            case PatchOperation::Copy: {
                if (ops.size() - opPos < 8) return false;
                const uint64_t srcOff = GetU64(ops.data() + opPos);
                opPos += 8;
                if (srcOff > source.size() ||
                    length > source.size() - srcOff) return false;
                if (outPos > targetSize ||
                    length > targetSize - outPos) return false;

                std::memcpy(output.data() + outPos,
                            source.data() + srcOff, length);
                outPos += length;
                break;
            }
            case PatchOperation::Insert: {
                if (length > ops.size() - opPos) return false;
                if (outPos > targetSize ||
                    length > targetSize - outPos) return false;

                std::memcpy(output.data() + outPos,
                            ops.data() + opPos, length);
                outPos += length;
                opPos  += length;
                break;
            }
            case PatchOperation::Run: {
                if (ops.size() - opPos < 1) return false;
                const uint8_t val = ops[opPos]; opPos += 1;
                if (outPos > targetSize ||
                    length > targetSize - outPos) return false;

                std::memset(output.data() + outPos, val, length);
                outPos += length;
                break;
            }
            default:
                SS_LOG_ERROR(kLogCategory,
                    L"Unknown patch opcode 0x%02X at offset %zu",
                    static_cast<unsigned>(opcode), opPos - 5);
                return false;
            }

            // Progress every 64 KB of output
            if ((outPos & 0xFFFF) == 0 && targetSize > 0) {
                uint8_t pct = static_cast<uint8_t>(
                    (outPos * 100ULL) / targetSize);
                SetProgress(PatchState::Patching, pct, outPos,
                            targetSize, "Applying operations");
            }
        }

        if (outPos != static_cast<size_t>(targetSize)) {
            SS_LOG_ERROR(kLogCategory,
                L"Output size mismatch: got %zu, expected %llu",
                outPos, targetSize);
            return false;
        }
        return true;
    }

    // ====================================================================
    // Core: create patch operations from old→new via block matching
    // ====================================================================

    [[nodiscard]] bool BuildOps(std::span<const uint8_t> oldData,
                                std::span<const uint8_t> newData,
                                std::vector<uint8_t>& opsOut) {
        // Build hash table of old-file blocks
        std::unordered_multimap<uint32_t, uint64_t> blockMap;
        const size_t oldBlocks = oldData.size() / kDiffBlockSize;
        blockMap.reserve(oldBlocks);

        for (size_t i = 0; i < oldBlocks; ++i) {
            uint64_t off = i * kDiffBlockSize;
            uint32_t h   = Fnv1aBlock(oldData.data() + off, kDiffBlockSize);
            blockMap.emplace(h, off);
        }

        // Scan new file in blocks, emit Copy for matches, Insert otherwise
        size_t newOff = 0;
        size_t pendingInsertStart = 0;
        bool   inPending = false;

        auto flushInsert = [&]() {
            if (!inPending) return;
            size_t len = newOff - pendingInsertStart;
            if (len == 0) { inPending = false; return; }
            // Emit Insert op: opcode(1) + length(4) + data(len)
            opsOut.push_back(static_cast<uint8_t>(PatchOperation::Insert));
            PutU32(opsOut, static_cast<uint32_t>(len));
            opsOut.insert(opsOut.end(),
                          newData.data() + pendingInsertStart,
                          newData.data() + pendingInsertStart + len);
            inPending = false;
        };

        while (newOff + kDiffBlockSize <= newData.size()) {
            uint32_t h = Fnv1aBlock(newData.data() + newOff, kDiffBlockSize);
            auto range = blockMap.equal_range(h);

            bool matched = false;
            int probes = 0;
            for (auto it = range.first;
                 it != range.second && probes < kMaxHashProbes;
                 ++it, ++probes) {
                uint64_t oldOff = it->second;
                if (std::memcmp(oldData.data() + oldOff,
                                newData.data() + newOff,
                                kDiffBlockSize) == 0) {
                    // Extend match forward as far as possible
                    size_t matchLen = kDiffBlockSize;
                    while (newOff + matchLen < newData.size() &&
                           oldOff + matchLen < oldData.size() &&
                           newData[newOff + matchLen] == oldData[oldOff + matchLen]) {
                        ++matchLen;
                    }

                    flushInsert();

                    // Emit Copy op: opcode(1) + length(4) + offset(8)
                    opsOut.push_back(
                        static_cast<uint8_t>(PatchOperation::Copy));
                    PutU32(opsOut, static_cast<uint32_t>(matchLen));
                    PutU64(opsOut, oldOff);

                    newOff += matchLen;
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                if (!inPending) {
                    pendingInsertStart = newOff;
                    inPending = true;
                }
                newOff += kDiffBlockSize;
            }
        }

        // Remaining tail bytes
        if (newOff < newData.size()) {
            if (!inPending) {
                pendingInsertStart = newOff;
                inPending = true;
            }
            newOff = newData.size();
        }
        flushInsert();
        return true;
    }

    // ====================================================================
    // Full apply-from-buffers pipeline
    // ====================================================================

    [[nodiscard]] bool ApplyFromBuffers(std::span<const uint8_t> source,
                                        std::span<const uint8_t> patchData,
                                        std::vector<uint8_t>& output,
                                        PatchResult& result) {
        auto t0 = Clock::now();
        result = {};
        result.algorithmUsed = PatchAlgorithm::Custom;

        // 1. Deserialize header
        PatchHeader hdr;
        if (!DeserializeHeader(patchData.data(), patchData.size(), hdr) ||
            !hdr.IsValid()) {
            result.errorMessage = "Invalid or corrupt patch header";
            NotifyError(result.errorMessage, kErrInvalidHeader);
            return false;
        }

        SetProgress(PatchState::Validating, 5, 0,
                    hdr.targetSize, "Validating patch header");

        // 2. Validate sizes
        if (hdr.sourceSize != source.size()) {
            result.errorMessage = "Source size does not match patch header";
            NotifyError(result.errorMessage, kErrSizeMismatch);
            return false;
        }

        const size_t payloadOff = kHeaderBytes;
        if (patchData.size() < payloadOff ||
            hdr.patchSize > patchData.size() - payloadOff) {
            result.errorMessage = "Patch data truncated";
            NotifyError(result.errorMessage, kErrInvalidHeader);
            return false;
        }

        // 3. Verify source checksum
        SetProgress(PatchState::Validating, 10, 0,
                    hdr.targetSize, "Verifying source checksum");

        std::array<uint8_t, 32> srcHash{};
        if (!Sha256Data(source.data(), source.size(), srcHash)) {
            result.errorMessage = "Failed to compute source SHA-256";
            NotifyError(result.errorMessage, kErrSrcChecksum);
            return false;
        }
        if (!HU::Equal(srcHash.data(), hdr.sourceChecksum.data(), 32)) {
            result.errorMessage = "Source file checksum mismatch";
            NotifyError(result.errorMessage, kErrSrcChecksum);
            return false;
        }

        // 4. Extract operations (decompress if needed)
        SetProgress(PatchState::Patching, 20, 0,
                    hdr.targetSize, "Extracting operations");

        const uint8_t* payload = patchData.data() + payloadOff;
        size_t payloadLen = static_cast<size_t>(hdr.patchSize);

        std::vector<uint8_t> opsBuffer;
        std::span<const uint8_t> ops;

        if (hdr.flags & kFlagCompressed) {
            if (payloadLen < 8) {
                result.errorMessage = "Compressed payload too short";
                NotifyError(result.errorMessage, kErrDecompression);
                return false;
            }
            uint64_t uncompLen = GetU64(payload);
            if (uncompLen > kMaxPatchBytes) {
                result.errorMessage = "Decompressed size exceeds limit";
                NotifyError(result.errorMessage, kErrPatchTooLarge);
                return false;
            }
            if (!DecompressPayload(payload + 8, payloadLen - 8,
                                   static_cast<size_t>(uncompLen),
                                   opsBuffer)) {
                result.errorMessage = "Decompression failed";
                NotifyError(result.errorMessage, kErrDecompression);
                return false;
            }
            ops = opsBuffer;
        } else {
            ops = {payload, payloadLen};
        }

        // 5. Execute operations
        if (!ExecuteOps(source, ops, hdr.targetSize, output)) {
            result.errorMessage = "Patch operation execution failed";
            NotifyError(result.errorMessage, kErrInvalidOp);
            return false;
        }

        // 6. Verify output checksum
        SetProgress(PatchState::Verifying, 90, hdr.targetSize,
                    hdr.targetSize, "Verifying output checksum");

        if (m_config.verifyOutput) {
            std::array<uint8_t, 32> outHash{};
            if (!Sha256Data(output.data(), output.size(), outHash)) {
                result.errorMessage = "Failed to compute output SHA-256";
                NotifyError(result.errorMessage, kErrOutChecksum);
                return false;
            }
            if (!HU::Equal(outHash.data(), hdr.targetChecksum.data(), 32)) {
                result.errorMessage = "Output checksum mismatch – patch produced corrupt data";
                NotifyError(result.errorMessage, kErrOutChecksum);
                return false;
            }
            result.outputVerified = true;
        }

        // 7. Finalize
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - t0);
        result.success       = true;
        result.algorithmUsed = hdr.algorithm;
        result.durationMs    = static_cast<uint32_t>(elapsed.count());

        if (hdr.targetSize < hdr.sourceSize)
            result.bytesSaved = hdr.sourceSize - hdr.targetSize;

        // Statistics
        m_stats.patchesApplied++;
        m_stats.bytesProcessed += hdr.targetSize;
        m_stats.bytesSaved += result.bytesSaved;
        m_stats.totalDurationMs += result.durationMs;
        auto algIdx = static_cast<size_t>(hdr.algorithm);
        if (algIdx < m_stats.byAlgorithm.size())
            m_stats.byAlgorithm[algIdx]++;

        SetProgress(PatchState::Completed, 100, hdr.targetSize,
                    hdr.targetSize, "Patch applied successfully");
        return true;
    }

    // ====================================================================
    // Full create-patch-from-buffers pipeline
    // ====================================================================

    [[nodiscard]] bool CreateFromBuffers(std::span<const uint8_t> oldData,
                                         std::span<const uint8_t> newData,
                                         std::vector<uint8_t>& patchOut,
                                         PatchAlgorithm /*alg*/) {
        // Compute checksums
        PatchHeader hdr;
        hdr.magic     = DeltaConstants::PATCH_MAGIC;
        hdr.version   = 1;
        hdr.algorithm = PatchAlgorithm::Custom;
        hdr.flags     = 0;
        hdr.sourceSize = oldData.size();
        hdr.targetSize = newData.size();

        if (!Sha256Data(oldData.data(), oldData.size(), hdr.sourceChecksum)) {
            SS_LOG_ERROR(kLogCategory, L"Failed to hash source for patch creation");
            return false;
        }
        if (!Sha256Data(newData.data(), newData.size(), hdr.targetChecksum)) {
            SS_LOG_ERROR(kLogCategory, L"Failed to hash target for patch creation");
            return false;
        }

        // Build operations
        std::vector<uint8_t> rawOps;
        rawOps.reserve(newData.size()); // reasonable initial estimate
        if (!BuildOps(oldData, newData, rawOps)) {
            SS_LOG_ERROR(kLogCategory, L"Failed to build diff operations");
            return false;
        }

        // Try compression
        std::vector<uint8_t> compressed;
        bool useCompression = false;
        if (CompressPayload(rawOps.data(), rawOps.size(), compressed) &&
            compressed.size() + 8 < rawOps.size()) {
            useCompression = true;
            hdr.flags |= kFlagCompressed;
            hdr.patchSize = 8 + compressed.size(); // uncompLen(8) + data
        } else {
            hdr.patchSize = rawOps.size();
        }

        // Serialize
        patchOut.clear();
        patchOut.reserve(kHeaderBytes + static_cast<size_t>(hdr.patchSize));
        SerializeHeader(hdr, patchOut);

        if (useCompression) {
            PutU64(patchOut, rawOps.size()); // store uncompressed size
            patchOut.insert(patchOut.end(), compressed.begin(), compressed.end());
        } else {
            patchOut.insert(patchOut.end(), rawOps.begin(), rawOps.end());
        }

        SS_LOG_INFO(kLogCategory,
            L"Patch created: source=%llu bytes, target=%llu bytes, "
            L"patch=%zu bytes, compressed=%s",
            static_cast<unsigned long long>(oldData.size()),
            static_cast<unsigned long long>(newData.size()),
            patchOut.size(),
            useCompression ? L"yes" : L"no");
        return true;
    }
};

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::atomic<bool> DeltaUpdater::s_instanceCreated{false};

// ============================================================================
// FREE FUNCTIONS
// ============================================================================

std::string_view GetAlgorithmName(PatchAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case PatchAlgorithm::Auto:      return "Auto";
        case PatchAlgorithm::BSDiff:    return "BSDiff";
        case PatchAlgorithm::Courgette: return "Courgette";
        case PatchAlgorithm::VCDIFF:    return "VCDIFF";
        case PatchAlgorithm::XDelta3:   return "XDelta3";
        case PatchAlgorithm::Custom:    return "Custom";
    }
    return "Unknown";
}

std::string_view GetPatchStateName(PatchState state) noexcept {
    switch (state) {
        case PatchState::NotStarted: return "NotStarted";
        case PatchState::Validating: return "Validating";
        case PatchState::Patching:   return "Patching";
        case PatchState::Verifying:  return "Verifying";
        case PatchState::Completed:  return "Completed";
        case PatchState::Failed:     return "Failed";
    }
    return "Unknown";
}

PatchAlgorithm DetectAlgorithm(std::span<const uint8_t> patchData) {
    if (patchData.size() < kHeaderBytes) return PatchAlgorithm::Auto;
    PatchHeader hdr;
    if (!DeserializeHeader(patchData.data(), patchData.size(), hdr))
        return PatchAlgorithm::Auto;
    if (hdr.magic != DeltaConstants::PATCH_MAGIC)
        return PatchAlgorithm::Auto;
    return hdr.algorithm;
}

uint64_t EstimatePatchSize(uint64_t sourceSize, uint64_t targetSize) {
    // Heuristic: patch ≈ 30% of the larger file for similar binaries,
    // capped at target size (worst case = full Insert).
    uint64_t larger = (std::max)(sourceSize, targetSize);
    uint64_t estimate = larger * 30 / 100;
    estimate += kHeaderBytes + 64; // header + overhead
    return (std::min)(estimate, targetSize + kHeaderBytes + 64);
}

// ============================================================================
// SINGLETON
// ============================================================================

DeltaUpdater& DeltaUpdater::Instance() noexcept {
    static DeltaUpdater instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool DeltaUpdater::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

DeltaUpdater::DeltaUpdater()
    : m_impl(std::make_unique<DeltaUpdaterImpl>())
{
}

DeltaUpdater::~DeltaUpdater() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool DeltaUpdater::Initialize(const DeltaUpdaterConfiguration& config) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory,
            L"Already initialized – skipping re-initialization");
        return true;
    }

    m_impl->m_status = DeltaUpdaterStatus::Initializing;
    SS_LOG_INFO(kLogCategory,
        L"Initializing DeltaUpdater v%u.%u.%u",
        DeltaConstants::VERSION_MAJOR,
        DeltaConstants::VERSION_MINOR,
        DeltaConstants::VERSION_PATCH);

    if (!config.IsValid()) {
        SS_LOG_ERROR(kLogCategory, L"Invalid configuration supplied");
        m_impl->m_status = DeltaUpdaterStatus::Error;
        return false;
    }

    m_impl->m_config = config;

    // Resolve temp directory
    if (!config.tempDirectory.empty()) {
        m_impl->m_tempDir = config.tempDirectory;
    } else {
        wchar_t buf[MAX_PATH + 1]{};
        DWORD len = ::GetTempPathW(MAX_PATH + 1, buf);
        m_impl->m_tempDir = (len > 0) ? fs::path(buf) / L"ShadowStrike"
                                       : fs::path(L"C:\\ProgramData\\ShadowStrike\\temp");
    }

    // Ensure temp directory exists
    {
        FU::Error fErr;
        if (!FU::CreateDirectories(m_impl->m_tempDir.wstring(), &fErr)) {
            SS_LOG_WARN(kLogCategory,
                L"Could not create temp directory: %s",
                m_impl->m_tempDir.c_str());
        }
    }

    // Resolve ntdll compression functions eagerly
    if (!NtdllCompress::Get().Resolve()) {
        SS_LOG_WARN(kLogCategory,
            L"XPRESS-Huffman compression unavailable – "
            L"patches will be uncompressed");
    }

    m_impl->m_stats.Reset();
    m_impl->m_initialized.store(true, std::memory_order_release);
    m_impl->m_status = DeltaUpdaterStatus::Running;

    SS_LOG_INFO(kLogCategory,
        L"Initialized: tempDir=%s, maxPatch=%zuMB, maxFile=%zuGB, "
        L"verify=%s",
        m_impl->m_tempDir.c_str(),
        config.maxPatchSizeMB,
        config.maxFileSizeGB,
        config.verifyOutput ? L"on" : L"off");
    return true;
}

void DeltaUpdater::Shutdown() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_mutex);
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) return;

    SS_LOG_INFO(kLogCategory, L"Shutting down DeltaUpdater");
    m_impl->m_status = DeltaUpdaterStatus::Stopping;

    {
        std::lock_guard cbLk(m_impl->m_callbackMutex);
        m_impl->m_progressCb   = nullptr;
        m_impl->m_completionCb = nullptr;
        m_impl->m_errorCb      = nullptr;
    }

    m_impl->m_initialized.store(false, std::memory_order_release);
    m_impl->m_status = DeltaUpdaterStatus::Stopped;
    SS_LOG_INFO(kLogCategory, L"DeltaUpdater shut down");
}

bool DeltaUpdater::IsInitialized() const noexcept {
    if (!m_impl) return false;
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

DeltaUpdaterStatus DeltaUpdater::GetStatus() const noexcept {
    if (!m_impl) return DeltaUpdaterStatus::Uninitialized;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// PATCH OPERATIONS
// ============================================================================

bool DeltaUpdater::ApplyPatch(const std::wstring& originalPath,
                              const std::vector<uint8_t>& patchData) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"ApplyPatch called before initialization");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = DeltaUpdaterStatus::Patching;
    m_impl->m_stats.startTime = Clock::now();

    SS_LOG_INFO(kLogCategory, L"ApplyPatch in-place: %s (%zu byte patch)",
        originalPath.c_str(), patchData.size());

    // Size guard
    if (patchData.size() > kMaxPatchBytes) {
        SS_LOG_ERROR(kLogCategory, L"Patch exceeds max size (%zu > %llu)",
            patchData.size(), kMaxPatchBytes);
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    // Read source
    std::vector<uint8_t> source;
    if (!ReadFileBytes(fs::path(originalPath), source)) {
        SS_LOG_ERROR(kLogCategory, L"Failed to read source file: %s",
            originalPath.c_str());
        m_impl->NotifyError("Failed to read source file", kErrIO);
        m_impl->m_stats.patchesFailed++;
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    if (source.size() > kMaxFileBytes) {
        SS_LOG_ERROR(kLogCategory, L"Source file exceeds max size");
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    // Apply
    std::vector<uint8_t> output;
    PatchResult result;
    result.sourceFile = fs::path(originalPath);
    result.outputFile = fs::path(originalPath);

    if (!m_impl->ApplyFromBuffers(source, patchData, output, result)) {
        SS_LOG_ERROR(kLogCategory, L"Patch application failed: %s",
            originalPath.c_str());
        m_impl->m_stats.patchesFailed++;
        m_impl->NotifyCompletion(result);
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    // Write back atomically
    if (!WriteFileBytes(fs::path(originalPath), output)) {
        SS_LOG_ERROR(kLogCategory, L"Failed to write patched file: %s",
            originalPath.c_str());
        m_impl->NotifyError("Failed to write patched output", kErrIO);
        m_impl->m_stats.patchesFailed++;
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    m_impl->NotifyCompletion(result);
    m_impl->m_status = DeltaUpdaterStatus::Running;
    SS_LOG_INFO(kLogCategory,
        L"In-place patch succeeded: %s (%u ms)",
        originalPath.c_str(), result.durationMs);
    return true;
}

PatchResult DeltaUpdater::ApplyPatchFile(const fs::path& sourcePath,
                                         const fs::path& patchPath,
                                         const fs::path& outputPath) {
    PatchResult result;
    result.sourceFile = sourcePath;
    result.outputFile = outputPath;

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        result.errorMessage = "DeltaUpdater not initialized";
        SS_LOG_ERROR(kLogCategory, L"ApplyPatchFile called before initialization");
        return result;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = DeltaUpdaterStatus::Patching;
    m_impl->m_stats.startTime = Clock::now();

    SS_LOG_INFO(kLogCategory,
        L"ApplyPatchFile: source=%s patch=%s output=%s",
        sourcePath.c_str(), patchPath.c_str(), outputPath.c_str());

    // Read source
    std::vector<uint8_t> source;
    if (!ReadFileBytes(sourcePath, source) || source.size() > kMaxFileBytes) {
        result.errorMessage = "Failed to read source file or file too large";
        m_impl->NotifyError(result.errorMessage, kErrIO);
        m_impl->m_stats.patchesFailed++;
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return result;
    }

    // Read patch
    std::vector<uint8_t> patchData;
    if (!ReadFileBytes(patchPath, patchData) || patchData.size() > kMaxPatchBytes) {
        result.errorMessage = "Failed to read patch file or patch too large";
        m_impl->NotifyError(result.errorMessage, kErrIO);
        m_impl->m_stats.patchesFailed++;
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return result;
    }

    // Apply
    std::vector<uint8_t> output;
    if (!m_impl->ApplyFromBuffers(source, patchData, output, result)) {
        m_impl->m_stats.patchesFailed++;
        m_impl->NotifyCompletion(result);
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return result;
    }

    // Ensure parent directory exists
    if (outputPath.has_parent_path()) {
        FU::Error fErr;
        FU::CreateDirectories(outputPath.parent_path().wstring(), &fErr);
    }

    // Write output
    if (!WriteFileBytes(outputPath, output)) {
        result.success = false;
        result.errorMessage = "Failed to write output file";
        m_impl->NotifyError(result.errorMessage, kErrIO);
        m_impl->m_stats.patchesFailed++;
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return result;
    }

    m_impl->NotifyCompletion(result);
    m_impl->m_status = DeltaUpdaterStatus::Running;
    SS_LOG_INFO(kLogCategory,
        L"Patch file applied: %s → %s (%u ms)",
        sourcePath.c_str(), outputPath.c_str(), result.durationMs);
    return result;
}

PatchResult DeltaUpdater::ApplyPatchMemory(
    std::span<const uint8_t> sourceData,
    std::span<const uint8_t> patchData) {
    PatchResult result;

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        result.errorMessage = "DeltaUpdater not initialized";
        SS_LOG_ERROR(kLogCategory,
            L"ApplyPatchMemory called before initialization");
        return result;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = DeltaUpdaterStatus::Patching;
    m_impl->m_stats.startTime = Clock::now();

    if (sourceData.size() > kMaxFileBytes || patchData.size() > kMaxPatchBytes) {
        result.errorMessage = "Input exceeds size limit";
        m_impl->NotifyError(result.errorMessage, kErrFileTooLarge);
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return result;
    }

    std::vector<uint8_t> output;
    if (!m_impl->ApplyFromBuffers(sourceData, patchData, output, result)) {
        m_impl->m_stats.patchesFailed++;
        m_impl->NotifyCompletion(result);
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return result;
    }

    // Write result to temp file so caller can retrieve it
    wchar_t nameBuf[64]{};
    auto tick = static_cast<unsigned long long>(
        Clock::now().time_since_epoch().count());
    swprintf_s(nameBuf, L"ssdp_%llx.tmp", tick);
    fs::path tmpPath = m_impl->m_tempDir / nameBuf;

    if (WriteFileBytes(tmpPath, output)) {
        result.outputFile = tmpPath;
    } else {
        SS_LOG_WARN(kLogCategory,
            L"Could not write temp output; result only in memory");
    }

    m_impl->NotifyCompletion(result);
    m_impl->m_status = DeltaUpdaterStatus::Running;
    return result;
}

bool DeltaUpdater::CreatePatch(const fs::path& oldFile,
                               const fs::path& newFile,
                               const fs::path& patchFile,
                               PatchAlgorithm algorithm) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"CreatePatch called before initialization");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_status = DeltaUpdaterStatus::Patching;

    SS_LOG_INFO(kLogCategory,
        L"CreatePatch: old=%s new=%s patch=%s alg=%S",
        oldFile.c_str(), newFile.c_str(), patchFile.c_str(),
        std::string(GetAlgorithmName(algorithm)).c_str());

    // Read files
    std::vector<uint8_t> oldData, newData;
    if (!ReadFileBytes(oldFile, oldData)) {
        SS_LOG_ERROR(kLogCategory, L"Failed to read old file: %s",
            oldFile.c_str());
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }
    if (!ReadFileBytes(newFile, newData)) {
        SS_LOG_ERROR(kLogCategory, L"Failed to read new file: %s",
            newFile.c_str());
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    if (oldData.size() > kMaxFileBytes || newData.size() > kMaxFileBytes) {
        SS_LOG_ERROR(kLogCategory,
            L"Input file exceeds maximum allowed size (%llu bytes)",
            kMaxFileBytes);
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    // Build patch
    std::vector<uint8_t> patchOut;
    if (!m_impl->CreateFromBuffers(oldData, newData, patchOut, algorithm)) {
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    // Ensure parent directory exists
    if (patchFile.has_parent_path()) {
        FU::Error fErr;
        FU::CreateDirectories(patchFile.parent_path().wstring(), &fErr);
    }

    // Write
    if (!WriteFileBytes(patchFile, patchOut)) {
        SS_LOG_ERROR(kLogCategory, L"Failed to write patch file: %s",
            patchFile.c_str());
        m_impl->m_status = DeltaUpdaterStatus::Running;
        return false;
    }

    m_impl->m_status = DeltaUpdaterStatus::Running;
    SS_LOG_INFO(kLogCategory,
        L"Patch created: %s (%zu bytes)",
        patchFile.c_str(), patchOut.size());
    return true;
}

// ============================================================================
// VALIDATION
// ============================================================================

bool DeltaUpdater::ValidatePatch(const fs::path& patchPath) {
    std::vector<uint8_t> data;
    if (!ReadFileBytes(patchPath, data)) {
        SS_LOG_ERROR(kLogCategory,
            L"ValidatePatch: cannot read %s", patchPath.c_str());
        return false;
    }
    return ValidatePatch(std::span<const uint8_t>(data));
}

bool DeltaUpdater::ValidatePatch(std::span<const uint8_t> patchData) {
    if (patchData.size() < kHeaderBytes) {
        SS_LOG_ERROR(kLogCategory,
            L"ValidatePatch: data too short (%zu < %zu)",
            patchData.size(), kHeaderBytes);
        return false;
    }

    PatchHeader hdr;
    if (!DeserializeHeader(patchData.data(), patchData.size(), hdr)) {
        SS_LOG_ERROR(kLogCategory,
            L"ValidatePatch: header deserialization failed");
        return false;
    }

    if (!hdr.IsValid()) {
        SS_LOG_ERROR(kLogCategory,
            L"ValidatePatch: header validation failed (magic=0x%08X ver=%u)",
            hdr.magic, hdr.version);
        return false;
    }

    // Verify payload size is consistent
    const size_t payloadOff = kHeaderBytes;
    if (patchData.size() < payloadOff + hdr.patchSize) {
        SS_LOG_ERROR(kLogCategory,
            L"ValidatePatch: payload truncated (%zu available, %llu expected)",
            patchData.size() - payloadOff, hdr.patchSize);
        return false;
    }

    SS_LOG_DEBUG(kLogCategory,
        L"ValidatePatch: valid SSDP patch (src=%llu tgt=%llu ops=%llu)",
        hdr.sourceSize, hdr.targetSize, hdr.patchSize);
    return true;
}

std::optional<PatchInfo> DeltaUpdater::GetPatchInfo(const fs::path& patchPath) {
    std::vector<uint8_t> data;
    if (!ReadFileBytes(patchPath, data)) {
        SS_LOG_ERROR(kLogCategory,
            L"GetPatchInfo: cannot read %s", patchPath.c_str());
        return std::nullopt;
    }

    if (data.size() < kHeaderBytes) return std::nullopt;

    PatchHeader hdr;
    if (!DeserializeHeader(data.data(), data.size(), hdr) || !hdr.IsValid())
        return std::nullopt;

    PatchInfo info;
    info.patchPath = patchPath;
    info.header    = hdr;

    if (hdr.sourceSize > 0) {
        info.compressionRatio =
            static_cast<double>(data.size()) /
            static_cast<double>(hdr.sourceSize);
    }

    // Estimated memory: source + target + ops buffer
    info.estimatedMemory = hdr.sourceSize + hdr.targetSize + hdr.patchSize;
    return info;
}

bool DeltaUpdater::VerifySource(const fs::path& sourcePath,
                                const PatchHeader& header) {
    // Check file exists and size matches
    FU::Error fErr;
    FU::FileStat st;
    if (!FU::Stat(sourcePath.wstring(), st, &fErr) || !st.exists) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifySource: file not found: %s", sourcePath.c_str());
        return false;
    }
    if (st.size != header.sourceSize) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifySource: size mismatch (%llu vs expected %llu)",
            st.size, header.sourceSize);
        return false;
    }

    // Verify checksum
    std::array<uint8_t, 32> hash{};
    if (!Sha256File(sourcePath, hash)) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifySource: SHA-256 computation failed for %s",
            sourcePath.c_str());
        return false;
    }
    if (!HU::Equal(hash.data(), header.sourceChecksum.data(), 32)) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifySource: checksum mismatch for %s", sourcePath.c_str());
        return false;
    }

    SS_LOG_DEBUG(kLogCategory,
        L"VerifySource: %s matches patch requirements", sourcePath.c_str());
    return true;
}

// ============================================================================
// PROGRESS
// ============================================================================

PatchProgress DeltaUpdater::GetProgress() const {
    if (!m_impl) {
        PatchProgress empty;
        return empty;
    }
    std::lock_guard lk(m_impl->m_progressMutex);
    return m_impl->m_progress;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void DeltaUpdater::RegisterProgressCallback(PatchProgressCallback callback) {
    if (!m_impl) return;
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_progressCb = std::move(callback);
}

void DeltaUpdater::RegisterCompletionCallback(PatchCompletionCallback callback) {
    if (!m_impl) return;
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_completionCb = std::move(callback);
}

void DeltaUpdater::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_errorCb = std::move(callback);
}

void DeltaUpdater::UnregisterCallbacks() {
    if (!m_impl) return;
    std::lock_guard lk(m_impl->m_callbackMutex);
    m_impl->m_progressCb   = nullptr;
    m_impl->m_completionCb = nullptr;
    m_impl->m_errorCb      = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

DeltaStatistics DeltaUpdater::GetStatistics() const {
    if (!m_impl) {
        DeltaStatistics empty;
        return empty;
    }
    DeltaStatistics copy;
    copy.patchesApplied = m_impl->m_stats.patchesApplied;
    copy.patchesFailed = m_impl->m_stats.patchesFailed;
    copy.bytesProcessed = m_impl->m_stats.bytesProcessed;
    copy.bytesSaved = m_impl->m_stats.bytesSaved;
    copy.totalDurationMs = m_impl->m_stats.totalDurationMs;
    for (size_t i = 0; i < m_impl->m_stats.byAlgorithm.size(); ++i) {
        copy.byAlgorithm[i] = m_impl->m_stats.byAlgorithm[i];
    }
    copy.startTime = m_impl->m_stats.startTime;
    return copy;
}

void DeltaUpdater::ResetStatistics() {
    if (!m_impl) return;
    m_impl->m_stats.Reset();
    SS_LOG_DEBUG(kLogCategory, L"Statistics reset");
}

// ============================================================================
// SELF-TEST
// ============================================================================

bool DeltaUpdater::SelfTest() {
    if (!m_impl) return false;

    SS_LOG_INFO(kLogCategory, L"Running DeltaUpdater self-test");

    // Build deterministic test buffers (2 × 4 blocks = 32 KB)
    constexpr size_t kTestSize = kDiffBlockSize * 8;
    std::vector<uint8_t> oldBuf(kTestSize);
    std::vector<uint8_t> newBuf(kTestSize);

    for (size_t i = 0; i < kTestSize; ++i) {
        oldBuf[i] = static_cast<uint8_t>((i * 131 + 17) & 0xFF);
        newBuf[i] = oldBuf[i]; // start identical
    }

    // Modify two blocks in the new buffer
    for (size_t i = kDiffBlockSize * 2; i < kDiffBlockSize * 3; ++i)
        newBuf[i] ^= 0xAA;
    for (size_t i = kDiffBlockSize * 6; i < kDiffBlockSize * 7; ++i)
        newBuf[i] = static_cast<uint8_t>(i & 0xFF);

    // Create patch
    std::vector<uint8_t> patchBuf;
    if (!m_impl->CreateFromBuffers(oldBuf, newBuf, patchBuf,
                                    PatchAlgorithm::Custom)) {
        SS_LOG_ERROR(kLogCategory, L"Self-test: patch creation failed");
        return false;
    }

    // Validate patch
    if (!ValidatePatch(std::span<const uint8_t>(patchBuf))) {
        SS_LOG_ERROR(kLogCategory, L"Self-test: patch validation failed");
        return false;
    }

    // Apply patch
    std::vector<uint8_t> result;
    PatchResult pr;
    if (!m_impl->ApplyFromBuffers(oldBuf, patchBuf, result, pr)) {
        SS_LOG_ERROR(kLogCategory,
            L"Self-test: patch application failed: %S",
            pr.errorMessage.c_str());
        return false;
    }

    // Verify roundtrip
    if (result.size() != newBuf.size() ||
        std::memcmp(result.data(), newBuf.data(), newBuf.size()) != 0) {
        SS_LOG_ERROR(kLogCategory,
            L"Self-test: roundtrip data mismatch");
        return false;
    }

    SS_LOG_INFO(kLogCategory,
        L"Self-test PASSED (patch=%zu bytes, ratio=%.1f%%)",
        patchBuf.size(),
        (static_cast<double>(patchBuf.size()) /
         static_cast<double>(kTestSize)) * 100.0);
    return true;
}

std::string DeltaUpdater::GetVersionString() noexcept {
    return std::to_string(DeltaConstants::VERSION_MAJOR) + "." +
           std::to_string(DeltaConstants::VERSION_MINOR) + "." +
           std::to_string(DeltaConstants::VERSION_PATCH);
}

}  // namespace Update
}  // namespace ShadowStrike
