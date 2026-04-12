// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
 * @file FuzzLoop.cpp
 * @brief Implementation of the main fuzzing iteration loop.
 */

#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"
#include "ShadowStrike/Fuzzer/Core/MutationEngine.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <set>
#include <sstream>

namespace ShadowStrike::Fuzzer {

// ============================================================================
// Global Ctrl+C Handler State
// ============================================================================

namespace {

std::atomic<bool> g_ctrlCReceived{false};

BOOL WINAPI CtrlCHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        g_ctrlCReceived.store(true, std::memory_order_release);
        return TRUE;
    default:
        return FALSE;
    }
}

}  // namespace

bool InstallCtrlCHandler() noexcept {
    return SetConsoleCtrlHandler(CtrlCHandler, TRUE) != FALSE;
}

bool WasCtrlCReceived() noexcept {
    return g_ctrlCReceived.load(std::memory_order_acquire);
}

void ResetCtrlCFlag() noexcept {
    g_ctrlCReceived.store(false, std::memory_order_release);
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string EscapeJsonString(std::string_view value) noexcept {
    std::string escaped;
    escaped.reserve(value.size() + 8);
    
    for (const char ch : value) {
        switch (ch) {
        case '\\': escaped += "\\\\"; break;
        case '"':  escaped += "\\\""; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (static_cast<unsigned char>(ch) < 0x20) {
                // Control character - escape as \uXXXX
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04X", static_cast<unsigned>(ch));
                escaped += buf;
            } else {
                escaped.push_back(ch);
            }
            break;
        }
    }
    
    return escaped;
}

std::string GetIsoTimestamp() noexcept {
    const auto now = std::chrono::system_clock::now();
    const auto timeT = std::chrono::system_clock::to_time_t(now);
    
    std::tm tm{};
    gmtime_s(&tm, &timeT);
    
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// ============================================================================
// Minimal PE Seed Generators
// ============================================================================

std::vector<uint8_t> GenerateMinimalPE32Seed() noexcept {
    std::vector<uint8_t> pe;
    pe.reserve(512);
    
    // DOS Header (64 bytes)
    pe.resize(64, 0);
    pe[0] = 'M';
    pe[1] = 'Z';
    // e_lfanew at offset 0x3C - point to PE header at offset 64
    pe[0x3C] = 0x40;  // 64 in little-endian
    pe[0x3D] = 0x00;
    pe[0x3E] = 0x00;
    pe[0x3F] = 0x00;
    
    // PE Signature at offset 64
    pe.push_back('P');
    pe.push_back('E');
    pe.push_back(0);
    pe.push_back(0);
    
    // COFF File Header (20 bytes) at offset 68
    pe.push_back(0x4C); pe.push_back(0x01);  // Machine: i386
    pe.push_back(0x01); pe.push_back(0x00);  // NumberOfSections: 1
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);  // TimeDateStamp
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);  // PointerToSymbolTable
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);  // NumberOfSymbols
    pe.push_back(0xE0); pe.push_back(0x00);  // SizeOfOptionalHeader: 224
    pe.push_back(0x02); pe.push_back(0x01);  // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    
    // Optional Header PE32 (224 bytes) at offset 88
    // Magic
    pe.push_back(0x0B); pe.push_back(0x01);  // PE32 magic
    pe.push_back(0x0E); pe.push_back(0x00);  // LinkerVersion
    // SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData
    for (int i = 0; i < 12; ++i) pe.push_back(0x00);
    // AddressOfEntryPoint
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);  // 0x1000
    // BaseOfCode
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);  // 0x1000
    // BaseOfData
    pe.push_back(0x00); pe.push_back(0x20); pe.push_back(0x00); pe.push_back(0x00);  // 0x2000
    // ImageBase
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x40); pe.push_back(0x00);  // 0x00400000
    // SectionAlignment
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);  // 0x1000
    // FileAlignment
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);  // 0x200
    // OS Version
    pe.push_back(0x06); pe.push_back(0x00);  // Major
    pe.push_back(0x00); pe.push_back(0x00);  // Minor
    // Image Version
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    // Subsystem Version
    pe.push_back(0x06); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    // Win32VersionValue
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // SizeOfImage
    pe.push_back(0x00); pe.push_back(0x30); pe.push_back(0x00); pe.push_back(0x00);  // 0x3000
    // SizeOfHeaders
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);  // 0x200
    // CheckSum
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // Subsystem
    pe.push_back(0x03); pe.push_back(0x00);  // CONSOLE
    // DllCharacteristics
    pe.push_back(0x40); pe.push_back(0x81);  // DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    // SizeOfStackReserve
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    // SizeOfStackCommit
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    // SizeOfHeapReserve
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    // SizeOfHeapCommit
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    // LoaderFlags
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // NumberOfRvaAndSizes
    pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);  // 16
    
    // Data directories (16 * 8 = 128 bytes) - all zeros
    for (int i = 0; i < 128; ++i) pe.push_back(0x00);
    
    // Section header (.text) at offset 312
    // Name
    pe.push_back('.'); pe.push_back('t'); pe.push_back('e'); pe.push_back('x');
    pe.push_back('t'); pe.push_back(0); pe.push_back(0); pe.push_back(0);
    // VirtualSize
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);  // 0x1000
    // VirtualAddress
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);  // 0x1000
    // SizeOfRawData
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);  // 0x200
    // PointerToRawData
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);  // 0x200
    // PointerToRelocations
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // PointerToLinenumbers
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // NumberOfRelocations
    pe.push_back(0x00); pe.push_back(0x00);
    // NumberOfLinenumbers
    pe.push_back(0x00); pe.push_back(0x00);
    // Characteristics
    pe.push_back(0x20); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x60);  // CNT_CODE | MEM_EXECUTE | MEM_READ
    
    // Pad to 512 bytes (file alignment)
    while (pe.size() < 512) {
        pe.push_back(0x00);
    }
    
    // Simple code section (just a RET instruction)
    pe.push_back(0xC3);  // RET
    
    // Pad to next file alignment
    while (pe.size() < 1024) {
        pe.push_back(0x00);
    }
    
    return pe;
}

std::vector<uint8_t> GenerateMinimalPE64Seed() noexcept {
    std::vector<uint8_t> pe;
    pe.reserve(512);
    
    // DOS Header (64 bytes)
    pe.resize(64, 0);
    pe[0] = 'M';
    pe[1] = 'Z';
    pe[0x3C] = 0x40;  // e_lfanew = 64
    
    // PE Signature
    pe.push_back('P');
    pe.push_back('E');
    pe.push_back(0);
    pe.push_back(0);
    
    // COFF File Header (20 bytes)
    pe.push_back(0x64); pe.push_back(0x86);  // Machine: AMD64
    pe.push_back(0x01); pe.push_back(0x00);  // NumberOfSections: 1
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0xF0); pe.push_back(0x00);  // SizeOfOptionalHeader: 240
    pe.push_back(0x22); pe.push_back(0x00);  // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    
    // Optional Header PE32+ (240 bytes)
    pe.push_back(0x0B); pe.push_back(0x02);  // PE32+ magic
    pe.push_back(0x0E); pe.push_back(0x00);  // LinkerVersion
    // SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData
    for (int i = 0; i < 12; ++i) pe.push_back(0x00);
    // AddressOfEntryPoint
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    // BaseOfCode
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    // ImageBase (64-bit)
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x40);
    pe.push_back(0x01); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // SectionAlignment
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    // FileAlignment
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    // OS Version
    pe.push_back(0x06); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    // Image Version
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    // Subsystem Version
    pe.push_back(0x06); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    // Win32VersionValue
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // SizeOfImage
    pe.push_back(0x00); pe.push_back(0x30); pe.push_back(0x00); pe.push_back(0x00);
    // SizeOfHeaders
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    // CheckSum
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // Subsystem
    pe.push_back(0x03); pe.push_back(0x00);  // CONSOLE
    // DllCharacteristics
    pe.push_back(0x60); pe.push_back(0x81);  // HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    // SizeOfStackReserve (64-bit)
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // SizeOfStackCommit (64-bit)
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // SizeOfHeapReserve (64-bit)
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // SizeOfHeapCommit (64-bit)
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // LoaderFlags
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    // NumberOfRvaAndSizes
    pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    
    // Data directories (16 * 8 = 128 bytes)
    for (int i = 0; i < 128; ++i) pe.push_back(0x00);
    
    // Section header (.text)
    pe.push_back('.'); pe.push_back('t'); pe.push_back('e'); pe.push_back('x');
    pe.push_back('t'); pe.push_back(0); pe.push_back(0); pe.push_back(0);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);  // VirtualSize
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);  // VirtualAddress
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);  // SizeOfRawData
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);  // PointerToRawData
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x20); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x60);
    
    // Pad to 512 bytes
    while (pe.size() < 512) {
        pe.push_back(0x00);
    }
    
    // Simple code section
    pe.push_back(0xC3);  // RET
    
    while (pe.size() < 1024) {
        pe.push_back(0x00);
    }
    
    return pe;
}

// ============================================================================
// FuzzLoop Implementation
// ============================================================================

struct FuzzLoop::Impl {
    std::filesystem::path corpusDirectory;
    std::filesystem::path crashDirectory;
    HarnessFunction harness;
    FuzzLoopConfig config;
    FuzzStatistics stats;
    MutationEngine mutationEngine;
    
    std::vector<CorpusEntry> corpus;
    std::vector<CrashInfo> crashes;
    std::set<std::string> uniqueCrashSignals;
    
    // Per-instance corpus expansion heuristic state (was incorrectly static)
    uint32_t lastAnomalyCount = 0;
    uint32_t lastValidationCount = 0;
    
    std::atomic<bool> stopRequested{false};
    std::atomic<bool> isRunning{false};
    
    std::mt19937_64 rng;
    
    Impl(const std::filesystem::path& corpusDir,
         const std::filesystem::path& crashDir,
         HarnessFunction harnessFunc,
         const FuzzLoopConfig& cfg)
        : corpusDirectory(corpusDir)
        , crashDirectory(crashDir)
        , harness(std::move(harnessFunc))
        , config(cfg)
        , stats{}
        , mutationEngine{}
        , corpus{}
        , crashes{}
        , uniqueCrashSignals{}
        , stopRequested(false)
        , isRunning(false)
        , rng{}
    {
        // Seed RNG
        try {
            std::random_device rd;
            rng.seed((static_cast<uint64_t>(rd()) << 32) | rd());
        } catch (...) {
            rng.seed(static_cast<uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count()));
        }
    }
    
    [[nodiscard]] size_t RandomIndex(size_t maxExclusive) {
        if (maxExclusive == 0) return 0;
        std::uniform_int_distribution<size_t> dist(0, maxExclusive - 1);
        return dist(rng);
    }
};

FuzzLoop::FuzzLoop(
    const std::filesystem::path& corpusDirectory,
    const std::filesystem::path& crashDirectory,
    HarnessFunction harness,
    const FuzzLoopConfig& config) noexcept
    : m_impl(std::make_unique<Impl>(corpusDirectory, crashDirectory, std::move(harness), config))
{
}

FuzzLoop::~FuzzLoop() = default;

size_t FuzzLoop::LoadCorpus() noexcept {
    if (!m_impl) return 0;
    
    std::error_code ec;
    
    // Create directory if it doesn't exist
    if (!std::filesystem::exists(m_impl->corpusDirectory)) {
        std::filesystem::create_directories(m_impl->corpusDirectory, ec);
        if (ec) {
            std::cerr << "[FuzzLoop] Failed to create corpus directory: "
                      << m_impl->corpusDirectory << '\n';
            return 0;
        }
    }
    
    size_t loaded = 0;
    
    for (const auto& entry : std::filesystem::directory_iterator(m_impl->corpusDirectory, ec)) {
        if (ec) break;
        
        if (!entry.is_regular_file()) continue;
        
        const auto& path = entry.path();
        const auto ext = path.extension().string();
        
        // Accept .bin files
        if (ext != ".bin") continue;
        
        // Read file
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) continue;
        
        const auto size = file.tellg();
        if (size <= 0 || static_cast<size_t>(size) > m_impl->config.maxInputSize) {
            continue;
        }
        
        file.seekg(0);
        
        CorpusEntry corpusEntry;
        corpusEntry.data.resize(static_cast<size_t>(size));
        file.read(reinterpret_cast<char*>(corpusEntry.data.data()),
                  static_cast<std::streamsize>(size));
        
        if (!file) continue;
        
        corpusEntry.sourcePath = path;
        corpusEntry.fromSeed = true;
        
        m_impl->corpus.push_back(std::move(corpusEntry));
        ++loaded;
    }
    
    m_impl->stats.corpusSize = m_impl->corpus.size();
    return loaded;
}

size_t FuzzLoop::GenerateMinimalSeeds() noexcept {
    if (!m_impl) return 0;
    
    size_t generated = 0;
    
    // 1. Minimal valid PE32
    {
        CorpusEntry entry;
        entry.data = GenerateMinimalPE32Seed();
        entry.fromSeed = true;
        m_impl->corpus.push_back(std::move(entry));
        ++generated;
    }
    
    // 2. Minimal valid PE64
    {
        CorpusEntry entry;
        entry.data = GenerateMinimalPE64Seed();
        entry.fromSeed = true;
        m_impl->corpus.push_back(std::move(entry));
        ++generated;
    }
    
    // 3. Empty buffer
    {
        CorpusEntry entry;
        entry.fromSeed = true;
        m_impl->corpus.push_back(std::move(entry));
        ++generated;
    }
    
    // 4. Buffer of 0xFF bytes
    {
        CorpusEntry entry;
        entry.data.resize(256, 0xFF);
        entry.fromSeed = true;
        m_impl->corpus.push_back(std::move(entry));
        ++generated;
    }
    
    // 5-8. Random buffers of various sizes
    const size_t randomSizes[] = {64, 256, 4096, 65536};
    for (const size_t size : randomSizes) {
        CorpusEntry entry;
        entry.data.resize(size);
        for (auto& byte : entry.data) {
            byte = static_cast<uint8_t>(m_impl->rng() & 0xFF);
        }
        entry.fromSeed = true;
        m_impl->corpus.push_back(std::move(entry));
        ++generated;
    }
    
    m_impl->stats.corpusSize = m_impl->corpus.size();
    return generated;
}

bool FuzzLoop::AddToCorpus(
    std::span<const uint8_t> data,
    const std::filesystem::path& sourcePath) noexcept
{
    if (!m_impl) return false;
    
    if (data.size() > m_impl->config.maxInputSize) {
        return false;
    }
    
    CorpusEntry entry;
    entry.data.assign(data.begin(), data.end());
    entry.sourcePath = sourcePath;
    entry.fromSeed = false;
    
    m_impl->corpus.push_back(std::move(entry));
    ++m_impl->stats.corpusAdditions;
    m_impl->stats.corpusSize = m_impl->corpus.size();
    
    return true;
}

size_t FuzzLoop::GetCorpusSize() const noexcept {
    return m_impl ? m_impl->corpus.size() : 0;
}

bool FuzzLoop::Run() noexcept {
    if (!m_impl || !m_impl->harness) {
        std::cerr << "[FuzzLoop] No harness function provided\n";
        return false;
    }
    
    // Initialize
    m_impl->isRunning.store(true, std::memory_order_release);
    m_impl->stopRequested.store(false, std::memory_order_release);
    m_impl->stats.startTime = std::chrono::steady_clock::now();
    
    // Load corpus if empty
    if (m_impl->corpus.empty()) {
        const size_t loaded = LoadCorpus();
        if (m_impl->corpus.empty()) {
            std::cout << "[FuzzLoop] Corpus empty, generating minimal seeds...\n";
            (void)GenerateMinimalSeeds();
        } else {
            std::cout << "[FuzzLoop] Loaded " << loaded << " corpus entries\n";
        }
    }
    
    // Create crash directory
    std::error_code ec;
    std::filesystem::create_directories(m_impl->crashDirectory, ec);
    
    std::cout << "[FuzzLoop] Starting fuzzing loop for target: "
              << m_impl->config.targetName << '\n';
    std::cout << "[FuzzLoop] Corpus size: " << m_impl->corpus.size() << '\n';
    std::cout << "[FuzzLoop] Max iterations: "
              << (m_impl->config.maxIterations ? std::to_string(m_impl->config.maxIterations) : "unlimited")
              << '\n';
    
    uint64_t iteration = 0;
    auto lastReportTime = std::chrono::steady_clock::now();
    
    while (!m_impl->stopRequested.load(std::memory_order_acquire) &&
           !WasCtrlCReceived())
    {
        // Check iteration limit
        if (m_impl->config.maxIterations > 0 &&
            iteration >= m_impl->config.maxIterations) {
            break;
        }
        
        // Check duration limit
        if (m_impl->config.maxDurationSeconds > 0) {
            const auto elapsed = std::chrono::steady_clock::now() - m_impl->stats.startTime;
            const auto elapsedSec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
            if (static_cast<uint64_t>(elapsedSec) >= m_impl->config.maxDurationSeconds) {
                break;
            }
        }
        
        // Select corpus entry
        const size_t corpusIdx = m_impl->RandomIndex(m_impl->corpus.size());
        CorpusEntry& selectedEntry = m_impl->corpus[corpusIdx];
        ++selectedEntry.hitCount;
        
        // Get splice source (different entry)
        std::span<const uint8_t> spliceSource;
        if (m_impl->corpus.size() > 1) {
            size_t spliceIdx = m_impl->RandomIndex(m_impl->corpus.size());
            if (spliceIdx == corpusIdx) {
                spliceIdx = (spliceIdx + 1) % m_impl->corpus.size();
            }
            spliceSource = m_impl->corpus[spliceIdx].data;
        }
        
        // Mutate
        MutationResult mutated = m_impl->mutationEngine.MutateWithSplice(
            selectedEntry.data, spliceSource);
        
        if (!mutated.success) {
            continue;
        }
        
        // Run harness
        HarnessResult result = m_impl->harness(mutated.data);
        
        // Update statistics
        ++iteration;
        ++m_impl->stats.totalIterations;
        m_impl->stats.totalBytesProcessed += mutated.data.size();
        
        if (result.parsedOk) {
            ++m_impl->stats.parseSuccesses;
        } else {
            ++m_impl->stats.parseFailures;
        }
        
        // Handle crash
        if (result.crashed) {
            ++m_impl->stats.crashesFound;
            
            const bool isUnique = m_impl->uniqueCrashSignals.insert(result.crashSignal).second;
            if (isUnique) {
                ++m_impl->stats.uniqueCrashes;
                
                // Save crash
                (void)SaveCrash(mutated.data, result, mutated.seed);
                
                std::cout << "\n[CRASH] Found new crash: " << result.crashSignal
                          << " at iteration " << iteration << '\n';
            }
        }
        
        // Corpus expansion — use per-instance heuristic state (not static)
        if (m_impl->config.enableCorpusExpansion && !result.crashed && result.parsedOk) {
            if (result.anomalyCount != m_impl->lastAnomalyCount ||
                result.validationIssueCount != m_impl->lastValidationCount) {
                m_impl->lastAnomalyCount = result.anomalyCount;
                m_impl->lastValidationCount = result.validationIssueCount;
                
                // Cap corpus to prevent unbounded memory growth
                if (m_impl->corpus.size() < m_impl->config.maxCorpusSize) {
                    // Add to corpus with small probability to avoid explosion
                    if ((m_impl->rng() % 100) < 5) {  // 5% chance
                        (void)AddToCorpus(mutated.data);
                    }
                }
            }
        }
        
        // Progress reporting
        if (iteration % m_impl->config.reportIntervalIterations == 0) {
            const auto now = std::chrono::steady_clock::now();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastReportTime).count();
            
            if (elapsed > 0) {
                m_impl->stats.iterationsPerSecond =
                    static_cast<double>(m_impl->config.reportIntervalIterations) /
                    (static_cast<double>(elapsed) / 1000.0);
            }
            
            const auto totalElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - m_impl->stats.startTime).count();
            m_impl->stats.durationMs = static_cast<uint64_t>(totalElapsed);
            
            PrintProgress();
            lastReportTime = now;
        }
    }
    
    // Final statistics
    const auto endTime = std::chrono::steady_clock::now();
    m_impl->stats.durationMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - m_impl->stats.startTime).count());
    
    if (m_impl->stats.durationMs > 0) {
        m_impl->stats.iterationsPerSecond =
            static_cast<double>(m_impl->stats.totalIterations) /
            (static_cast<double>(m_impl->stats.durationMs) / 1000.0);
    }
    
    m_impl->isRunning.store(false, std::memory_order_release);
    
    std::cout << "\n[FuzzLoop] Fuzzing complete.\n";
    PrintProgress();
    
    // Write summary
    const auto summaryPath = m_impl->crashDirectory / "summary.json";
    (void)WriteSummaryJson(summaryPath);
    
    return !WasCtrlCReceived() && !m_impl->stopRequested.load(std::memory_order_acquire);
}

void FuzzLoop::Stop() noexcept {
    if (m_impl) {
        m_impl->stopRequested.store(true, std::memory_order_release);
    }
}

bool FuzzLoop::IsRunning() const noexcept {
    return m_impl ? m_impl->isRunning.load(std::memory_order_acquire) : false;
}

const FuzzStatistics& FuzzLoop::GetStatistics() const noexcept {
    static const FuzzStatistics empty{};
    return m_impl ? m_impl->stats : empty;
}

const std::vector<CrashInfo>& FuzzLoop::GetCrashes() const noexcept {
    static const std::vector<CrashInfo> empty;
    return m_impl ? m_impl->crashes : empty;
}

const FuzzLoopConfig& FuzzLoop::GetConfig() const noexcept {
    static const FuzzLoopConfig defaultConfig;
    return m_impl ? m_impl->config : defaultConfig;
}

void FuzzLoop::SetConfig(const FuzzLoopConfig& config) noexcept {
    if (m_impl) {
        m_impl->config = config;
    }
}

std::filesystem::path FuzzLoop::SaveCrash(
    std::span<const uint8_t> data,
    const HarnessResult& result,
    uint64_t prngSeed) noexcept
{
    if (!m_impl) return {};
    
    std::error_code ec;
    std::filesystem::create_directories(m_impl->crashDirectory, ec);
    if (ec) {
        std::cerr << "[FuzzLoop] Failed to create crash directory\n";
        return {};
    }
    
    // Generate filename
    const std::string timestamp = GetIsoTimestamp();
    std::string sanitizedSignal = result.crashSignal;
    for (char& c : sanitizedSignal) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
            c = '_';
        }
    }
    
    const std::string baseName = "crash_" + sanitizedSignal + "_" +
        std::to_string(m_impl->stats.totalIterations);
    
    const auto inputPath = m_impl->crashDirectory / (baseName + ".bin");
    const auto metadataPath = m_impl->crashDirectory / (baseName + ".json");
    
    // Write input file
    std::ofstream inputFile(inputPath, std::ios::binary | std::ios::trunc);
    if (!inputFile) {
        std::cerr << "[FuzzLoop] Failed to write crash input: " << inputPath << '\n';
        return {};
    }
    inputFile.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
    inputFile.close();
    
    // Build metadata JSON
    std::ostringstream json;
    json << "{\n"
         << "  \"signal\": \"" << EscapeJsonString(result.crashSignal) << "\",\n"
         << "  \"timestamp\": \"" << EscapeJsonString(timestamp) << "\",\n"
         << "  \"iteration\": " << m_impl->stats.totalIterations << ",\n"
         << "  \"prngSeed\": " << prngSeed << ",\n"
         << "  \"inputSize\": " << data.size() << ",\n"
         << "  \"inputPath\": \"" << EscapeJsonString(inputPath.filename().string()) << "\",\n"
         << "  \"target\": \"" << EscapeJsonString(m_impl->config.targetName) << "\",\n"
         << "  \"parsedOk\": " << (result.parsedOk ? "true" : "false") << ",\n"
         << "  \"errorMessage\": \"" << EscapeJsonString(result.errorMessage) << "\"\n"
         << "}\n";
    
    // Write metadata
    std::ofstream metadataFile(metadataPath, std::ios::binary | std::ios::trunc);
    if (!metadataFile) {
        std::cerr << "[FuzzLoop] Failed to write crash metadata: " << metadataPath << '\n';
        return inputPath;
    }
    const std::string jsonStr = json.str();
    metadataFile.write(jsonStr.data(), static_cast<std::streamsize>(jsonStr.size()));
    metadataFile.close();
    
    // Record crash info
    CrashInfo info;
    info.signal = result.crashSignal;
    info.inputPath = inputPath;
    info.metadataPath = metadataPath;
    info.iterationNumber = m_impl->stats.totalIterations;
    info.prngSeed = prngSeed;
    info.inputSize = data.size();
    info.timestamp = timestamp;
    m_impl->crashes.push_back(std::move(info));
    
    return inputPath;
}

bool FuzzLoop::WriteSummaryJson(const std::filesystem::path& path) const noexcept {
    const std::string json = BuildSummaryJson();
    
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        std::cerr << "[FuzzLoop] Failed to write summary: " << path << '\n';
        return false;
    }
    
    file.write(json.data(), static_cast<std::streamsize>(json.size()));
    return file.good();
}

std::string FuzzLoop::BuildSummaryJson() const noexcept {
    if (!m_impl) return "{}";
    
    const auto& stats = m_impl->stats;
    
    std::ostringstream json;
    json << "{\n"
         << "  \"target\": \"" << EscapeJsonString(m_impl->config.targetName) << "\",\n"
         << "  \"timestamp\": \"" << EscapeJsonString(GetIsoTimestamp()) << "\",\n"
         << "  \"statistics\": {\n"
         << "    \"totalIterations\": " << stats.totalIterations << ",\n"
         << "    \"crashesFound\": " << stats.crashesFound << ",\n"
         << "    \"uniqueCrashes\": " << stats.uniqueCrashes << ",\n"
         << "    \"corpusSize\": " << stats.corpusSize << ",\n"
         << "    \"corpusAdditions\": " << stats.corpusAdditions << ",\n"
         << "    \"totalBytesProcessed\": " << stats.totalBytesProcessed << ",\n"
         << "    \"parseSuccesses\": " << stats.parseSuccesses << ",\n"
         << "    \"parseFailures\": " << stats.parseFailures << ",\n"
         << "    \"iterationsPerSecond\": " << std::fixed << std::setprecision(2)
         << stats.iterationsPerSecond << ",\n"
         << "    \"durationMs\": " << stats.durationMs << "\n"
         << "  },\n"
         << "  \"crashes\": [\n";
    
    for (size_t i = 0; i < m_impl->crashes.size(); ++i) {
        const auto& crash = m_impl->crashes[i];
        json << "    {\n"
             << "      \"signal\": \"" << EscapeJsonString(crash.signal) << "\",\n"
             << "      \"inputPath\": \"" << EscapeJsonString(crash.inputPath.filename().string()) << "\",\n"
             << "      \"iteration\": " << crash.iterationNumber << ",\n"
             << "      \"prngSeed\": " << crash.prngSeed << ",\n"
             << "      \"inputSize\": " << crash.inputSize << ",\n"
             << "      \"timestamp\": \"" << EscapeJsonString(crash.timestamp) << "\"\n"
             << "    }";
        if (i + 1 < m_impl->crashes.size()) {
            json << ",";
        }
        json << "\n";
    }
    
    json << "  ]\n"
         << "}\n";
    
    return json.str();
}

void FuzzLoop::PrintProgress() const noexcept {
    if (!m_impl) return;
    
    const auto& stats = m_impl->stats;
    
    std::cout << "[FuzzLoop] iter=" << stats.totalIterations
              << " crashes=" << stats.uniqueCrashes
              << "/" << stats.crashesFound
              << " corpus=" << stats.corpusSize
              << " speed=" << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << "/s"
              << " parsed=" << stats.parseSuccesses
              << "/" << (stats.parseSuccesses + stats.parseFailures)
              << '\n';
}

}  // namespace ShadowStrike::Fuzzer
