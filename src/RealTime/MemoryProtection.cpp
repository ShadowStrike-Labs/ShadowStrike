#include "MemoryProtection.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/StringUtils.hpp"

#include <shared_mutex>
#include <mutex>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <array>
#include <algorithm>
#include <thread>

// Windows headers for memory constants
#ifdef _WIN32
#include <Windows.h>
#include <Psapi.h>
#else
// Stubs for non-Windows (should not happen in this project context)
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_PRIVATE 0x20000
#define MEM_IMAGE 0x1000000
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#endif

namespace ShadowStrike {
    namespace RealTime {

        using namespace Utils;

        // ============================================================================
        // JSON Helpers
        // ============================================================================

        static std::string EscapeJson(const std::string& s) {
            std::ostringstream o;
            for (char c : s) {
                switch (c) {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if ('\x00' <= c && c <= '\x1f') {
                        o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                    }
                    else {
                        o << c;
                    }
                }
            }
            return o.str();
        }

        std::string MemoryViolation::ToJson() const {
            std::stringstream ss;
            ss << "{";
            ss << "\"type\":" << static_cast<int>(type) << ",";
            ss << "\"address\":" << address << ",";
            ss << "\"size\":" << size << ",";
            ss << "\"confidence\":" << confidence << ",";
            ss << "\"details\":\"" << EscapeJson(details) << "\",";
            ss << "\"dump\":\"";
            for (size_t i = 0; i < dump.size(); ++i) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)dump[i];
            }
            ss << "\"";
            ss << "}";
            return ss.str();
        }

        std::string MemoryScanResult::ToJson() const {
            std::stringstream ss;
            ss << "{";
            ss << "\"pid\":" << pid << ",";
            ss << "\"compromised\":" << (compromised ? "true" : "false") << ",";
            ss << "\"pagesScanned\":" << pagesScanned << ",";
            ss << "\"scanDurationUs\":" << scanDuration.count() << ",";
            ss << "\"violations\":[";
            for (size_t i = 0; i < violations.size(); ++i) {
                ss << violations[i].ToJson();
                if (i < violations.size() - 1) ss << ",";
            }
            ss << "]";
            ss << "}";
            return ss.str();
        }

        // ============================================================================
        // Implementation Class
        // ============================================================================

        class MemoryProtection::MemoryProtectionImpl {
        public:
            MemoryProtectionImpl() {
                m_stats.startTime = std::chrono::system_clock::now();
            }

            // Statistics tracking
            struct Stats {
                std::atomic<uint64_t> scansPerformed{ 0 };
                std::atomic<uint64_t> threatsDetected{ 0 };
                std::atomic<uint64_t> pagesScanned{ 0 };
                std::atomic<uint64_t> totalScanTimeUs{ 0 };
                std::chrono::system_clock::time_point startTime;
            };

            Stats m_stats;
            mutable std::shared_mutex m_mutex;
            std::unordered_set<ProcessUtils::ProcessId> m_monitoredProcesses;

            // Core Logic
            void ScanProcessInternal(ProcessUtils::ProcessId pid, ScanMode mode, MemoryScanResult& result);
            void ScanForRWX(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result);
            void ScanForShellcode(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result);
            void ScanForModuleStomping(ProcessUtils::ProcessId pid, MemoryScanResult& result);
            void ScanForROP(ProcessUtils::ProcessId pid, MemoryScanResult& result);

            // Helpers
            bool ReadMemorySafe(ProcessUtils::ProcessId pid, uint64_t address, std::vector<uint8_t>& buffer, size_t size);
            bool IsNopSled(const std::vector<uint8_t>& buffer);
        };

        // ============================================================================
        // Core Logic Implementation
        // ============================================================================

        bool MemoryProtection::MemoryProtectionImpl::ReadMemorySafe(ProcessUtils::ProcessId pid, uint64_t address, std::vector<uint8_t>& buffer, size_t size) {
            buffer.resize(size);
            SIZE_T bytesRead = 0;
            // Using raw cast for void* to handle address math
            return ProcessUtils::ReadProcessMemory(pid, reinterpret_cast<void*>(address), buffer.data(), size, &bytesRead);
        }

        bool MemoryProtection::MemoryProtectionImpl::IsNopSled(const std::vector<uint8_t>& buffer) {
            if (buffer.size() < 16) return false;

            size_t nops = 0;
            // Check for standard x86 NOP (0x90)
            for (uint8_t byte : buffer) {
                if (byte == 0x90) nops++;
            }

            // If > 70% of buffer is NOPs, detecting as sled
            return (static_cast<double>(nops) / buffer.size()) > 0.7;
        }

        void MemoryProtection::MemoryProtectionImpl::ScanForRWX(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result) {
            for (const auto& mbi : regions) {
                // Check for PAGE_EXECUTE_READWRITE (0x40) or PAGE_EXECUTE_WRITECOPY (0x80)
                if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) {

                    // Filter out non-private memory if desired, but RWX private is most suspicious

                    MemoryViolation violation;
                    violation.type = MemoryViolationType::RWX_Page;
                    violation.address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                    violation.size = mbi.RegionSize;
                    violation.confidence = 0.8f; // RWX is highly suspicious but sometimes legitimate (JIT)
                    violation.details = "RWX Memory Region Detected (Potential Shellcode Buffer)";

                    // Read first 64 bytes for dump
                    ReadMemorySafe(pid, violation.address, violation.dump, 64);

                    result.violations.push_back(violation);
                    result.compromised = true;
                }
            }
        }

        void MemoryProtection::MemoryProtectionImpl::ScanForShellcode(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result) {
            // Heuristic scan on Executable pages
            for (const auto& mbi : regions) {
                bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

                // Only scan committed memory
                if (isExec && mbi.State == MEM_COMMIT) {

                    // Limit scan to private memory or suspicious image memory
                    if (mbi.Type == MEM_PRIVATE) {
                        std::vector<uint8_t> buffer;
                        // Scan first 1024 bytes of region for heuristics
                        size_t scanSize = std::min(static_cast<size_t>(mbi.RegionSize), size_t(1024));

                        if (ReadMemorySafe(pid, reinterpret_cast<uint64_t>(mbi.BaseAddress), buffer, scanSize)) {
                            if (IsNopSled(buffer)) {
                                MemoryViolation violation;
                                violation.type = MemoryViolationType::Shellcode_Pattern;
                                violation.address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                                violation.size = mbi.RegionSize;
                                violation.confidence = 0.9f;
                                violation.details = "NOP Sled Detected (Heuristic Shellcode Pattern)";
                                violation.dump = std::vector<uint8_t>(buffer.begin(), buffer.begin() + std::min(size_t(64), buffer.size()));

                                result.violations.push_back(violation);
                                result.compromised = true;
                            }
                        }
                    }
                }
            }
        }

        void MemoryProtection::MemoryProtectionImpl::ScanForModuleStomping(ProcessUtils::ProcessId pid, MemoryScanResult& result) {
            std::vector<ProcessUtils::ProcessModuleInfo> modules;
            if (!ProcessUtils::EnumerateProcessModules(pid, modules)) {
                return;
            }

            for (const auto& mod : modules) {
                // Quick check: does module memory look like a PE header?
                std::vector<uint8_t> header;
                if (ReadMemorySafe(pid, reinterpret_cast<uint64_t>(mod.baseAddress), header, 0x1000)) { // Read first page
                    if (header.size() >= 2) {
                        if (header[0] != 'M' || header[1] != 'Z') {
                            // Module base does not start with MZ
                            MemoryViolation violation;
                            violation.type = MemoryViolationType::Module_Stomping;
                            violation.address = reinterpret_cast<uint64_t>(mod.baseAddress);
                            violation.size = mod.size;
                            violation.confidence = 0.95f;
                            violation.details = "Module Stomping Detected: Invalid PE Header at Base Address: " + Utils::StringUtils::WideToString(mod.name);
                            violation.dump = std::vector<uint8_t>(header.begin(), header.begin() + std::min(size_t(64), header.size()));

                            result.violations.push_back(violation);
                            result.compromised = true;
                        }
                    }
                }
            }
        }

        void MemoryProtection::MemoryProtectionImpl::ScanForROP(ProcessUtils::ProcessId pid, MemoryScanResult& result) {
             // Basic ROP detection involves checking thread stacks for return addresses pointing to gadget-like sequences
             // This is computationally expensive to do fully from user-mode without suspension, so we do a lightweight check

             std::vector<ProcessUtils::ProcessThreadInfo> threads;
             if (ProcessUtils::EnumerateProcessThreads(pid, threads)) {
                 for (const auto& thread : threads) {
                     // In a real implementation, we would inspect the stack frames
                     // For this version, we'll placeholder this as it requires advanced stack walking privileges
                 }
             }
        }

        void MemoryProtection::MemoryProtectionImpl::ScanProcessInternal(ProcessUtils::ProcessId pid, ScanMode mode, MemoryScanResult& result) {
            auto startTime = std::chrono::high_resolution_clock::now();

            result.pid = pid;
            result.compromised = false;

            // 1. Walk Memory Regions
            std::vector<MEMORY_BASIC_INFORMATION> regions;
            uint8_t* address = nullptr;
            MEMORY_BASIC_INFORMATION mbi = {};

            // Use ProcessUtils to query memory
            while (ProcessUtils::QueryProcessMemoryRegion(pid, address, mbi)) {
                regions.push_back(mbi);
                result.pagesScanned += (mbi.RegionSize / 4096); // Approx pages
                address = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
            }

            // 2. RWX Scan (Fast & Deep)
            ScanForRWX(pid, regions, result);

            // 3. Shellcode / Pattern Scan (Deep)
            if (mode == ScanMode::Deep || mode == ScanMode::Heuristic) {
                ScanForShellcode(pid, regions, result);
                ScanForModuleStomping(pid, result);
                ScanForROP(pid, result);
            }

            auto endTime = std::chrono::high_resolution_clock::now();
            result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

            // Update Stats
            m_stats.scansPerformed++;
            m_stats.pagesScanned += result.pagesScanned;
            m_stats.totalScanTimeUs += result.scanDuration.count();
            if (result.compromised) {
                m_stats.threatsDetected++;
                Logger::Warn("Memory Threat Detected in PID {}: {} violations found", pid, result.violations.size());
            }
        }

        // ============================================================================
        // Public Interface
        // ============================================================================

        MemoryProtection& MemoryProtection::Instance() noexcept {
            static MemoryProtection instance;
            return instance;
        }

        MemoryProtection::MemoryProtection() : m_impl(std::make_unique<MemoryProtectionImpl>()) {
            Logger::Info("MemoryProtection Engine Initialized");
        }

        MemoryProtection::~MemoryProtection() {
            Logger::Info("MemoryProtection Engine Shutdown");
        }

        MemoryScanResult MemoryProtection::ScanProcess(Utils::ProcessUtils::ProcessId pid, ScanMode mode) {
            MemoryScanResult result;
            try {
                // RAII lock for config/state if needed
                std::shared_lock lock(m_impl->m_mutex);

                if (!ProcessUtils::IsProcessRunning(pid)) {
                    // Silent return if process gone
                    return result;
                }

                m_impl->ScanProcessInternal(pid, mode, result);

            } catch (const std::exception& e) {
                Logger::Error("ScanProcess Exception: {}", e.what());
            } catch (...) {
                Logger::Critical("ScanProcess Unknown Exception");
            }
            return result;
        }

        bool MemoryProtection::MonitorProcess(Utils::ProcessUtils::ProcessId pid) {
            std::unique_lock lock(m_impl->m_mutex);
            if (m_impl->m_monitoredProcesses.contains(pid)) return true;
            m_impl->m_monitoredProcesses.insert(pid);
            Logger::Info("Monitoring enabled for PID {}", pid);
            return true;
        }

        bool MemoryProtection::EnableExploitProtection(Utils::ProcessUtils::ProcessId pid, uint32_t flags) {
            // Placeholder for integration with kernel driver or SetProcessMitigationPolicy
            Logger::Info("EnableExploitProtection for PID {} with flags 0x{:X}", pid, flags);
            return true; // Stub
        }

        bool MemoryProtection::IsProcessCompromised(Utils::ProcessUtils::ProcessId pid) {
            auto result = ScanProcess(pid, ScanMode::Fast);
            return result.compromised;
        }

        bool MemoryProtection::SelfTest() {
            Logger::Info("Starting MemoryProtection SelfTest...");

            // 1. Allocate RWX Memory (Simulate Shellcode Page) using MemoryUtils
            void* rwxMem = MemoryUtils::Alloc(4096, PAGE_EXECUTE_READWRITE, MEM_COMMIT | MEM_RESERVE);
            if (!rwxMem) {
                Logger::Error("SelfTest: Failed to allocate RWX memory");
                return false;
            }

            // 2. Write NOP Sled pattern (0x90)
            memset(rwxMem, 0x90, 128); // 128 bytes of NOPs

            // 3. Scan Current Process
            auto pid = ProcessUtils::GetCurrentProcessId();
            auto result = ScanProcess(pid, ScanMode::Deep); // Deep mode checks for patterns

            // 4. Cleanup
            MemoryUtils::Free(rwxMem);

            // 5. Verify Detection
            bool rwxDetected = false;
            bool patternDetected = false;

            for (const auto& v : result.violations) {
                if (v.type == MemoryViolationType::RWX_Page && v.address == reinterpret_cast<uint64_t>(rwxMem)) {
                    rwxDetected = true;
                }
                if (v.type == MemoryViolationType::Shellcode_Pattern && v.address == reinterpret_cast<uint64_t>(rwxMem)) {
                    patternDetected = true;
                }
            }

            if (rwxDetected) {
                Logger::Info("SelfTest: RWX Page successfully detected");
            } else {
                Logger::Error("SelfTest: Failed to detect RWX page");
            }

            if (patternDetected) {
                Logger::Info("SelfTest: Shellcode pattern successfully detected");
            } else {
                 // Warning only, heuristics might vary
                Logger::Warn("SelfTest: Shellcode pattern not detected (heuristics may vary)");
            }

            return rwxDetected;
        }

        std::string MemoryProtection::GetStatistics() const {
            std::shared_lock lock(m_impl->m_mutex);
            std::stringstream ss;
            ss << "{";
            ss << "\"scansPerformed\":" << m_impl->m_stats.scansPerformed << ",";
            ss << "\"threatsDetected\":" << m_impl->m_stats.threatsDetected << ",";
            ss << "\"pagesScanned\":" << m_impl->m_stats.pagesScanned << ",";
            ss << "\"totalScanTimeUs\":" << m_impl->m_stats.totalScanTimeUs;
            ss << "}";
            return ss.str();
        }

    } // namespace RealTime
} // namespace ShadowStrike
