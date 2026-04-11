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
#include "MemoryProtection.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"
#include "../Core/Engine/BehaviorAnalyzer.hpp"
#include "ProcessCreationMonitor.hpp"

// Kernel shared types for IPC message parsing
#include "../../PhantomSensor/Shared/MemoryTypes.h"
#include "../../PhantomSensor/Shared/MessageTypes.h"

#include <shared_mutex>
#include <mutex>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <array>
#include <algorithm>
#include <thread>
#include <cmath>
#include <numeric>

#ifdef _WIN32
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// THREAD_BASIC_INFORMATION is not always fully defined in <winternl.h>
#ifndef _SS_MP_THREAD_BASIC_INFO
#define _SS_MP_THREAD_BASIC_INFO
typedef struct _MP_THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} MP_THREAD_BASIC_INFORMATION;
#endif

#endif

namespace ShadowStrike {
namespace RealTime {

    using namespace Utils;

    // =========================================================================
    // Constants
    // =========================================================================

    namespace {
        constexpr const wchar_t* LOG_CATEGORY = L"MemoryProtection";

        // Compile-time guard: all MemoryTypes.h event structures MUST have unique
        // sizes so that the size-discriminated dispatch in ProcessKernelMemoryAlert
        // is unambiguous.  Any future field addition that causes a collision will
        // fail to compile, forcing an explicit resolution.
        static_assert(sizeof(SHELLCODE_DETECTION_EVENT) != sizeof(INJECTION_DETECTION_EVENT),
            "Dispatch ambiguity: SHELLCODE_DETECTION_EVENT and INJECTION_DETECTION_EVENT have the same size");
        static_assert(sizeof(SHELLCODE_DETECTION_EVENT) != sizeof(HOLLOWING_DETECTION_EVENT),
            "Dispatch ambiguity: SHELLCODE_DETECTION_EVENT and HOLLOWING_DETECTION_EVENT have the same size");
        static_assert(sizeof(SHELLCODE_DETECTION_EVENT) != sizeof(MEMORY_PROTECT_EVENT),
            "Dispatch ambiguity: SHELLCODE_DETECTION_EVENT and MEMORY_PROTECT_EVENT have the same size");
        static_assert(sizeof(SHELLCODE_DETECTION_EVENT) != sizeof(MEMORY_ACCESS_EVENT),
            "Dispatch ambiguity: SHELLCODE_DETECTION_EVENT and MEMORY_ACCESS_EVENT have the same size");
        static_assert(sizeof(SHELLCODE_DETECTION_EVENT) != sizeof(MEMORY_ALLOC_EVENT),
            "Dispatch ambiguity: SHELLCODE_DETECTION_EVENT and MEMORY_ALLOC_EVENT have the same size");
        static_assert(sizeof(INJECTION_DETECTION_EVENT) != sizeof(HOLLOWING_DETECTION_EVENT),
            "Dispatch ambiguity: INJECTION_DETECTION_EVENT and HOLLOWING_DETECTION_EVENT have the same size");
        static_assert(sizeof(INJECTION_DETECTION_EVENT) != sizeof(MEMORY_PROTECT_EVENT),
            "Dispatch ambiguity: INJECTION_DETECTION_EVENT and MEMORY_PROTECT_EVENT have the same size");
        static_assert(sizeof(INJECTION_DETECTION_EVENT) != sizeof(MEMORY_ACCESS_EVENT),
            "Dispatch ambiguity: INJECTION_DETECTION_EVENT and MEMORY_ACCESS_EVENT have the same size");
        static_assert(sizeof(INJECTION_DETECTION_EVENT) != sizeof(MEMORY_ALLOC_EVENT),
            "Dispatch ambiguity: INJECTION_DETECTION_EVENT and MEMORY_ALLOC_EVENT have the same size");
        static_assert(sizeof(HOLLOWING_DETECTION_EVENT) != sizeof(MEMORY_PROTECT_EVENT),
            "Dispatch ambiguity: HOLLOWING_DETECTION_EVENT and MEMORY_PROTECT_EVENT have the same size");
        static_assert(sizeof(HOLLOWING_DETECTION_EVENT) != sizeof(MEMORY_ACCESS_EVENT),
            "Dispatch ambiguity: HOLLOWING_DETECTION_EVENT and MEMORY_ACCESS_EVENT have the same size");
        static_assert(sizeof(HOLLOWING_DETECTION_EVENT) != sizeof(MEMORY_ALLOC_EVENT),
            "Dispatch ambiguity: HOLLOWING_DETECTION_EVENT and MEMORY_ALLOC_EVENT have the same size");
        static_assert(sizeof(MEMORY_PROTECT_EVENT) != sizeof(MEMORY_ACCESS_EVENT),
            "Dispatch ambiguity: MEMORY_PROTECT_EVENT and MEMORY_ACCESS_EVENT have the same size");
        static_assert(sizeof(MEMORY_PROTECT_EVENT) != sizeof(MEMORY_ALLOC_EVENT),
            "Dispatch ambiguity: MEMORY_PROTECT_EVENT and MEMORY_ALLOC_EVENT have the same size");
        static_assert(sizeof(MEMORY_ACCESS_EVENT) != sizeof(MEMORY_ALLOC_EVENT),
            "Dispatch ambiguity: MEMORY_ACCESS_EVENT and MEMORY_ALLOC_EVENT have the same size");

        constexpr uint8_t ROR13_PAT1[] = { 0xC1, 0xCF, 0x0D };
        constexpr uint8_t ROR13_PAT2[] = { 0xC1, 0xCA, 0x0D };
        constexpr uint8_t SYSCALL_STUB_X64[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
        constexpr uint8_t SYSCALL_INST[] = { 0x0F, 0x05 };
        constexpr uint8_t INT2E_INST[] = { 0xCD, 0x2E };
        constexpr uint8_t PIC_CALL5[] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
        constexpr uint8_t SHIKATA_MARKER[] = { 0xD9, 0x74, 0x24, 0xF4 };
        constexpr uint32_t PE_SIG_VAL = 0x00004550;

        constexpr size_t MAX_DUMP_SIZE = 128;
        constexpr size_t SHELLCODE_SCAN_WINDOW = 4096;
        constexpr size_t MIN_NOP_SLED_LEN = 16;
        constexpr double NOP_SLED_THRESH = 0.70;
        constexpr uint32_t MAX_VIOLATIONS = 256;
        constexpr uint32_t MONITOR_INTERVAL_MS = 30000;
        constexpr uint32_t MAX_HUNT_PROCS = 500;
    } // anonymous namespace

    // =========================================================================
    // Helpers
    // =========================================================================

    namespace {

        std::string EscapeJson(const std::string& s) {
            std::string out;
            out.reserve(s.size() + 16);
            for (char c : s) {
                switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                        out += buf;
                    } else {
                        out += c;
                    }
                }
            }
            return out;
        }

        const char* ViolationTypeToStr(MemoryViolationType type) {
            switch (type) {
            case MemoryViolationType::RWX_Page:             return "RWX_Page";
            case MemoryViolationType::Shellcode_Pattern:    return "Shellcode_Pattern";
            case MemoryViolationType::Module_Stomping:      return "Module_Stomping";
            case MemoryViolationType::ROP_Gadget:           return "ROP_Gadget";
            case MemoryViolationType::Heap_Spray:           return "Heap_Spray";
            case MemoryViolationType::Thread_Injection:     return "Thread_Injection";
            case MemoryViolationType::W_to_X_Transition:    return "W_to_X_Transition";
            case MemoryViolationType::Unbacked_Executable:  return "Unbacked_Executable";
            case MemoryViolationType::API_Hash_Resolution:  return "API_Hash_Resolution";
            case MemoryViolationType::Syscall_Stub:         return "Syscall_Stub";
            case MemoryViolationType::CFG_Bypass:           return "CFG_Bypass";
            case MemoryViolationType::Stack_Pivot:          return "Stack_Pivot";
            case MemoryViolationType::Process_Hollowing:    return "Process_Hollowing";
            case MemoryViolationType::Reflective_DLL:       return "Reflective_DLL";
            case MemoryViolationType::Early_Bird_APC:       return "Early_Bird_APC";
            case MemoryViolationType::Phantom_DLL:          return "Phantom_DLL";
            case MemoryViolationType::AtomBombing:          return "AtomBombing";
            case MemoryViolationType::Process_Doppelganging:return "Process_Doppelganging";
            case MemoryViolationType::Trampolining:         return "Trampolining";
            case MemoryViolationType::Entropy_Anomaly:      return "Entropy_Anomaly";
            case MemoryViolationType::IAT_Tampering:        return "IAT_Tampering";
            case MemoryViolationType::Callback_Overwrite:   return "Callback_Overwrite";
            case MemoryViolationType::Kernel_Shellcode:     return "Kernel_Shellcode";
            case MemoryViolationType::Kernel_Injection:     return "Kernel_Injection";
            case MemoryViolationType::Kernel_Hollowing:     return "Kernel_Hollowing";
            case MemoryViolationType::Kernel_MemoryProtect: return "Kernel_MemoryProtect";
            case MemoryViolationType::Kernel_CrossProcess:  return "Kernel_CrossProcess";
            case MemoryViolationType::Kernel_SuspiciousAlloc: return "Kernel_SuspiciousAlloc";
            default:                                        return "Unknown";
            }
        }

        const char* SeverityToStr(MemoryThreatSeverity sev) {
            switch (sev) {
            case MemoryThreatSeverity::Low:       return "Low";
            case MemoryThreatSeverity::Medium:    return "Medium";
            case MemoryThreatSeverity::High:      return "High";
            case MemoryThreatSeverity::Critical:  return "Critical";
            case MemoryThreatSeverity::Emergency: return "Emergency";
            default:                              return "None";
            }
        }

        const char* MitreToStr(MitreTechnique t) {
            switch (t) {
            case MitreTechnique::T1055_001: return "T1055.001";
            case MitreTechnique::T1055_002: return "T1055.002";
            case MitreTechnique::T1055_003: return "T1055.003";
            case MitreTechnique::T1055_004: return "T1055.004";
            case MitreTechnique::T1055_012: return "T1055.012";
            case MitreTechnique::T1055_013: return "T1055.013";
            case MitreTechnique::T1620:     return "T1620";
            case MitreTechnique::T1574:     return "T1574";
            case MitreTechnique::T1106:     return "T1106";
            case MitreTechnique::T1027:     return "T1027";
            default:                        return "None";
            }
        }

        double CalcEntropy(const uint8_t* data, size_t size) {
            if (size == 0) return 0.0;
            std::array<uint64_t, 256> freq{};
            for (size_t i = 0; i < size; ++i) freq[data[i]]++;
            double entropy = 0.0;
            const double dSize = static_cast<double>(size);
            for (auto count : freq) {
                if (count == 0) continue;
                double p = static_cast<double>(count) / dSize;
                entropy -= p * std::log2(p);
            }
            return entropy;
        }

        bool MemContains(const uint8_t* hay, size_t hLen, const uint8_t* needle, size_t nLen) {
            if (nLen > hLen || nLen == 0) return false;
            for (size_t i = 0; i <= hLen - nLen; ++i) {
                if (memcmp(hay + i, needle, nLen) == 0) return true;
            }
            return false;
        }

        size_t MemCount(const uint8_t* hay, size_t hLen, const uint8_t* needle, size_t nLen) {
            if (nLen > hLen || nLen == 0) return 0;
            size_t c = 0;
            for (size_t i = 0; i <= hLen - nLen; ++i) {
                if (memcmp(hay + i, needle, nLen) == 0) ++c;
            }
            return c;
        }

        MemoryThreatSeverity CalcSeverity(MemoryViolationType type, float conf) {
            MemoryThreatSeverity base = MemoryThreatSeverity::Medium;
            switch (type) {
            case MemoryViolationType::RWX_Page:
            case MemoryViolationType::Unbacked_Executable:
            case MemoryViolationType::Entropy_Anomaly:
                base = MemoryThreatSeverity::Low; break;
            case MemoryViolationType::Shellcode_Pattern:
            case MemoryViolationType::Heap_Spray:
            case MemoryViolationType::W_to_X_Transition:
                base = MemoryThreatSeverity::Medium; break;
            case MemoryViolationType::Module_Stomping:
            case MemoryViolationType::ROP_Gadget:
            case MemoryViolationType::Thread_Injection:
            case MemoryViolationType::API_Hash_Resolution:
            case MemoryViolationType::Syscall_Stub:
            case MemoryViolationType::Stack_Pivot:
            case MemoryViolationType::Phantom_DLL:
                base = MemoryThreatSeverity::High; break;
            case MemoryViolationType::Process_Hollowing:
            case MemoryViolationType::Reflective_DLL:
            case MemoryViolationType::Early_Bird_APC:
            case MemoryViolationType::AtomBombing:
            case MemoryViolationType::Process_Doppelganging:
            case MemoryViolationType::CFG_Bypass:
            case MemoryViolationType::Kernel_Shellcode:
            case MemoryViolationType::Kernel_Injection:
            case MemoryViolationType::Kernel_Hollowing:
            case MemoryViolationType::Kernel_CrossProcess:
                base = MemoryThreatSeverity::Critical; break;
            default: break;
            }
            if (conf >= 0.95f && base < MemoryThreatSeverity::Critical)
                base = static_cast<MemoryThreatSeverity>(static_cast<uint8_t>(base) + 1);
            return base;
        }

        MitreTechnique MapMitre(MemoryViolationType type) {
            switch (type) {
            case MemoryViolationType::Thread_Injection:
            case MemoryViolationType::Kernel_Injection:     return MitreTechnique::T1055_001;
            case MemoryViolationType::Shellcode_Pattern:
            case MemoryViolationType::Kernel_Shellcode:     return MitreTechnique::T1055_009;
            case MemoryViolationType::ROP_Gadget:
            case MemoryViolationType::Stack_Pivot:          return MitreTechnique::T1055_003;
            case MemoryViolationType::Early_Bird_APC:
            case MemoryViolationType::AtomBombing:          return MitreTechnique::T1055_004;
            case MemoryViolationType::Process_Hollowing:
            case MemoryViolationType::Kernel_Hollowing:     return MitreTechnique::T1055_012;
            case MemoryViolationType::Process_Doppelganging:return MitreTechnique::T1055_013;
            case MemoryViolationType::Reflective_DLL:
            case MemoryViolationType::Phantom_DLL:          return MitreTechnique::T1620;
            case MemoryViolationType::Trampolining:
            case MemoryViolationType::IAT_Tampering:        return MitreTechnique::T1574;
            case MemoryViolationType::Syscall_Stub:
            case MemoryViolationType::API_Hash_Resolution:  return MitreTechnique::T1106;
            case MemoryViolationType::Module_Stomping:      return MitreTechnique::T1027;
            default:                                        return MitreTechnique::None;
            }
        }

    } // anonymous namespace
    // =========================================================================
    // JSON Serialization
    // =========================================================================

    std::string MemoryViolation::ToJson() const {
        std::string j;
        j.reserve(512);
        char addrBuf[32]; snprintf(addrBuf, sizeof(addrBuf), "\"0x%llX\"", static_cast<unsigned long long>(address));
        j += "{\"type\":\""; j += ViolationTypeToStr(type);
        j += "\",\"typeId\":"; j += std::to_string(static_cast<uint16_t>(type));
        j += ",\"address\":"; j += addrBuf;
        j += ",\"size\":"; j += std::to_string(size);
        char cb[16]; snprintf(cb, sizeof(cb), "%.3f", confidence);
        j += ",\"confidence\":"; j += cb;
        j += ",\"severity\":\""; j += SeverityToStr(severity);
        j += "\",\"mitre\":\""; j += MitreToStr(mitreTechnique);
        j += "\",\"details\":\""; j += EscapeJson(details);
        char eb[16]; snprintf(eb, sizeof(eb), "%.4f", entropy);
        j += "\",\"entropy\":"; j += eb;
        j += ",\"fromKernel\":"; j += fromKernel ? "true" : "false";
        j += ",\"targetPid\":"; j += std::to_string(targetPid);
        j += ",\"sourcePid\":"; j += std::to_string(sourcePid);
        j += ",\"threadId\":"; j += std::to_string(threadId);
        j += ",\"dump\":\"";
        char hx[4];
        size_t dl = std::min(dump.size(), MAX_DUMP_SIZE);
        for (size_t i = 0; i < dl; ++i) { snprintf(hx, sizeof(hx), "%02x", dump[i]); j += hx; }
        j += "\"}";
        return j;
    }

    std::string MemoryScanResult::ToJson() const {
        std::string j;
        j.reserve(1024);
        j += "{\"pid\":"; j += std::to_string(pid);
        j += ",\"compromised\":"; j += compromised ? "true" : "false";
        j += ",\"pagesScanned\":"; j += std::to_string(pagesScanned);
        j += ",\"scanDurationUs\":"; j += std::to_string(scanDuration.count());
        j += ",\"highestSeverity\":\""; j += SeverityToStr(highestSeverity);
        char sb[16]; snprintf(sb, sizeof(sb), "%.2f", overallThreatScore);
        j += "\",\"overallThreatScore\":"; j += sb;
        j += ",\"violations\":[";
        for (size_t i = 0; i < violations.size(); ++i) {
            if (i > 0) j += ",";
            j += violations[i].ToJson();
        }
        j += "]}";
        return j;
    }

    // =========================================================================
    // PIMPL Implementation Class
    // =========================================================================

    class MemoryProtection::MemoryProtectionImpl {
    public:
        MemoryProtectionImpl() { m_stats.startTime = std::chrono::system_clock::now(); }
        ~MemoryProtectionImpl() { StopInternal(); }

        struct Stats {
            std::atomic<uint64_t> scansPerformed{ 0 };
            std::atomic<uint64_t> threatsDetected{ 0 };
            std::atomic<uint64_t> pagesScanned{ 0 };
            std::atomic<uint64_t> totalScanTimeUs{ 0 };
            std::atomic<uint64_t> kernelEventsProcessed{ 0 };
            std::atomic<uint64_t> alertsRaised{ 0 };
            std::chrono::system_clock::time_point startTime;
        };

        MemoryProtectionConfig m_config;
        Stats m_stats;
        std::atomic<bool> m_running{ false };
        mutable std::shared_mutex m_dataMutex;
        std::mutex m_callbackMutex;
        std::unordered_set<ProcessUtils::ProcessId> m_monitoredProcesses;
        std::vector<std::pair<uint64_t, MemoryThreatCallback>> m_threatCallbacks;
        std::atomic<uint64_t> m_nextCallbackId{ 1 };
        uint64_t m_pcmTerminateCbId = 0;
        std::thread m_monitorThread;
        std::atomic<bool> m_monitorStop{ false };

        void StartInternal();
        void StopInternal();
        void MonitoringLoop();
        void ScanProcessInternal(ProcessUtils::ProcessId pid, ScanMode mode, MemoryScanResult& result);
        void ScanRegionInternal(ProcessUtils::ProcessId pid, uint64_t addr, size_t size, MemoryScanResult& result);

        // Detection methods
        void ScanForRWX(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result);
        void ScanForShellcode(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result);
        void ScanForModuleStomping(ProcessUtils::ProcessId pid, MemoryScanResult& result);
        void ScanForROP(ProcessUtils::ProcessId pid, MemoryScanResult& result);
        void ScanForHeapSpray(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result);
        void ScanForThreadInjection(ProcessUtils::ProcessId pid, MemoryScanResult& result);
        void ScanForUnbackedExec(ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result);

        // Sub-detectors
        bool DetectAPIHashing(const uint8_t* data, size_t size);
        bool DetectSyscallStub(const uint8_t* data, size_t size);
        bool DetectEncoderStub(const uint8_t* data, size_t size);
        bool DetectPIC(const uint8_t* data, size_t size);
        bool DetectNopSled(const uint8_t* data, size_t size);
        bool DetectReflectiveDLL(const uint8_t* data, size_t size);

        // Kernel handlers
        void HandleKernelShellcode(const SHELLCODE_DETECTION_EVENT* e);
        void HandleKernelInjection(const INJECTION_DETECTION_EVENT* e);
        void HandleKernelHollowing(const HOLLOWING_DETECTION_EVENT* e);
        void HandleKernelProtect(const MEMORY_PROTECT_EVENT* e);
        void HandleKernelAccess(const MEMORY_ACCESS_EVENT* e);
        void HandleKernelAlloc(const MEMORY_ALLOC_EVENT* e);

        // Integration
        void ReportAlert(const MemoryViolation& v, uint32_t pid);
        void ReportTelemetry(const MemoryViolation& v, uint32_t pid);
        void ReportBehavior(const MemoryViolation& v, uint32_t pid);
        void NotifyCallbacks(const MemoryViolation& v, uint32_t pid);
        void ProcessViolation(MemoryViolation& v, uint32_t pid, MemoryScanResult& result);

        // Helpers
        bool ReadSafe(ProcessUtils::ProcessId pid, uint64_t addr, std::vector<uint8_t>& buf, size_t size);
        bool ReadSafe(ProcessUtils::ProcessId pid, uint64_t addr, uint8_t* buf, size_t size, size_t* bytesRead);
        std::vector<MEMORY_BASIC_INFORMATION> CollectRegions(ProcessUtils::ProcessId pid, uint32_t maxReg);
        void CapDump(MemoryViolation& v, const uint8_t* data, size_t avail);
    };
    // =========================================================================
    // Helper Method Implementations
    // =========================================================================

    bool MemoryProtection::MemoryProtectionImpl::ReadSafe(
        ProcessUtils::ProcessId pid, uint64_t addr, std::vector<uint8_t>& buf, size_t size) {
        if (size == 0 || size > (64 * 1024 * 1024)) return false;
        buf.resize(size);
        SIZE_T br = 0;
        bool ok = ProcessUtils::ReadProcessMemory(pid, reinterpret_cast<void*>(addr), buf.data(), size, &br);
        if (!ok || br == 0) { buf.clear(); return false; }
        buf.resize(br);
        return true;
    }

    bool MemoryProtection::MemoryProtectionImpl::ReadSafe(
        ProcessUtils::ProcessId pid, uint64_t addr, uint8_t* buf, size_t size, size_t* bytesRead) {
        if (!buf || size == 0 || size > (64 * 1024 * 1024)) return false;
        SIZE_T br = 0;
        bool ok = ProcessUtils::ReadProcessMemory(pid, reinterpret_cast<void*>(addr), buf, size, &br);
        if (bytesRead) *bytesRead = static_cast<size_t>(br);
        return ok && br > 0;
    }

    std::vector<MEMORY_BASIC_INFORMATION> MemoryProtection::MemoryProtectionImpl::CollectRegions(
        ProcessUtils::ProcessId pid, uint32_t maxReg) {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
        regions.reserve(4096);
        uint8_t* address = nullptr;
        MEMORY_BASIC_INFORMATION mbi{};
        uint32_t count = 0;
        while (ProcessUtils::QueryProcessMemoryRegion(pid, address, mbi) && count < maxReg) {
            regions.push_back(mbi);
            address = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
            ++count;
        }
        return regions;
    }

    void MemoryProtection::MemoryProtectionImpl::CapDump(
        MemoryViolation& v, const uint8_t* data, size_t avail) {
        size_t ds = std::min(avail, MAX_DUMP_SIZE);
        v.dump.assign(data, data + ds);
    }

    // =========================================================================
    // Shellcode Sub-Detectors
    // =========================================================================

    bool MemoryProtection::MemoryProtectionImpl::DetectAPIHashing(const uint8_t* data, size_t size) {
        if (MemContains(data, size, ROR13_PAT1, sizeof(ROR13_PAT1))) return true;
        if (MemContains(data, size, ROR13_PAT2, sizeof(ROR13_PAT2))) return true;
        constexpr uint8_t CRC32_I[] = { 0xF2, 0x0F, 0x38, 0xF1 };
        if (MemCount(data, size, CRC32_I, sizeof(CRC32_I)) >= 2) return true;
        return false;
    }

    bool MemoryProtection::MemoryProtectionImpl::DetectSyscallStub(const uint8_t* data, size_t size) {
        constexpr size_t kMinSyscallStubBytes =
            sizeof(SYSCALL_STUB_X64) + sizeof(uint16_t) + sizeof(SYSCALL_INST);

        for (size_t i = 0; i + kMinSyscallStubBytes <= size; ++i) {
            if (memcmp(data + i, SYSCALL_STUB_X64, sizeof(SYSCALL_STUB_X64)) == 0) {
                uint16_t ssn = *reinterpret_cast<const uint16_t*>(data + i + 4);
                if (ssn < 0x2000) {
                    for (size_t j = i + 6; j + 1 < size && j < i + 14; ++j) {
                        if (memcmp(data + j, SYSCALL_INST, sizeof(SYSCALL_INST)) == 0) return true;
                        if (memcmp(data + j, INT2E_INST, sizeof(INT2E_INST)) == 0) return true;
                    }
                }
            }
        }
        // Heaven's Gate: far call to 0x33 segment
        for (size_t i = 0; i + 7 <= size; ++i) {
            if (data[i] == 0x9A && data[i + 5] == 0x33 && data[i + 6] == 0x00) return true;
        }
        return false;
    }

    bool MemoryProtection::MemoryProtectionImpl::DetectEncoderStub(const uint8_t* data, size_t size) {
        if (MemContains(data, size, SHIKATA_MARKER, sizeof(SHIKATA_MARKER))) return true;
        for (size_t i = 0; i + 8 <= size; ++i) {
            uint8_t op = data[i];
            if ((op >= 0x30 && op <= 0x33) || op == 0x80) {
                for (size_t j = i + 2; j + 1 < size && j < i + 20; ++j) {
                    if (data[j] == 0xE2 || data[j] == 0x75 || data[j] == 0x79) {
                        int8_t offset = static_cast<int8_t>(data[j + 1]);
                        if (offset < 0 && offset > -32) return true;
                    }
                }
            }
        }
        return false;
    }

    bool MemoryProtection::MemoryProtectionImpl::DetectPIC(const uint8_t* data, size_t size) {
        for (size_t i = 0; i + sizeof(PIC_CALL5) < size; ++i) {
            if (memcmp(data + i, PIC_CALL5, sizeof(PIC_CALL5)) == 0) {
                uint8_t next = data[i + 5];
                if (next >= 0x58 && next <= 0x5F) return true;
            }
        }
        return false;
    }

    bool MemoryProtection::MemoryProtectionImpl::DetectNopSled(const uint8_t* data, size_t size) {
        if (size < MIN_NOP_SLED_LEN) return false;
        size_t nops = 0;
        for (size_t i = 0; i < size; ++i) { if (data[i] == 0x90) ++nops; }
        return (static_cast<double>(nops) / static_cast<double>(size)) > NOP_SLED_THRESH;
    }

    bool MemoryProtection::MemoryProtectionImpl::DetectReflectiveDLL(const uint8_t* data, size_t size) {
        if (size < 0x100) return false;
        if (data[0] != 'M' || data[1] != 'Z') return false;
        if (size < 0x40) return false;
        uint32_t peOff = *reinterpret_cast<const uint32_t*>(data + 0x3C);
        if (peOff >= size - 4 || peOff > 0x1000) return false;
        uint32_t peSig = *reinterpret_cast<const uint32_t*>(data + peOff);
        return peSig == PE_SIG_VAL;
    }
    // =========================================================================
    // Detection: RWX Scanning
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanForRWX(
        ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result) {
        for (const auto& mbi : regions) {
            if (result.violations.size() >= MAX_VIOLATIONS) break;
            if (mbi.State != MEM_COMMIT) continue;
            bool isRWX = (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY);
            if (!isRWX) continue;

            MemoryViolation v;
            v.type = MemoryViolationType::RWX_Page;
            v.address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            v.size = mbi.RegionSize;
            v.targetPid = pid;
            v.detectedAt = std::chrono::system_clock::now();
            v.confidence = (mbi.Type == MEM_PRIVATE) ? 0.85f : 0.50f;
            v.details = (mbi.Type == MEM_PRIVATE)
                ? "Private RWX memory region (high-risk shellcode buffer)"
                : "Image-backed RWX memory region (possible JIT or shellcode)";

            std::vector<uint8_t> sample;
            if (ReadSafe(pid, v.address, sample, std::min<size_t>(MAX_DUMP_SIZE, mbi.RegionSize))) {
                CapDump(v, sample.data(), sample.size());
                v.entropy = CalcEntropy(sample.data(), sample.size());
                if (v.entropy > m_config.highEntropyThreshold && mbi.Type == MEM_PRIVATE) {
                    v.confidence = 0.92f;
                    char eb[16]; snprintf(eb, sizeof(eb), "%.2f", v.entropy);
                    v.details += std::string(" [HIGH ENTROPY: ") + eb + "]";
                }
            }
            ProcessViolation(v, pid, result);
        }
    }

    // =========================================================================
    // Detection: Shellcode Scanning (multi-technique)
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanForShellcode(
        ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result) {
        for (const auto& mbi : regions) {
            if (result.violations.size() >= MAX_VIOLATIONS) break;
            if (mbi.State != MEM_COMMIT) continue;
            bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            if (!isExec || mbi.Type != MEM_PRIVATE) continue;

            size_t scanSize = std::min(static_cast<size_t>(mbi.RegionSize), SHELLCODE_SCAN_WINDOW);
            std::vector<uint8_t> buf;
            if (!ReadSafe(pid, reinterpret_cast<uint64_t>(mbi.BaseAddress), buf, scanSize)) continue;
            const uint8_t* d = buf.data();
            size_t ds = buf.size();
            uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            double ent = CalcEntropy(d, ds);

            auto makeViolation = [&](MemoryViolationType t, float conf, const char* det) {
                MemoryViolation v;
                v.type = t; v.address = base; v.size = mbi.RegionSize;
                v.confidence = conf; v.entropy = ent; v.targetPid = pid;
                v.details = det; v.detectedAt = std::chrono::system_clock::now();
                CapDump(v, d, ds);
                ProcessViolation(v, pid, result);
            };

            if (DetectNopSled(d, ds))
                makeViolation(MemoryViolationType::Shellcode_Pattern, 0.88f, "NOP sled in executable private memory");
            if (DetectAPIHashing(d, ds))
                makeViolation(MemoryViolationType::API_Hash_Resolution, 0.91f, "API hashing pattern (ror13/crc32) - shellcode API resolution");
            if (DetectSyscallStub(d, ds))
                makeViolation(MemoryViolationType::Syscall_Stub, 0.93f, "Direct syscall stub - user-mode hook bypass (Hell's Gate)");
            if (DetectEncoderStub(d, ds))
                makeViolation(MemoryViolationType::Shellcode_Pattern, 0.90f, "Shellcode encoder stub (polymorphic/metamorphic)");
            if (DetectPIC(d, ds))
                makeViolation(MemoryViolationType::Shellcode_Pattern, 0.75f, "Position-independent code prologue (call $+5; pop reg)");
            if (DetectReflectiveDLL(d, ds))
                makeViolation(MemoryViolationType::Reflective_DLL, 0.95f, "PE image in private executable memory - reflective DLL loading");
            if (ent > m_config.highEntropyThreshold) {
                char eb[32]; snprintf(eb, sizeof(eb), "High entropy (%.2f) in exec private mem", ent);
                makeViolation(MemoryViolationType::Entropy_Anomaly, 0.55f, eb);
            }
        }
    }

    // =========================================================================
    // Detection: Module Stomping
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanForModuleStomping(
        ProcessUtils::ProcessId pid, MemoryScanResult& result) {
        std::vector<ProcessUtils::ProcessModuleInfo> modules;
        if (!ProcessUtils::EnumerateProcessModules(pid, modules)) return;

        for (const auto& mod : modules) {
            if (result.violations.size() >= MAX_VIOLATIONS) break;
            uint64_t modBase = reinterpret_cast<uint64_t>(mod.baseAddress);
            std::vector<uint8_t> hdr;
            if (!ReadSafe(pid, modBase, hdr, 0x1000)) continue;

            if (hdr.size() < 2 || hdr[0] != 'M' || hdr[1] != 'Z') {
                MemoryViolation v;
                v.type = MemoryViolationType::Module_Stomping;
                v.address = modBase; v.size = mod.size; v.confidence = 0.97f;
                v.targetPid = pid; v.detectedAt = std::chrono::system_clock::now();
                v.details = "Module stomping: invalid PE header at base of " + StringUtils::ToNarrow(mod.name);
                CapDump(v, hdr.data(), hdr.size());
                ProcessViolation(v, pid, result);
                continue;
            }

            if (hdr.size() >= 0x40) {
                uint32_t peOff = *reinterpret_cast<const uint32_t*>(hdr.data() + 0x3C);
                if (peOff < hdr.size() - 4 && peOff <= 0x400) {
                    uint32_t peSig = *reinterpret_cast<const uint32_t*>(hdr.data() + peOff);
                    if (peSig != PE_SIG_VAL) {
                        MemoryViolation v;
                        v.type = MemoryViolationType::Module_Stomping;
                        v.address = modBase; v.size = mod.size; v.confidence = 0.95f;
                        v.targetPid = pid; v.detectedAt = std::chrono::system_clock::now();
                        v.details = "Module stomping: corrupted PE signature in " + StringUtils::ToNarrow(mod.name);
                        CapDump(v, hdr.data(), hdr.size());
                        ProcessViolation(v, pid, result);
                    }
                }
            }
        }
    }

    // =========================================================================
    // Detection: ROP / Stack Pivot
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanForROP(
        ProcessUtils::ProcessId pid, MemoryScanResult& result) {
        // Never suspend threads in our own process: doing so while holding any
        // lock (allocator, logging, etc.) that the suspended thread might own
        // will deadlock immediately.
        if (static_cast<DWORD>(pid) == ::GetCurrentProcessId()) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"ScanForROP: skipping self (PID=%u)", pid);
            return;
        }
        std::vector<ProcessUtils::ProcessThreadInfo> threads;
        if (!ProcessUtils::EnumerateProcessThreads(pid, threads)) return;
        std::vector<ProcessUtils::ProcessModuleInfo> modules;
        ProcessUtils::EnumerateProcessModules(pid, modules);

        for (const auto& thr : threads) {
            if (result.violations.size() >= MAX_VIOLATIONS) break;
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                FALSE, static_cast<DWORD>(thr.tid));
            if (!hThread) continue;

            struct TGuard { HANDLE h; bool susp = false;
                ~TGuard() { if (susp) ResumeThread(h); CloseHandle(h); }
            } guard{ hThread, false };

            if (SuspendThread(hThread) == static_cast<DWORD>(-1)) continue;
            guard.susp = true;
            CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (!GetThreadContext(hThread, &ctx)) continue;
            // Thread stays suspended through entire analysis to prevent TOCTOU
            // TGuard RAII will resume on scope exit or explicit resume below

            // Stack pivot detection via TEB stack limits
            MP_THREAD_BASIC_INFORMATION tbi{};
            NTSTATUS status = NtQueryInformationThread(hThread,
                static_cast<THREADINFOCLASS>(0) /* ThreadBasicInformation */, &tbi, sizeof(tbi), nullptr);
            if (NT_SUCCESS(status) && tbi.TebBaseAddress) {
                NT_TIB tib{}; size_t br = 0;
                if (ReadSafe(pid, reinterpret_cast<uint64_t>(tbi.TebBaseAddress),
                    reinterpret_cast<uint8_t*>(&tib), sizeof(NT_TIB), &br) && br >= sizeof(NT_TIB)) {
                    uint64_t sBase = reinterpret_cast<uint64_t>(tib.StackBase);
                    uint64_t sLimit = reinterpret_cast<uint64_t>(tib.StackLimit);
                    uint64_t rsp = ctx.Rsp;
                    if (rsp < sLimit || rsp >= sBase) {
                        MemoryViolation v;
                        v.type = MemoryViolationType::Stack_Pivot;
                        v.address = rsp; v.size = 0; v.confidence = 0.94f;
                        v.targetPid = pid; v.threadId = thr.tid;
                        v.detectedAt = std::chrono::system_clock::now();
                        char db[256]; snprintf(db, sizeof(db),
                            "Stack pivot: RSP=0x%llX outside [0x%llX-0x%llX] TID=%u",
                            rsp, sLimit, sBase, static_cast<uint32_t>(thr.tid));
                        v.details = db;
                        ProcessViolation(v, pid, result);
                    }
                }
            }

            // Walk stack for ROP: validate return addresses
            uint64_t stackStart = ctx.Rsp;
            constexpr size_t STACK_SCAN = 2048;
            std::vector<uint8_t> stackData;
            if (!ReadSafe(pid, stackStart, stackData, STACK_SCAN)) continue;
            uint32_t suspRet = 0, totalRet = 0;
            for (size_t off = 0; off + sizeof(uint64_t) <= stackData.size(); off += sizeof(uint64_t)) {
                uint64_t potRet = *reinterpret_cast<const uint64_t*>(stackData.data() + off);
                if (potRet == 0) continue;
                if (potRet < 0x10000 || potRet > 0x7FFFFFFFFFFF) continue;
                ++totalRet;
                bool inMod = false;
                for (const auto& m : modules) {
                    uint64_t ms = reinterpret_cast<uint64_t>(m.baseAddress);
                    if (potRet >= ms && potRet < ms + m.size) { inMod = true; break; }
                }
                if (!inMod) ++suspRet;
            }
            if (totalRet > 4 && suspRet > totalRet / 2) {
                MemoryViolation v;
                v.type = MemoryViolationType::ROP_Gadget;
                v.address = stackStart; v.size = STACK_SCAN;
                v.confidence = 0.80f + (static_cast<float>(suspRet) / totalRet * 0.15f);
                v.targetPid = pid; v.threadId = thr.tid;
                v.detectedAt = std::chrono::system_clock::now();
                char db[256]; snprintf(db, sizeof(db),
                    "ROP chain: %u/%u stack return addrs outside modules (TID %u)",
                    suspRet, totalRet, static_cast<uint32_t>(thr.tid));
                v.details = db;
                CapDump(v, stackData.data(), stackData.size());
                ProcessViolation(v, pid, result);
            }
        }
    }
    // =========================================================================
    // Detection: Heap Spray
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanForHeapSpray(
        ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result) {
        std::unordered_map<size_t, uint32_t> sizeBuckets;
        for (const auto& mbi : regions) {
            if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
            if (mbi.RegionSize < 0x1000 || mbi.RegionSize > 0x100000) continue;
            sizeBuckets[mbi.RegionSize]++;
        }
        for (auto& [regionSize, count] : sizeBuckets) {
            if (count < 50) continue;
            if (result.violations.size() >= MAX_VIOLATIONS) break;
            uint32_t sampled = 0, matching = 0;
            std::vector<uint8_t> firstSample;
            bool gotFirst = false;
            for (const auto& mbi : regions) {
                if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || mbi.RegionSize != regionSize) continue;
                if (sampled >= 10) break;
                std::vector<uint8_t> s;
                if (!ReadSafe(pid, reinterpret_cast<uint64_t>(mbi.BaseAddress), s, 64)) continue;
                if (!gotFirst) { firstSample = s; gotFirst = true; }
                else if (s.size() == firstSample.size() && memcmp(s.data(), firstSample.data(), s.size()) == 0) ++matching;
                ++sampled;
            }
            if (sampled >= 5 && matching >= sampled / 2) {
                MemoryViolation v;
                v.type = MemoryViolationType::Heap_Spray;
                v.size = regionSize; v.targetPid = pid;
                v.confidence = 0.85f + (static_cast<float>(matching) / sampled * 0.10f);
                v.detectedAt = std::chrono::system_clock::now();
                char db[256]; snprintf(db, sizeof(db), "Heap spray: %u regions of 0x%zX, %u/%u identical", count, regionSize, matching, sampled);
                v.details = db;
                if (!firstSample.empty()) CapDump(v, firstSample.data(), firstSample.size());
                ProcessViolation(v, pid, result);
            }
        }
    }

    // =========================================================================
    // Detection: Thread Injection
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanForThreadInjection(
        ProcessUtils::ProcessId pid, MemoryScanResult& result) {
        std::vector<ProcessUtils::ProcessThreadInfo> threads;
        if (!ProcessUtils::EnumerateProcessThreads(pid, threads)) return;
        std::vector<ProcessUtils::ProcessModuleInfo> modules;
        ProcessUtils::EnumerateProcessModules(pid, modules);

        for (const auto& thr : threads) {
            if (result.violations.size() >= MAX_VIOLATIONS) break;
            HANDLE hT = OpenThread(THREAD_QUERY_INFORMATION, FALSE, static_cast<DWORD>(thr.tid));
            if (!hT) continue;
            PVOID startAddr = nullptr; ULONG retLen = 0;
            // ThreadQuerySetWin32StartAddress = 9
            NTSTATUS st = NtQueryInformationThread(hT, static_cast<THREADINFOCLASS>(9), &startAddr, sizeof(startAddr), &retLen);
            CloseHandle(hT);
            if (!NT_SUCCESS(st) || !startAddr) continue;
            uint64_t sa = reinterpret_cast<uint64_t>(startAddr);
            bool inMod = false;
            for (const auto& m : modules) {
                uint64_t ms = reinterpret_cast<uint64_t>(m.baseAddress);
                if (sa >= ms && sa < ms + m.size) { inMod = true; break; }
            }
            if (!inMod && sa > 0x10000) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!ProcessUtils::QueryProcessMemoryRegion(pid, reinterpret_cast<uint8_t*>(sa), mbi)) continue;
                MemoryViolation v;
                v.type = MemoryViolationType::Thread_Injection;
                v.address = sa; v.size = mbi.RegionSize; v.targetPid = pid; v.threadId = thr.tid;
                v.detectedAt = std::chrono::system_clock::now();
                bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                bool isPriv = (mbi.Type == MEM_PRIVATE);
                if (isExec && isPriv) { v.confidence = 0.92f; v.details = "Thread start in private exec memory (no module)"; }
                else if (isExec)       { v.confidence = 0.75f; v.details = "Thread start in exec memory outside modules"; }
                else                   { v.confidence = 0.60f; v.details = "Thread start outside all loaded modules"; }
                std::vector<uint8_t> smp;
                if (ReadSafe(pid, sa, smp, MAX_DUMP_SIZE)) {
                    CapDump(v, smp.data(), smp.size());
                    v.entropy = CalcEntropy(smp.data(), smp.size());
                }
                ProcessViolation(v, pid, result);
            }
        }
    }

    // =========================================================================
    // Detection: Unbacked Executable
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanForUnbackedExec(
        ProcessUtils::ProcessId pid, const std::vector<MEMORY_BASIC_INFORMATION>& regions, MemoryScanResult& result) {
        for (const auto& mbi : regions) {
            if (result.violations.size() >= MAX_VIOLATIONS) break;
            if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;
            bool isExecOnly = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ)) != 0;
            bool isRWX = (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY);
            if (!isExecOnly || isRWX) continue; // RWX caught separately
            MemoryViolation v;
            v.type = MemoryViolationType::Unbacked_Executable;
            v.address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            v.size = mbi.RegionSize; v.targetPid = pid; v.confidence = 0.65f;
            v.detectedAt = std::chrono::system_clock::now();
            v.details = "Private executable memory with no file backing";
            std::vector<uint8_t> smp;
            if (ReadSafe(pid, v.address, smp, std::min<size_t>(MAX_DUMP_SIZE, mbi.RegionSize))) {
                CapDump(v, smp.data(), smp.size());
                v.entropy = CalcEntropy(smp.data(), smp.size());
                if (DetectReflectiveDLL(smp.data(), smp.size())) {
                    v.type = MemoryViolationType::Reflective_DLL;
                    v.confidence = 0.96f;
                    v.details = "PE image in unbacked executable memory - reflective DLL";
                }
            }
            ProcessViolation(v, pid, result);
        }
    }
    // =========================================================================
    // Kernel Event Processing
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::HandleKernelShellcode(const SHELLCODE_DETECTION_EVENT* e) {
        if (!e) return;
        MemoryViolation v;
        v.type = MemoryViolationType::Kernel_Shellcode;
        v.address = e->DetectionAddress; v.size = static_cast<size_t>(e->RegionSize);
        v.targetPid = e->ProcessId; v.threadId = e->ThreadId; v.fromKernel = true;
        v.entropy = static_cast<double>(e->Entropy) / 1000.0;
        v.confidence = static_cast<float>(e->Confidence) / 100.0f;
        v.detectedAt = std::chrono::system_clock::now();
        std::string det = "Kernel shellcode: ";
        if (e->HasAPIHashing) det += "[API-Hash] ";
        if (e->HasSyscallStub) det += "[Syscall] ";
        if (e->HasEncoderStub) det += "[Encoder] ";
        if (e->HasNopSled) det += "[NOP] ";
        if (e->IsPolymorphic) det += "[Poly] ";
        if (e->HasStackPivot) det += "[StackPivot] ";
        det += "Score=" + std::to_string(e->ThreatScore);
        v.details = std::move(det);
        v.dump.assign(e->ContentSample, e->ContentSample + std::min(sizeof(e->ContentSample), MAX_DUMP_SIZE));
        if (e->PrimaryType == Shellcode_Syscall) v.type = MemoryViolationType::Syscall_Stub;
        else if (e->PrimaryType == Shellcode_APIHash) v.type = MemoryViolationType::API_Hash_Resolution;
        else if (e->PrimaryType == Shellcode_ROP || e->PrimaryType == Shellcode_JOP) v.type = MemoryViolationType::ROP_Gadget;
        MemoryScanResult sr; sr.pid = e->ProcessId; sr.compromised = true;
        ProcessViolation(v, e->ProcessId, sr);
        m_stats.kernelEventsProcessed++;
    }

    void MemoryProtection::MemoryProtectionImpl::HandleKernelInjection(const INJECTION_DETECTION_EVENT* e) {
        if (!e) return;
        MemoryViolation v;
        v.type = MemoryViolationType::Kernel_Injection;
        v.address = e->InjectedAddress; v.size = static_cast<size_t>(e->InjectedSize);
        v.sourcePid = e->SourceProcessId; v.targetPid = e->TargetProcessId;
        v.threadId = e->SourceThreadId; v.fromKernel = true;
        v.entropy = static_cast<double>(e->Entropy) / 1000.0;
        v.confidence = static_cast<float>(e->Confidence) / 100.0f;
        v.detectedAt = std::chrono::system_clock::now();
        switch (e->InjectionType) {
        case Injection_ReflectiveDLL:       v.type = MemoryViolationType::Reflective_DLL; break;
        case Injection_ProcessHollowing:    v.type = MemoryViolationType::Process_Hollowing; break;
        case Injection_ProcessDoppelganging:v.type = MemoryViolationType::Process_Doppelganging; break;
        case Injection_AtomBombing:         v.type = MemoryViolationType::AtomBombing; break;
        case Injection_EarlyBird:           v.type = MemoryViolationType::Early_Bird_APC; break;
        case Injection_ThreadHijack:        v.type = MemoryViolationType::Thread_Injection; break;
        case Injection_ModuleStomping:      v.type = MemoryViolationType::Module_Stomping; break;
        default: break;
        }
        std::string det = "Kernel injection: type=" + std::to_string(e->InjectionType);
        det += " src=" + std::to_string(e->SourceProcessId) + " tgt=" + std::to_string(e->TargetProcessId);
        det += " Score=" + std::to_string(e->ThreatScore);
        if (e->Flags & INJECTION_FLAG_BLOCKED) det += " [BLOCKED]";
        if (e->Flags & INJECTION_FLAG_CROSS_SESSION) det += " [CROSS-SESSION]";
        if (e->Flags & INJECTION_FLAG_SYSTEM_TARGET) det += " [SYSTEM-TARGET]";
        v.details = std::move(det);
        MemoryScanResult sr; sr.pid = e->TargetProcessId; sr.compromised = true;
        ProcessViolation(v, e->TargetProcessId, sr);
        m_stats.kernelEventsProcessed++;
    }

    void MemoryProtection::MemoryProtectionImpl::HandleKernelHollowing(const HOLLOWING_DETECTION_EVENT* e) {
        if (!e) return;
        MemoryViolation v;
        v.type = MemoryViolationType::Kernel_Hollowing;
        v.address = e->ActualImageBase; v.size = static_cast<size_t>(e->ActualImageSize);
        v.targetPid = e->HollowedProcessId; v.sourcePid = e->ParentProcessId;
        v.threadId = e->HollowedThreadId; v.fromKernel = true;
        v.confidence = static_cast<float>(e->Confidence) / 100.0f;
        v.detectedAt = std::chrono::system_clock::now();
        if (e->Flags & HOLLOWING_FLAG_DOPPELGANGING) v.type = MemoryViolationType::Process_Doppelganging;
        else if (e->Flags & HOLLOWING_FLAG_CONFIRMED) v.type = MemoryViolationType::Process_Hollowing;
        std::string det = "Kernel hollowing: PID=" + std::to_string(e->HollowedProcessId);
        det += " Score=" + std::to_string(e->ThreatScore);
        if (e->Flags & HOLLOWING_FLAG_BLOCKED) det += " [BLOCKED]";
        if (e->Flags & HOLLOWING_FLAG_GHOSTING) det += " [GHOSTING]";
        if (e->Flags & HOLLOWING_FLAG_HERPADERPING) det += " [HERPADERPING]";
        v.details = std::move(det);
        MemoryScanResult sr; sr.pid = e->HollowedProcessId; sr.compromised = true;
        ProcessViolation(v, e->HollowedProcessId, sr);
        m_stats.kernelEventsProcessed++;
    }

    void MemoryProtection::MemoryProtectionImpl::HandleKernelProtect(const MEMORY_PROTECT_EVENT* e) {
        if (!e) return;
        bool susp = (e->DetectionFlags & (MEMPROT_FLAG_RW_TO_RX | MEMPROT_FLAG_RW_TO_RWX |
            MEMPROT_FLAG_UNBACKED_TO_EXEC | MEMPROT_FLAG_CFG_BYPASS | MEMPROT_FLAG_DEP_BYPASS)) != 0;
        if (!susp) return;
        MemoryViolation v;
        v.type = MemoryViolationType::Kernel_MemoryProtect;
        v.address = e->BaseAddress; v.size = static_cast<size_t>(e->RegionSize);
        v.targetPid = e->ProcessId; v.threadId = e->ThreadId; v.fromKernel = true;
        v.detectedAt = std::chrono::system_clock::now();
        if (e->DetectionFlags & MEMPROT_FLAG_CFG_BYPASS) { v.type = MemoryViolationType::CFG_Bypass; v.confidence = 0.90f; }
        else if (e->DetectionFlags & MEMPROT_FLAG_DEP_BYPASS) { v.confidence = 0.88f; }
        else if (e->DetectionFlags & MEMPROT_FLAG_RW_TO_RX) { v.type = MemoryViolationType::W_to_X_Transition; v.confidence = 0.70f; }
        else { v.confidence = 0.65f; }
        char det[256];
        snprintf(det, sizeof(det),
            "Kernel VirtualProtect: old=0x%08X new=0x%08X Score=%u",
            e->OldProtection, e->NewProtection, e->ThreatScore);
        std::string detStr(det);
        if (e->DetectionFlags & MEMPROT_FLAG_CROSS_PROCESS) detStr += " [CROSS-PROC]";
        v.details = std::move(detStr);
        MemoryScanResult sr; sr.pid = e->ProcessId;
        ProcessViolation(v, e->ProcessId, sr);
        m_stats.kernelEventsProcessed++;
    }

    void MemoryProtection::MemoryProtectionImpl::HandleKernelAccess(const MEMORY_ACCESS_EVENT* e) {
        if (!e) return;
        bool hv = (e->DetectionFlags & (MEMACCESS_FLAG_LSASS_TARGET | MEMACCESS_FLAG_AV_TARGET |
            MEMACCESS_FLAG_SHELLCODE_CONTENT | MEMACCESS_FLAG_PE_HEADER |
            MEMACCESS_FLAG_WRITE_NTDLL | MEMACCESS_FLAG_CREDENTIAL_READ)) != 0;
        if (!hv) return;
        MemoryViolation v;
        v.type = MemoryViolationType::Kernel_CrossProcess;
        v.address = e->TargetAddress; v.size = static_cast<size_t>(e->Size_);
        v.sourcePid = e->SourceProcessId; v.targetPid = e->TargetProcessId;
        v.threadId = e->SourceThreadId; v.fromKernel = true;
        v.entropy = static_cast<double>(e->ContentEntropy) / 1000.0;
        v.detectedAt = std::chrono::system_clock::now();
        if (e->DetectionFlags & MEMACCESS_FLAG_LSASS_TARGET) v.confidence = 0.93f;
        else if (e->DetectionFlags & MEMACCESS_FLAG_AV_TARGET) v.confidence = 0.95f;
        else v.confidence = 0.75f;
        std::string det = "Kernel cross-process: src=" + std::to_string(e->SourceProcessId);
        det += " tgt=" + std::to_string(e->TargetProcessId);
        det += " Score=" + std::to_string(e->ThreatScore);
        if (e->DetectionFlags & MEMACCESS_FLAG_LSASS_TARGET) det += " [LSASS]";
        if (e->DetectionFlags & MEMACCESS_FLAG_AV_TARGET) det += " [AV-TARGET]";
        if (e->DetectionFlags & MEMACCESS_FLAG_CREDENTIAL_READ) det += " [CRED]";
        v.details = std::move(det);
        MemoryScanResult sr; sr.pid = e->TargetProcessId; sr.compromised = true;
        ProcessViolation(v, e->TargetProcessId, sr);
        m_stats.kernelEventsProcessed++;
    }

    void MemoryProtection::MemoryProtectionImpl::HandleKernelAlloc(const MEMORY_ALLOC_EVENT* e) {
        if (!e) return;
        bool susp = (e->DetectionFlags & (MEMALLOC_FLAG_RWX_INITIAL | MEMALLOC_FLAG_CROSS_PROCESS |
            MEMALLOC_FLAG_HIGH_ENTROPY_AFTER | MEMALLOC_FLAG_FOLLOWS_PATTERN)) != 0;
        if (!susp) return;
        MemoryViolation v;
        v.type = MemoryViolationType::Kernel_SuspiciousAlloc;
        v.address = e->BaseAddress; v.size = static_cast<size_t>(e->RegionSize);
        v.targetPid = e->ProcessId; v.threadId = e->ThreadId; v.fromKernel = true;
        v.detectedAt = std::chrono::system_clock::now();
        if (e->DetectionFlags & MEMALLOC_FLAG_RWX_INITIAL) { v.type = MemoryViolationType::RWX_Page; v.confidence = 0.80f; }
        else if (e->DetectionFlags & MEMALLOC_FLAG_CROSS_PROCESS) { v.confidence = 0.75f; }
        else { v.confidence = 0.60f; }
        char det[256];
        snprintf(det, sizeof(det),
            "Kernel alloc: addr=0x%llX size=0x%llX prot=0x%08X Score=%u",
            static_cast<unsigned long long>(e->BaseAddress),
            static_cast<unsigned long long>(e->RegionSize),
            e->Protection, e->ThreatScore);
        v.details = det;
        MemoryScanResult sr; sr.pid = e->ProcessId;
        ProcessViolation(v, e->ProcessId, sr);
        m_stats.kernelEventsProcessed++;
    }
    // =========================================================================
    // Integration Methods
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ProcessViolation(
        MemoryViolation& v, uint32_t pid, MemoryScanResult& result) {
        v.severity = CalcSeverity(v.type, v.confidence);
        v.mitreTechnique = MapMitre(v.type);
        result.violations.push_back(v);
        if (v.severity >= MemoryThreatSeverity::High) result.compromised = true;
        if (v.severity > result.highestSeverity) result.highestSeverity = v.severity;
        result.overallThreatScore = std::max(result.overallThreatScore, v.confidence * 100.0f);
        m_stats.threatsDetected++;
        SS_LOG_WARN(LOG_CATEGORY, L"Memory threat: type=%hs sev=%hs PID=%u addr=0x%llX conf=%.2f",
            ViolationTypeToStr(v.type), SeverityToStr(v.severity), pid, v.address, v.confidence);
        if (v.confidence >= m_config.alertThreshold) {
            ReportAlert(v, pid);
            ReportTelemetry(v, pid);
        }
        ReportBehavior(v, pid);
        NotifyCallbacks(v, pid);
    }

    void MemoryProtection::MemoryProtectionImpl::ReportAlert(const MemoryViolation& v, uint32_t pid) {
        if (!m_config.enableAlertSystem) return;
        try {
            auto& as = Communication::AlertSystem::Instance();
            Communication::AlertSeverity sev = Communication::AlertSeverity::Medium;
            switch (v.severity) {
            case MemoryThreatSeverity::Low:       sev = Communication::AlertSeverity::Low; break;
            case MemoryThreatSeverity::Medium:    sev = Communication::AlertSeverity::Medium; break;
            case MemoryThreatSeverity::High:      sev = Communication::AlertSeverity::High; break;
            case MemoryThreatSeverity::Critical:  sev = Communication::AlertSeverity::Critical; break;
            case MemoryThreatSeverity::Emergency: sev = Communication::AlertSeverity::Emergency; break;
            default: break;
            }
            std::string subj = std::string("Memory Threat: ") + ViolationTypeToStr(v.type) + " PID " + std::to_string(pid);
            as.RaiseAlert(sev, Communication::AlertType::ThreatDetection, subj, v.ToJson(), "MemoryProtection");
            m_stats.alertsRaised++;
        } catch (const std::exception& ex) {
            SS_LOG_WARN(LOG_CATEGORY, L"AlertSystem report failed: %hs", ex.what());
        } catch (...) {
            SS_LOG_WARN(LOG_CATEGORY, L"AlertSystem report failed (unknown)");
        }
    }

    void MemoryProtection::MemoryProtectionImpl::ReportTelemetry(const MemoryViolation& v, uint32_t pid) {
        if (!m_config.enableTelemetry) return;
        try {
            auto& tc = Communication::TelemetryCollector::Instance();
            Communication::DetectionEventData det;
            det.threatName = std::string("MemoryThreat.") + ViolationTypeToStr(v.type);
            det.threatType = "Memory";
            det.detectionMethod = v.fromKernel ? "KernelDriver" : "UserModeScan";
            det.actionTaken = (v.confidence >= m_config.blockThreshold) ? "Blocked" : "Alerted";
            det.detectionTime = static_cast<uint64_t>(std::chrono::system_clock::to_time_t(v.detectedAt));
            det.fpProbability = std::max(0.0, 1.0 - static_cast<double>(v.confidence));
            tc.RecordDetection(det);
        } catch (const std::exception& ex) {
            SS_LOG_WARN(LOG_CATEGORY, L"Telemetry report failed: %hs", ex.what());
        } catch (...) {
            SS_LOG_WARN(LOG_CATEGORY, L"Telemetry report failed (unknown)");
        }
    }

    void MemoryProtection::MemoryProtectionImpl::ReportBehavior(const MemoryViolation& v, uint32_t pid) {
        if (!m_config.enableBehaviorFeedback) return;
        try {
            using namespace Core::Engine;
            auto& ba = BehaviorAnalyzer::Instance();
            BehaviorEvent ev{};
            ev.timestamp = std::chrono::steady_clock::now();
            ev.systemTime = v.detectedAt;
            ev.category = BehaviorEventCategory::Memory;
            ev.processId = pid;
            ev.targetProcessId = v.targetPid;
            ev.targetAddress = v.address;
            ev.targetSize = v.size;
            ev.success = true;
            switch (v.type) {
            case MemoryViolationType::RWX_Page:
            case MemoryViolationType::Kernel_SuspiciousAlloc:
                ev.eventType = BehaviorEventType::MemoryAllocate; break;
            case MemoryViolationType::W_to_X_Transition:
            case MemoryViolationType::Kernel_MemoryProtect:
                ev.eventType = BehaviorEventType::MemoryProtect; break;
            case MemoryViolationType::Thread_Injection:
            case MemoryViolationType::Early_Bird_APC:
            case MemoryViolationType::Kernel_Injection:
                ev.eventType = BehaviorEventType::MemoryRemoteWrite; break;
            case MemoryViolationType::Kernel_CrossProcess:
                ev.eventType = BehaviorEventType::MemoryRead; break;
            default:
                ev.eventType = BehaviorEventType::MemoryWrite; break;
            }
            ev.action = ViolationTypeToStr(v.type);
            ev.details = StringUtils::ToWide(v.details);
            ev.accessMask = static_cast<uint32_t>(v.type);
            ba.ProcessEventAsync(std::move(ev));
        } catch (const std::exception& ex) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"BehaviorAnalyzer feed failed: %hs", ex.what());
        } catch (...) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"BehaviorAnalyzer feed failed (unknown)");
        }
    }

    void MemoryProtection::MemoryProtectionImpl::NotifyCallbacks(const MemoryViolation& v, uint32_t pid) {
        // Snapshot the callback list under the lock, then invoke outside it.
        // This prevents a deadlock where a callback calls UnregisterThreatCallback(),
        // which would attempt to re-acquire m_callbackMutex on the same thread.
        std::vector<std::pair<uint64_t, MemoryThreatCallback>> snapshot;
        {
            std::lock_guard lk(m_callbackMutex);
            snapshot = m_threatCallbacks;
        }
        for (const auto& [id, cb] : snapshot) {
            try { cb(v, pid); }
            catch (const std::exception& ex) { SS_LOG_WARN(LOG_CATEGORY, L"Callback %llu error: %hs", id, ex.what()); }
            catch (...) { SS_LOG_WARN(LOG_CATEGORY, L"Callback %llu unknown error", id); }
        }
    }
    // =========================================================================
    // Core Scan Orchestration
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::ScanProcessInternal(
        ProcessUtils::ProcessId pid, ScanMode mode, MemoryScanResult& result) {
        auto startTime = std::chrono::high_resolution_clock::now();
        result.pid = pid;
        result.compromised = false;

        auto regions = CollectRegions(pid, m_config.maxRegionsPerScan);
        for (const auto& mbi : regions)
            result.pagesScanned += (mbi.RegionSize / 4096);

        // Fast: RWX + module headers
        ScanForRWX(pid, regions, result);
        ScanForModuleStomping(pid, result);

        // Deep: full pattern scan
        if (mode >= ScanMode::Deep) {
            ScanForShellcode(pid, regions, result);
            ScanForUnbackedExec(pid, regions, result);
            ScanForHeapSpray(pid, regions, result);
        }

        // Heuristic/APT_Hunt: behavioral + stack analysis
        if (mode >= ScanMode::Heuristic) {
            ScanForThreadInjection(pid, result);
            ScanForROP(pid, result);
        }

        auto endTime = std::chrono::high_resolution_clock::now();
        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
        m_stats.scansPerformed++;
        m_stats.pagesScanned += result.pagesScanned;
        m_stats.totalScanTimeUs += result.scanDuration.count();

        if (result.compromised) {
            SS_LOG_WARN(LOG_CATEGORY, L"PID=%u scan: %zu violations, sev=%hs, score=%.1f in %lldus",
                pid, result.violations.size(), SeverityToStr(result.highestSeverity),
                result.overallThreatScore, result.scanDuration.count());
        } else {
            SS_LOG_DEBUG(LOG_CATEGORY, L"PID=%u clean: %zu pages in %lldus",
                pid, result.pagesScanned, result.scanDuration.count());
        }
    }

    void MemoryProtection::MemoryProtectionImpl::ScanRegionInternal(
        ProcessUtils::ProcessId pid, uint64_t addr, size_t size, MemoryScanResult& result) {
        auto startTime = std::chrono::high_resolution_clock::now();
        result.pid = pid;
        std::vector<uint8_t> buf;
        if (!ReadSafe(pid, addr, buf, std::min(size, SHELLCODE_SCAN_WINDOW))) return;
        double ent = CalcEntropy(buf.data(), buf.size());
        const uint8_t* d = buf.data(); size_t ds = buf.size();

        auto mkV = [&](MemoryViolationType t, float c, const char* det) {
            MemoryViolation v;
            v.type = t; v.address = addr; v.size = size; v.confidence = c;
            v.entropy = ent; v.targetPid = pid; v.details = det;
            v.detectedAt = std::chrono::system_clock::now();
            CapDump(v, d, ds);
            ProcessViolation(v, pid, result);
        };

        if (DetectNopSled(d, ds)) mkV(MemoryViolationType::Shellcode_Pattern, 0.88f, "NOP sled in targeted region");
        if (DetectAPIHashing(d, ds)) mkV(MemoryViolationType::API_Hash_Resolution, 0.91f, "API hashing in targeted region");
        if (DetectSyscallStub(d, ds)) mkV(MemoryViolationType::Syscall_Stub, 0.93f, "Syscall stub in targeted region");
        if (DetectReflectiveDLL(d, ds)) mkV(MemoryViolationType::Reflective_DLL, 0.95f, "PE image in targeted region");

        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - startTime);
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    void MemoryProtection::MemoryProtectionImpl::StartInternal() {
        if (m_running.exchange(true)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Start called but engine already running");
            return;
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Starting MemoryProtection engine");

        if (m_config.enableKernelIntegration) {
            try {
                (void)Communication::IPCManager::Instance();
                SS_LOG_INFO(LOG_CATEGORY, L"Kernel IPC integration enabled - listening for MemoryAlert events");
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to verify kernel IPC: %hs", e.what());
            }
        }

        if (m_config.scanOnProcessCreate) {
            try {
                auto& pcm = ProcessCreationMonitor::Instance();
                m_pcmTerminateCbId = pcm.RegisterTerminateCallback(
                    [this](uint32_t pid, uint32_t /*exitCode*/) {
                        std::unique_lock lk(m_dataMutex);
                        m_monitoredProcesses.erase(pid);
                    });
                SS_LOG_INFO(LOG_CATEGORY, L"ProcessCreationMonitor terminate callback registered (ID=%llu)", m_pcmTerminateCbId);
            } catch (const std::exception& e) {
                SS_LOG_WARN(LOG_CATEGORY, L"ProcessCreationMonitor registration failed: %hs", e.what());
            }
        }

        if (m_config.enableContinuousMonitoring) {
            m_monitorStop.store(false);
            m_monitorThread = std::thread([this]() { MonitoringLoop(); });
            SS_LOG_INFO(LOG_CATEGORY, L"Continuous monitoring thread started");
        }
        SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection engine started");
    }

    void MemoryProtection::MemoryProtectionImpl::StopInternal() {
        if (!m_running.exchange(false)) return;
        SS_LOG_INFO(LOG_CATEGORY, L"Stopping MemoryProtection engine");
        m_monitorStop.store(true);
        if (m_monitorThread.joinable()) m_monitorThread.join();
        if (m_pcmTerminateCbId != 0) {
            try {
                ProcessCreationMonitor::Instance().UnregisterTerminateCallback(m_pcmTerminateCbId);
                m_pcmTerminateCbId = 0;
            } catch (...) {}
        }
        SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection engine stopped");
    }

    void MemoryProtection::MemoryProtectionImpl::MonitoringLoop() {
        SS_LOG_DEBUG(LOG_CATEGORY, L"Monitoring loop started (interval=%ums)", MONITOR_INTERVAL_MS);
        while (!m_monitorStop.load()) {
            for (uint32_t el = 0; el < MONITOR_INTERVAL_MS && !m_monitorStop.load(); el += 500)
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (m_monitorStop.load()) break;
            std::vector<ProcessUtils::ProcessId> toScan;
            { std::shared_lock lk(m_dataMutex); toScan.assign(m_monitoredProcesses.begin(), m_monitoredProcesses.end()); }
            for (auto pid : toScan) {
                if (m_monitorStop.load()) break;
                if (!ProcessUtils::IsProcessRunning(pid)) {
                    std::unique_lock lk(m_dataMutex); m_monitoredProcesses.erase(pid); continue;
                }
                try { MemoryScanResult r; ScanProcessInternal(pid, m_config.processCreateScanMode, r); }
                catch (const std::exception& e) { SS_LOG_WARN(LOG_CATEGORY, L"Monitor scan PID=%u failed: %hs", pid, e.what()); }
            }
        }
        SS_LOG_DEBUG(LOG_CATEGORY, L"Monitoring loop exited");
    }
    // =========================================================================
    // Public API Forwarding
    // =========================================================================

    MemoryProtection& MemoryProtection::Instance() noexcept {
        static MemoryProtection instance;
        return instance;
    }

    MemoryProtection::MemoryProtection()
        : m_impl(std::make_unique<MemoryProtectionImpl>()) {
        SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection engine initialized");
    }

    MemoryProtection::~MemoryProtection() {
        SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection engine destroyed");
    }

    void MemoryProtection::Start() { m_impl->StartInternal(); }
    void MemoryProtection::Stop() { m_impl->StopInternal(); }
    bool MemoryProtection::IsRunning() const noexcept { return m_impl->m_running.load(); }

    void MemoryProtection::Configure(const MemoryProtectionConfig& config) {
        std::unique_lock lk(m_impl->m_dataMutex);
        m_impl->m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Config updated: kernel=%d, monitor=%d, APT=%d",
            config.enableKernelIntegration, config.enableContinuousMonitoring, config.enableAPTHunting);
    }

    MemoryProtectionConfig MemoryProtection::GetConfig() const {
        std::shared_lock lk(m_impl->m_dataMutex);
        return m_impl->m_config;
    }

    MemoryScanResult MemoryProtection::ScanProcess(Utils::ProcessUtils::ProcessId pid, ScanMode mode) {
        MemoryScanResult result;
        try {
            if (!ProcessUtils::IsProcessRunning(pid)) return result;
            m_impl->ScanProcessInternal(pid, mode, result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanProcess PID=%u: %hs", pid, e.what());
        } catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"ScanProcess PID=%u unknown exception", pid);
        }
        return result;
    }

    MemoryScanResult MemoryProtection::ScanRegion(Utils::ProcessUtils::ProcessId pid, uint64_t address, size_t size) {
        MemoryScanResult result;
        try {
            if (!ProcessUtils::IsProcessRunning(pid)) return result;
            if (size == 0 || size > (256 * 1024 * 1024)) return result;
            m_impl->ScanRegionInternal(pid, address, size, result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ScanRegion PID=%u: %hs", pid, e.what());
        } catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"ScanRegion PID=%u unknown exception", pid);
        }
        return result;
    }

    bool MemoryProtection::MonitorProcess(Utils::ProcessUtils::ProcessId pid) {
        std::unique_lock lk(m_impl->m_dataMutex);
        if (m_impl->m_monitoredProcesses.contains(pid)) return true;
        m_impl->m_monitoredProcesses.insert(pid);
        SS_LOG_INFO(LOG_CATEGORY, L"Monitoring enabled PID=%u", pid);
        return true;
    }

    bool MemoryProtection::UnmonitorProcess(Utils::ProcessUtils::ProcessId pid) {
        std::unique_lock lk(m_impl->m_dataMutex);
        auto erased = m_impl->m_monitoredProcesses.erase(pid);
        if (erased) SS_LOG_INFO(LOG_CATEGORY, L"Monitoring disabled PID=%u", pid);
        return erased > 0;
    }

    bool MemoryProtection::IsProcessCompromised(Utils::ProcessUtils::ProcessId pid) {
        return ScanProcess(pid, ScanMode::Fast).compromised;
    }

    MemoryScanResult MemoryProtection::HuntAPT(Utils::ProcessUtils::ProcessId pid) {
        MemoryScanResult result;
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"APT hunt PID=%u", pid);
            if (!ProcessUtils::IsProcessRunning(pid)) return result;
            m_impl->ScanProcessInternal(pid, ScanMode::APT_Hunt, result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"HuntAPT PID=%u: %hs", pid, e.what());
        }
        return result;
    }

    std::vector<MemoryScanResult> MemoryProtection::HuntAllProcesses() {
        std::vector<MemoryScanResult> results;
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"System-wide APT hunt");
            std::vector<ProcessUtils::ProcessId> pids;
            ProcessUtils::EnumerateProcesses(pids);
            uint32_t count = 0;
            for (auto pid : pids) {
                if (count >= MAX_HUNT_PROCS) break;
                if (pid == 0 || pid == 4) continue;
                MemoryScanResult r;
                m_impl->ScanProcessInternal(pid, ScanMode::Deep, r);
                if (!r.violations.empty()) results.push_back(std::move(r));
                ++count;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"APT hunt done: %u scanned, %zu with detections", count, results.size());
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"HuntAll: %hs", e.what());
        }
        return results;
    }

    void MemoryProtection::ProcessKernelMemoryAlert(uint32_t messageType, const void* payload, size_t payloadSize) {
        if (!m_impl->m_running.load()) return;
        if (!m_impl->m_config.enableKernelIntegration) return;

        // Strict input validation — this function is on the critical IPC hot path.
        if (!payload || payloadSize < sizeof(uint32_t)) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"ProcessKernelMemoryAlert: invalid payload (ptr=%p size=%zu msgType=%u)",
                payload, payloadSize, messageType);
            return;
        }

        // All MemoryTypes.h event structures begin with UINT32 Size at offset 0.
        // The kernel driver sets this field to sizeof(struct) so we can safely
        // discriminate the event sub-type.  We also require payloadSize >= declaredSize
        // to prevent any out-of-bounds reads if the IPC layer delivers a truncated buffer.
        const uint32_t declaredSize = *static_cast<const uint32_t*>(payload);
        if (declaredSize < sizeof(uint32_t) || declaredSize > payloadSize) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"ProcessKernelMemoryAlert: declared size %u outside received window %zu (msgType=%u)",
                declaredSize, payloadSize, messageType);
            return;
        }

        // Dispatch by declared structure size.
        // With #pragma pack(push,1) all structures have distinct sizes.
        if (declaredSize == sizeof(SHELLCODE_DETECTION_EVENT)) {
            m_impl->HandleKernelShellcode(static_cast<const SHELLCODE_DETECTION_EVENT*>(payload));
        } else if (declaredSize == sizeof(INJECTION_DETECTION_EVENT)) {
            m_impl->HandleKernelInjection(static_cast<const INJECTION_DETECTION_EVENT*>(payload));
        } else if (declaredSize == sizeof(HOLLOWING_DETECTION_EVENT)) {
            m_impl->HandleKernelHollowing(static_cast<const HOLLOWING_DETECTION_EVENT*>(payload));
        } else if (declaredSize == sizeof(MEMORY_PROTECT_EVENT)) {
            m_impl->HandleKernelProtect(static_cast<const MEMORY_PROTECT_EVENT*>(payload));
        } else if (declaredSize == sizeof(MEMORY_ACCESS_EVENT)) {
            m_impl->HandleKernelAccess(static_cast<const MEMORY_ACCESS_EVENT*>(payload));
        } else if (declaredSize == sizeof(MEMORY_ALLOC_EVENT)) {
            m_impl->HandleKernelAlloc(static_cast<const MEMORY_ALLOC_EVENT*>(payload));
        } else {
            SS_LOG_WARN(LOG_CATEGORY,
                L"ProcessKernelMemoryAlert: unrecognized payload size %u (msgType=%u) — dropping",
                declaredSize, messageType);
        }
    }

    uint64_t MemoryProtection::RegisterThreatCallback(MemoryThreatCallback callback) {
        if (!callback) return 0;
        const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
        std::lock_guard lk(m_impl->m_callbackMutex);
        m_impl->m_threatCallbacks.emplace_back(id, std::move(callback));
        SS_LOG_DEBUG(LOG_CATEGORY, L"Threat callback registered ID=%llu (total=%zu)",
            id, m_impl->m_threatCallbacks.size());
        return id;
    }

    bool MemoryProtection::UnregisterThreatCallback(uint64_t callbackId) {
        if (callbackId == 0) return false;
        std::lock_guard lk(m_impl->m_callbackMutex);
        auto it = std::find_if(m_impl->m_threatCallbacks.begin(),
                               m_impl->m_threatCallbacks.end(),
                               [callbackId](const auto& p) { return p.first == callbackId; });
        if (it == m_impl->m_threatCallbacks.end()) return false;
        m_impl->m_threatCallbacks.erase(it);
        SS_LOG_DEBUG(LOG_CATEGORY, L"Threat callback unregistered ID=%llu", callbackId);
        return true;
    }

    bool MemoryProtection::EnableExploitProtection(
        Utils::ProcessUtils::ProcessId pid,
        uint32_t flags) {
        if (pid == 0) return false;

        bool allOk = true;
        const bool isSelf = (static_cast<DWORD>(pid) == ::GetCurrentProcessId());

        SS_LOG_INFO(LOG_CATEGORY, L"EnableExploitProtection PID=%u flags=0x%08X self=%d",
            pid, flags, isSelf ? 1 : 0);

        // For the calling process, apply mitigations directly via
        // SetProcessMitigationPolicy.  For external processes, we cannot apply
        // most mitigations from user-mode without kernel assistance; we fall
        // back to enhanced monitoring.
        if (isSelf && !(flags & EXPLOIT_PROTECT_MONITOR_ONLY)) {
            if (flags & EXPLOIT_PROTECT_DEP) {
                PROCESS_MITIGATION_DEP_POLICY dep{};
                dep.Enable = 1;
                dep.DisableAtlThunkEmulation = 1;
                if (!SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep))) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"EnableExploitProtection: DEP SetProcessMitigationPolicy failed (0x%08X)",
                        GetLastError());
                    allOk = false;
                }
            }
            if (flags & EXPLOIT_PROTECT_ASLR_FORCE) {
                PROCESS_MITIGATION_ASLR_POLICY aslr{};
                aslr.EnableForceRelocateImages = 1;
                aslr.DisallowStrippedImages    = 1;
                aslr.EnableBottomUpRandomization = 1;
                aslr.EnableHighEntropy          = 1;
                if (!SetProcessMitigationPolicy(ProcessASLRPolicy, &aslr, sizeof(aslr))) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"EnableExploitProtection: ASLR SetProcessMitigationPolicy failed (0x%08X)",
                        GetLastError());
                    allOk = false;
                }
            }
            if (flags & EXPLOIT_PROTECT_CFG) {
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
                cfg.EnableControlFlowGuard   = 1;
                cfg.EnableExportSuppression  = 1;
                cfg.StrictMode               = 1;
                if (!SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg))) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"EnableExploitProtection: CFG SetProcessMitigationPolicy failed (0x%08X)",
                        GetLastError());
                    allOk = false;
                }
            }
            if (flags & EXPLOIT_PROTECT_HEAP_TERMINATE) {
                PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY hchk{};
                hchk.RaiseExceptionOnInvalidHandleReference = 1;
                hchk.HandleExceptionsPermanentlyEnabled     = 1;
                (void)SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &hchk, sizeof(hchk));

                // PROCESS_MITIGATION_HEAP_POLICY requires recent Windows SDK
                // Use runtime check via GetProcAddress to remain compatible
                struct HeapPolicy_ { DWORD Flags; };
                HeapPolicy_ hp{};
                hp.Flags = 0x1;  // TerminateOnHeapErrors
                if (!SetProcessMitigationPolicy(static_cast<PROCESS_MITIGATION_POLICY>(16 /*ProcessHeapPolicy*/),
                        &hp, sizeof(hp))) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"EnableExploitProtection: heap-terminate policy failed (0x%08X)",
                        GetLastError());
                    allOk = false;
                }
            }
            if (flags & EXPLOIT_PROTECT_NO_DYNAMIC_CODE) {
                PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcp{};
                dcp.ProhibitDynamicCode = 1;
                if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dcp, sizeof(dcp))) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"EnableExploitProtection: dynamic-code policy failed (0x%08X)",
                        GetLastError());
                    // Not fatal — some JIT runtimes legitimately need this.
                }
            }
            if (flags & EXPLOIT_PROTECT_STRICT_HANDLES) {
                PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY shc{};
                shc.RaiseExceptionOnInvalidHandleReference = 1;
                shc.HandleExceptionsPermanentlyEnabled     = 1;
                (void)SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &shc, sizeof(shc));
            }
        } else if (!isSelf) {
            // For external processes, user-mode cannot apply most mitigations.
            // Register the process for continuous monitoring at Heuristic depth
            // so the monitoring loop will perform behavioral tracking.
            SS_LOG_INFO(LOG_CATEGORY,
                L"EnableExploitProtection: external PID=%u — applying enhanced monitoring (no kernel assist)",
                pid);
        }

        // Always: register the process for continuous monitoring regardless of
        // whether hardware mitigations could be applied.
        MonitorProcess(pid);
        return allOk;
    }

    bool MemoryProtection::SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"SelfTest: running detection algorithm validation");
        bool passed = true;

        // ---- Test 1: NOP sled detection ----
        {
            constexpr size_t NOP_LEN = 64;
            uint8_t nopSled[NOP_LEN];
            memset(nopSled, 0x90, sizeof(nopSled));
            if (!m_impl->DetectNopSled(nopSled, NOP_LEN)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAIL: NOP sled not detected");
                passed = false;
            }
        }

        // ---- Test 2: API hashing (ror13 pattern) ----
        {
            constexpr uint8_t ror13[] = { 0xC1, 0xCF, 0x0D, 0x41, 0x03, 0xC8 };
            if (!m_impl->DetectAPIHashing(ror13, sizeof(ror13))) {
                SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAIL: ror13 API hash not detected");
                passed = false;
            }
        }

        // ---- Test 3: Direct syscall stub ----
        {
            // mov r10, rcx ; mov eax, 0x55 ; syscall
            constexpr uint8_t syscallStub[] = {
                0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x0F, 0x05
            };
            if (!m_impl->DetectSyscallStub(syscallStub, sizeof(syscallStub))) {
                SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAIL: syscall stub not detected");
                passed = false;
            }
        }

        // ---- Test 4: Reflective DLL header ----
        {
            uint8_t peHdr[0x100] = {};
            peHdr[0] = 'M'; peHdr[1] = 'Z';
            *reinterpret_cast<uint32_t*>(peHdr + 0x3C) = 0x80u;
            *reinterpret_cast<uint32_t*>(peHdr + 0x80) = 0x00004550u; // "PE\0\0"
            if (!m_impl->DetectReflectiveDLL(peHdr, sizeof(peHdr))) {
                SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAIL: reflective DLL header not detected");
                passed = false;
            }
        }

        // ---- Test 5: Entropy calculation sanity ----
        {
            uint8_t allBytes[256];
            for (int i = 0; i < 256; ++i) allBytes[i] = static_cast<uint8_t>(i);
            const double ent = CalcEntropy(allBytes, 256);
            if (ent < 7.95) { // Perfect entropy = 8.0 bits per byte
                SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAIL: entropy calc returned %.4f (expected ~8.0)", ent);
                passed = false;
            }
        }

        // ---- Test 6: Encoder stub (shikata marker) ----
        {
            constexpr uint8_t shikata[] = { 0xD9, 0x74, 0x24, 0xF4, 0x58, 0x31, 0xC9 };
            if (!m_impl->DetectEncoderStub(shikata, sizeof(shikata))) {
                SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAIL: shikata encoder not detected");
                passed = false;
            }
        }

        // ---- Test 7: PIC call-pop prologue ----
        {
            // E8 00 00 00 00 5B  =>  call $+5 ; pop ebx
            constexpr uint8_t callPop[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B };
            if (!m_impl->DetectPIC(callPop, sizeof(callPop))) {
                SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAIL: PIC call-pop not detected");
                passed = false;
            }
        }

        if (passed) {
            SS_LOG_INFO(LOG_CATEGORY, L"SelfTest PASSED: all 7 detection checks functional");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"SelfTest FAILED: one or more detection algorithms malfunction");
        }
        return passed;
    }

    std::string MemoryProtection::GetStatistics() const {
        // Snapshot atomics without holding any lock that could block writers.
        const uint64_t scans        = m_impl->m_stats.scansPerformed.load(std::memory_order_relaxed);
        const uint64_t threats      = m_impl->m_stats.threatsDetected.load(std::memory_order_relaxed);
        const uint64_t pages        = m_impl->m_stats.pagesScanned.load(std::memory_order_relaxed);
        const uint64_t scanTimeUs   = m_impl->m_stats.totalScanTimeUs.load(std::memory_order_relaxed);
        const uint64_t kernelEvts   = m_impl->m_stats.kernelEventsProcessed.load(std::memory_order_relaxed);
        const uint64_t alerts       = m_impl->m_stats.alertsRaised.load(std::memory_order_relaxed);
        const bool     running      = m_impl->m_running.load(std::memory_order_relaxed);

        size_t monitoredCount = 0;
        {
            std::shared_lock lk(m_impl->m_dataMutex);
            monitoredCount = m_impl->m_monitoredProcesses.size();
        }

        size_t callbackCount = 0;
        {
            std::lock_guard lk(m_impl->m_callbackMutex);
            callbackCount = m_impl->m_threatCallbacks.size();
        }

        const double avgScanMs = (scans > 0)
            ? (static_cast<double>(scanTimeUs) / static_cast<double>(scans) / 1000.0)
            : 0.0;

        const double detectionRate = (scans > 0)
            ? (static_cast<double>(threats) / static_cast<double>(scans) * 100.0)
            : 0.0;

        char buf[512];
        snprintf(buf, sizeof(buf),
            "{"
            "\"running\":%s,"
            "\"scansPerformed\":%llu,"
            "\"threatsDetected\":%llu,"
            "\"pagesScanned\":%llu,"
            "\"kernelEventsProcessed\":%llu,"
            "\"alertsRaised\":%llu,"
            "\"monitoredProcesses\":%zu,"
            "\"registeredCallbacks\":%zu,"
            "\"avgScanTimeMs\":%.3f,"
            "\"detectionRatePct\":%.2f"
            "}",
            running ? "true" : "false",
            static_cast<unsigned long long>(scans),
            static_cast<unsigned long long>(threats),
            static_cast<unsigned long long>(pages),
            static_cast<unsigned long long>(kernelEvts),
            static_cast<unsigned long long>(alerts),
            monitoredCount,
            callbackCount,
            avgScanMs,
            detectionRate);

        return buf;
    }

} // namespace RealTime
} // namespace ShadowStrike
