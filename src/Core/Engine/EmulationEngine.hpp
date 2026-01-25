/**
 * ============================================================================
 * ShadowStrike Core Engine - EMULATION ENGINE (The Sandbox)
 * ============================================================================
 *
 * @file EmulationEngine.hpp
 * @brief Enterprise-grade code emulation and dynamic analysis sandbox.
 *
 * This module provides hardware-accelerated code emulation for safe execution
 * of suspect code using Windows Hypervisor Platform (WHP) / Hyper-V. It creates
 * isolated virtual environments to detonate malware without risk to the host.
 *
 * =============================================================================
 * TECHNOLOGY STACK
 * =============================================================================
 *
 * 1. **Windows Hypervisor Platform (WHP)**
 *    - Hardware-accelerated virtualization using Intel VT-x / AMD-V
 *    - Near-native execution speed for analysis
 *    - Memory isolation via Extended Page Tables (EPT)
 *    - CPU state isolation (registers, flags, control registers)
 *
 * 2. **CPU Emulation Fallback**
 *    - Unicorn Engine for software emulation when WHP unavailable
 *    - Supports x86, x64, ARM, ARM64 architectures
 *    - Instruction-level tracing and breakpoints
 *
 * 3. **Disassembly Engine**
 *    - Capstone for instruction disassembly
 *    - Supports all major architectures
 *    - Used for code flow analysis and debugging
 *
 * 4. **Virtual OS Components**
 *    - Virtual File System (in-memory, copy-on-write)
 *    - Virtual Registry (captures persistence attempts)
 *    - Virtual Network Stack (captures C2 communication)
 *    - Virtual Process Environment (PEB/TEB simulation)
 *
 * =============================================================================
 * CAPABILITIES
 * =============================================================================
 *
 * 1. **Automatic Unpacking**
 *    - Detects packed/encrypted executables
 *    - Emulates until Original Entry Point (OEP) reached
 *    - Dumps unpacked code from memory
 *    - Supports 100+ packer families (UPX, Themida, VMProtect, etc.)
 *
 * 2. **API Hooking & Monitoring**
 *    - Intercepts all Windows API calls
 *    - Captures parameters and return values
 *    - Detects anti-analysis API usage
 *    - Simulates API responses to trigger malware behavior
 *
 * 3. **Memory Analysis**
 *    - Periodic YARA scanning of emulated memory
 *    - Heap spray detection
 *    - Shellcode injection detection
 *    - ROP chain identification
 *
 * 4. **Behavioral Analysis**
 *    - Tracks file system modifications
 *    - Monitors registry changes
 *    - Captures network communication attempts
 *    - Detects process injection techniques
 *
 * 5. **Anti-Evasion Countermeasures**
 *    - Hooks timing APIs to defeat time-based evasion
 *    - Simulates human interaction patterns
 *    - Provides realistic environment fingerprints
 *    - Defeats VM/sandbox detection attempts
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                         EmulationEngine                                  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Hypervisor Layer (WHP/Hyper-V)                │   │
 * │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │   │
 * │  │  │ vCPU Manager│  │ Memory Mgr  │  │ Partition Controller    │  │   │
 * │  │  │ - x86/x64   │  │ - EPT/NPT   │  │ - Create/Destroy        │  │   │
 * │  │  │ - State     │  │ - CoW       │  │ - Snapshot/Restore      │  │   │
 * │  │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │   │
 * │  └─────────────────────────────────────────────────────────────────┘   │
 * │                                  │                                      │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Virtual OS Layer                              │   │
 * │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │   │
 * │  │  │Virtual FS │  │Virtual Reg│  │Virtual Net│  │Virtual Env│    │   │
 * │  │  │- Files    │  │- Keys     │  │- DNS      │  │- PEB/TEB  │    │   │
 * │  │  │- Dirs     │  │- Values   │  │- Sockets  │  │- Heap     │    │   │
 * │  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘    │   │
 * │  └─────────────────────────────────────────────────────────────────┘   │
 * │                                  │                                      │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    API Emulation Layer                           │   │
 * │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │   │
 * │  │  │kernel32   │  │ntdll      │  │ws2_32     │  │user32     │    │   │
 * │  │  │advapi32   │  │wininet    │  │crypt32    │  │shell32    │    │   │
 * │  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘    │   │
 * │  └─────────────────────────────────────────────────────────────────┘   │
 * │                                  │                                      │
 * │  ┌─────────────────────────────────────────────────────────────────┐   │
 * │  │                    Analysis Layer                                │   │
 * │  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐    │   │
 * │  │  │Unpacker   │  │YARA Scan  │  │Behavior   │  │Threat     │    │   │
 * │  │  │Detection  │  │Engine     │  │Tracker    │  │Classifier │    │   │
 * │  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘    │   │
 * │  └─────────────────────────────────────────────────────────────────┘   │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * =============================================================================
 * INTEGRATION POINTS
 * =============================================================================
 *
 * - **SignatureStore**: YARA rules for memory scanning
 * - **PatternStore**: Byte patterns for unpacker detection
 * - **HashStore**: Hash comparison of unpacked payloads
 * - **ThreatIntel**: IOC checking for network destinations
 * - **AntiEvasion**: Countermeasures against sandbox detection
 *
 * =============================================================================
 * PERFORMANCE TARGETS
 * =============================================================================
 *
 * | Operation              | Target      | Notes                           |
 * |------------------------|-------------|----------------------------------|
 * | Partition creation     | < 100ms     | With memory pre-allocation       |
 * | PE loading             | < 50ms      | Including import resolution      |
 * | Instruction execution  | Near-native | With WHP hardware acceleration   |
 * | API hook overhead      | < 1μs       | Per API call                     |
 * | Memory scan (YARA)     | < 100ms     | Per 64MB region                  |
 * | Snapshot/Restore       | < 10ms      | Full VM state                    |
 *
 * =============================================================================
 * SECURITY CONSIDERATIONS
 * =============================================================================
 *
 * - Strict memory isolation via hardware virtualization
 * - No direct host filesystem access from guest
 * - Network traffic captured but not forwarded
 * - Resource limits to prevent DoS (CPU time, memory, instructions)
 * - Automatic cleanup on timeout or crash
 *
 * @note Requires Windows 10 1803+ with Hyper-V enabled
 * @note Falls back to Unicorn Engine if WHP unavailable
 *
 * @see SignatureStore for YARA rule integration
 * @see PatternStore for packer detection patterns
 * @see HashStore for payload hash comparison
 * @see ThreatIntel for IOC correlation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/ProcessUtils.hpp"       // Process emulation
#include "../../Utils/FileUtils.hpp"          // Virtual filesystem
#include "../../Utils/RegistryUtils.hpp"      // Virtual registry
#include "../../PatternStore/PatternStore.hpp" // Unpacker patterns
#include "../../SignatureStore/SignatureStore.hpp" // YARA memory scanning
#include "../../HashStore/HashStore.hpp"      // Unpacked hash comparison
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Network IOC checking

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <atomic>
#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// Forward declarations to avoid header pollution
namespace ShadowStrike {
    namespace SignatureStore {
        class SignatureStore;
        struct DetectionResult;
    }
    namespace PatternStore {
        class PatternStore;
    }
    namespace HashStore {
        class HashStore;
    }
    namespace ThreatIntel {
        class ThreatIntelIndex;
    }
    namespace Utils {
        class ThreadPool;
        class TimerManager;
    }
}

namespace ShadowStrike {
namespace Core {
namespace Engine {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class EmulationEngine;
class EmulationPartition;
class VirtualCPU;
class VirtualMemoryManager;
class VirtualFileSystem;
class VirtualRegistry;
class VirtualNetwork;
class APIEmulator;
class UnpackerEngine;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace EmulationConstants {
    // -------------------------------------------------------------------------
    // Resource Limits
    // -------------------------------------------------------------------------
    
    /// @brief Default emulation timeout (milliseconds)
    constexpr uint32_t DEFAULT_TIMEOUT_MS = 30000;  // 30 seconds
    
    /// @brief Minimum timeout
    constexpr uint32_t MIN_TIMEOUT_MS = 1000;  // 1 second
    
    /// @brief Maximum timeout
    constexpr uint32_t MAX_TIMEOUT_MS = 300000;  // 5 minutes
    
    /// @brief Default max instructions
    constexpr uint64_t DEFAULT_MAX_INSTRUCTIONS = 100'000'000;  // 100M
    
    /// @brief Minimum instructions
    constexpr uint64_t MIN_INSTRUCTIONS = 10'000;
    
    /// @brief Maximum instructions
    constexpr uint64_t MAX_INSTRUCTIONS = 10'000'000'000;  // 10B
    
    /// @brief Default memory limit (bytes)
    constexpr size_t DEFAULT_MEMORY_LIMIT = 512 * 1024 * 1024;  // 512MB
    
    /// @brief Minimum memory limit
    constexpr size_t MIN_MEMORY_LIMIT = 64 * 1024 * 1024;  // 64MB
    
    /// @brief Maximum memory limit
    constexpr size_t MAX_MEMORY_LIMIT = 4ULL * 1024 * 1024 * 1024;  // 4GB
    
    /// @brief Default virtual disk size
    constexpr size_t DEFAULT_VDISK_SIZE = 1024 * 1024 * 1024;  // 1GB
    
    /// @brief Maximum file drops allowed
    constexpr size_t MAX_FILE_DROPS = 1000;
    
    /// @brief Maximum API calls to trace
    constexpr size_t MAX_API_TRACE = 100000;
    
    /// @brief Maximum network connections
    constexpr size_t MAX_NETWORK_CONNECTIONS = 100;
    
    // -------------------------------------------------------------------------
    // Emulation Settings
    // -------------------------------------------------------------------------
    
    /// @brief YARA scan interval (instructions)
    constexpr uint64_t YARA_SCAN_INTERVAL = 1'000'000;  // Every 1M instructions
    
    /// @brief Memory snapshot interval (instructions)
    constexpr uint64_t SNAPSHOT_INTERVAL = 10'000'000;  // Every 10M instructions
    
    /// @brief Unpack detection check interval
    constexpr uint64_t UNPACK_CHECK_INTERVAL = 100'000;  // Every 100K instructions
    
    /// @brief Maximum unpacked layers to process
    constexpr uint32_t MAX_UNPACK_LAYERS = 10;
    
    /// @brief Maximum concurrent emulation sessions
    constexpr size_t MAX_CONCURRENT_SESSIONS = 16;
    
    /// @brief Session pool size
    constexpr size_t SESSION_POOL_SIZE = 8;
    
    // -------------------------------------------------------------------------
    // Memory Layout (x64)
    // -------------------------------------------------------------------------
    
    /// @brief Default image base for 64-bit
    constexpr uint64_t DEFAULT_IMAGE_BASE_64 = 0x140000000ULL;
    
    /// @brief Default image base for 32-bit
    constexpr uint32_t DEFAULT_IMAGE_BASE_32 = 0x00400000;
    
    /// @brief Stack base address (64-bit)
    constexpr uint64_t STACK_BASE_64 = 0x7FFE0000000ULL;
    
    /// @brief Stack base address (32-bit)
    constexpr uint32_t STACK_BASE_32 = 0x7FFE0000;
    
    /// @brief Default stack size
    constexpr size_t DEFAULT_STACK_SIZE = 1 * 1024 * 1024;  // 1MB
    
    /// @brief Heap base address (64-bit)
    constexpr uint64_t HEAP_BASE_64 = 0x000001000000ULL;
    
    /// @brief Heap base address (32-bit)
    constexpr uint32_t HEAP_BASE_32 = 0x00100000;
    
    /// @brief Default heap size
    constexpr size_t DEFAULT_HEAP_SIZE = 16 * 1024 * 1024;  // 16MB
    
    /// @brief PEB address (64-bit)
    constexpr uint64_t PEB_ADDRESS_64 = 0x7FFE0000ULL;
    
    /// @brief PEB address (32-bit)
    constexpr uint32_t PEB_ADDRESS_32 = 0x7FFE0000;
    
    /// @brief TEB address (64-bit)
    constexpr uint64_t TEB_ADDRESS_64 = 0x7FFE1000ULL;
    
    /// @brief TEB address (32-bit)
    constexpr uint32_t TEB_ADDRESS_32 = 0x7FFE1000;
    
    // -------------------------------------------------------------------------
    // Detection Thresholds
    // -------------------------------------------------------------------------
    
    /// @brief Entropy threshold for packed detection
    constexpr double PACKED_ENTROPY_THRESHOLD = 7.0;
    
    /// @brief Code entropy drop threshold for unpacking detection
    constexpr double UNPACK_ENTROPY_DROP = 1.5;
    
    /// @brief Minimum unpacked code size
    constexpr size_t MIN_UNPACKED_SIZE = 4096;
    
    /// @brief Maximum API calls per second (DoS prevention)
    constexpr uint32_t MAX_API_CALLS_PER_SECOND = 10000;
    
    /// @brief Suspicious API call count threshold
    constexpr uint32_t SUSPICIOUS_API_THRESHOLD = 100;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Emulation backend type.
 */
enum class EmulationBackend : uint8_t {
    /// @brief Automatic selection based on availability
    Auto = 0,
    
    /// @brief Windows Hypervisor Platform (hardware-accelerated)
    WHP = 1,
    
    /// @brief Hyper-V direct (requires admin)
    HyperV = 2,
    
    /// @brief Unicorn Engine (software emulation)
    Unicorn = 3,
    
    /// @brief QEMU KVM (Linux only)
    KVM = 4,
    
    /// @brief Intel HAXM
    HAXM = 5
};

/**
 * @brief Target architecture for emulation.
 */
enum class EmulationArch : uint8_t {
    /// @brief x86 32-bit
    X86 = 0,
    
    /// @brief x86-64 / AMD64
    X64 = 1,
    
    /// @brief ARM 32-bit
    ARM = 2,
    
    /// @brief ARM 64-bit (AArch64)
    ARM64 = 3
};

/**
 * @brief Emulation execution mode.
 */
enum class EmulationMode : uint8_t {
    /// @brief Full emulation with all monitoring
    Full = 0,
    
    /// @brief Fast mode (minimal monitoring)
    Fast = 1,
    
    /// @brief Unpack only mode
    UnpackOnly = 2,
    
    /// @brief API trace only mode
    TraceOnly = 3,
    
    /// @brief Debug mode (single-step)
    Debug = 4,
    
    /// @brief Shellcode analysis mode
    Shellcode = 5
};

/**
 * @brief Emulation session state.
 */
enum class EmulationState : uint8_t {
    /// @brief Not initialized
    Uninitialized = 0,
    
    /// @brief Ready to execute
    Ready = 1,
    
    /// @brief Currently running
    Running = 2,
    
    /// @brief Paused
    Paused = 3,
    
    /// @brief Completed normally
    Completed = 4,
    
    /// @brief Terminated by timeout
    Timeout = 5,
    
    /// @brief Terminated by instruction limit
    InstructionLimit = 6,
    
    /// @brief Terminated by memory limit
    MemoryLimit = 7,
    
    /// @brief Terminated by error
    Error = 8,
    
    /// @brief Terminated by detection
    Detected = 9,
    
    /// @brief Terminated by user/API
    Terminated = 10
};

/**
 * @brief Type of emulation exit/stop reason.
 */
enum class EmulationExitReason : uint8_t {
    /// @brief Unknown/unspecified
    Unknown = 0,
    
    /// @brief Normal completion (return from entry point)
    NormalExit = 1,
    
    /// @brief Timeout reached
    Timeout = 2,
    
    /// @brief Instruction limit reached
    InstructionLimit = 3,
    
    /// @brief Memory allocation limit reached
    MemoryLimit = 4,
    
    /// @brief API call limit reached
    APILimit = 5,
    
    /// @brief Malware detected by YARA/patterns
    MalwareDetected = 6,
    
    /// @brief Unpacking completed
    UnpackComplete = 7,
    
    /// @brief Breakpoint hit
    Breakpoint = 8,
    
    /// @brief Exception occurred
    Exception = 9,
    
    /// @brief Invalid instruction
    InvalidInstruction = 10,
    
    /// @brief Access violation
    AccessViolation = 11,
    
    /// @brief Privileged instruction
    PrivilegedInstruction = 12,
    
    /// @brief Anti-analysis detected
    AntiAnalysis = 13,
    
    /// @brief User termination
    UserTerminated = 14,
    
    /// @brief Internal error
    InternalError = 15
};

/**
 * @brief Category of emulated API call.
 */
enum class APICategory : uint8_t {
    /// @brief Unknown/uncategorized
    Unknown = 0,
    
    /// @brief File system operations
    FileSystem = 1,
    
    /// @brief Registry operations
    Registry = 2,
    
    /// @brief Process/thread operations
    Process = 3,
    
    /// @brief Memory operations
    Memory = 4,
    
    /// @brief Network operations
    Network = 5,
    
    /// @brief Cryptography
    Crypto = 6,
    
    /// @brief System information
    SystemInfo = 7,
    
    /// @brief User interface
    UI = 8,
    
    /// @brief Service control
    Service = 9,
    
    /// @brief Security/privileges
    Security = 10,
    
    /// @brief Synchronization
    Sync = 11,
    
    /// @brief Dynamic code
    DynamicCode = 12,
    
    /// @brief Anti-analysis
    AntiAnalysis = 13,
    
    /// @brief Evasion technique
    Evasion = 14,
    
    /// @brief Injection technique
    Injection = 15
};

/**
 * @brief Severity of API call (for threat assessment).
 */
enum class APISeverity : uint8_t {
    /// @brief Benign/normal API usage
    Benign = 0,
    
    /// @brief Low severity (common operations)
    Low = 25,
    
    /// @brief Medium severity (potentially suspicious)
    Medium = 50,
    
    /// @brief High severity (likely malicious)
    High = 75,
    
    /// @brief Critical severity (definitive indicator)
    Critical = 100
};

/**
 * @brief Type of memory region in emulation.
 */
enum class MemoryRegionType : uint8_t {
    /// @brief Unknown/unmapped
    Unknown = 0,
    
    /// @brief PE image section
    Image = 1,
    
    /// @brief Stack memory
    Stack = 2,
    
    /// @brief Heap memory
    Heap = 3,
    
    /// @brief DLL mapped memory
    DLL = 4,
    
    /// @brief Allocated via VirtualAlloc
    VirtualAlloc = 5,
    
    /// @brief Memory mapped file
    MappedFile = 6,
    
    /// @brief PEB/TEB structure
    ProcessEnvironment = 7,
    
    /// @brief Shellcode region
    Shellcode = 8
};

/**
 * @brief Known packer/protector families.
 */
enum class PackerType : uint16_t {
    /// @brief Unknown/custom packer
    Unknown = 0,
    
    // Common packers (1-99)
    UPX = 1,
    ASPack = 2,
    PECompact = 3,
    FSG = 4,
    MEW = 5,
    MPRESS = 6,
    Petite = 7,
    NsPack = 8,
    
    // Commercial protectors (100-199)
    Themida = 100,
    VMProtect = 101,
    Enigma = 102,
    Obsidium = 103,
    ExeCryptor = 104,
    Armadillo = 105,
    ASProtect = 106,
    CodeVirtualizer = 107,
    
    // .NET protectors (200-249)
    ConfuserEx = 200,
    Eazfuscator = 201,
    Dotfuscator = 202,
    SmartAssembly = 203,
    Crypto_Obfuscator = 204,
    
    // Custom/malware packers (250-299)
    CustomCrypter = 250,
    MalwarePacker = 251,
    
    /// @brief Multiple layers detected
    MultiLayer = 300,
    
    /// @brief Reserved
    Reserved = 65534,
    
    /// @brief Not packed
    None = 65535
};

/**
 * @brief Get string representation of emulation backend.
 */
[[nodiscard]] constexpr const char* EmulationBackendToString(EmulationBackend backend) noexcept {
    switch (backend) {
        case EmulationBackend::Auto:    return "Auto";
        case EmulationBackend::WHP:     return "Windows Hypervisor Platform";
        case EmulationBackend::HyperV:  return "Hyper-V";
        case EmulationBackend::Unicorn: return "Unicorn Engine";
        case EmulationBackend::KVM:     return "KVM";
        case EmulationBackend::HAXM:    return "Intel HAXM";
        default:                        return "Unknown";
    }
}

/**
 * @brief Get string representation of emulation state.
 */
[[nodiscard]] constexpr const char* EmulationStateToString(EmulationState state) noexcept {
    switch (state) {
        case EmulationState::Uninitialized:     return "Uninitialized";
        case EmulationState::Ready:             return "Ready";
        case EmulationState::Running:           return "Running";
        case EmulationState::Paused:            return "Paused";
        case EmulationState::Completed:         return "Completed";
        case EmulationState::Timeout:           return "Timeout";
        case EmulationState::InstructionLimit:  return "Instruction Limit";
        case EmulationState::MemoryLimit:       return "Memory Limit";
        case EmulationState::Error:             return "Error";
        case EmulationState::Detected:          return "Detected";
        case EmulationState::Terminated:        return "Terminated";
        default:                                return "Unknown";
    }
}

/**
 * @brief Get string representation of packer type.
 */
[[nodiscard]] constexpr const char* PackerTypeToString(PackerType packer) noexcept {
    switch (packer) {
        case PackerType::Unknown:           return "Unknown Packer";
        case PackerType::UPX:               return "UPX";
        case PackerType::ASPack:            return "ASPack";
        case PackerType::PECompact:         return "PECompact";
        case PackerType::FSG:               return "FSG";
        case PackerType::MEW:               return "MEW";
        case PackerType::MPRESS:            return "MPRESS";
        case PackerType::Petite:            return "Petite";
        case PackerType::NsPack:            return "NsPack";
        case PackerType::Themida:           return "Themida/WinLicense";
        case PackerType::VMProtect:         return "VMProtect";
        case PackerType::Enigma:            return "Enigma Protector";
        case PackerType::Obsidium:          return "Obsidium";
        case PackerType::ExeCryptor:        return "ExeCryptor";
        case PackerType::Armadillo:         return "Armadillo";
        case PackerType::ASProtect:         return "ASProtect";
        case PackerType::CodeVirtualizer:   return "Code Virtualizer";
        case PackerType::ConfuserEx:        return "ConfuserEx";
        case PackerType::Eazfuscator:       return "Eazfuscator.NET";
        case PackerType::Dotfuscator:       return "Dotfuscator";
        case PackerType::SmartAssembly:     return "SmartAssembly";
        case PackerType::Crypto_Obfuscator: return "Crypto Obfuscator";
        case PackerType::CustomCrypter:     return "Custom Crypter";
        case PackerType::MalwarePacker:     return "Malware Packer";
        case PackerType::MultiLayer:        return "Multi-Layer Protection";
        case PackerType::None:              return "Not Packed";
        default:                            return "Unknown";
    }
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief CPU register state for x86/x64.
 */
struct alignas(64) CPUState {
    // General purpose registers (x64)
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
    uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    
    // Instruction pointer and flags
    uint64_t rip = 0;
    uint64_t rflags = 0;
    
    // Segment registers
    uint16_t cs = 0, ds = 0, es = 0, fs = 0, gs = 0, ss = 0;
    
    // Control registers
    uint64_t cr0 = 0, cr2 = 0, cr3 = 0, cr4 = 0;
    
    // Debug registers
    uint64_t dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0;
    uint64_t dr6 = 0, dr7 = 0;
    
    // FPU state (simplified)
    bool fpuInitialized = false;
    std::array<uint8_t, 512> fpuState{};  // FXSAVE format
    
    // SSE/AVX state
    std::array<std::array<uint8_t, 32>, 16> xmmRegisters{};  // XMM0-XMM15
    
    // Architecture flag
    EmulationArch arch = EmulationArch::X64;
    
    /**
     * @brief Get 32-bit register value.
     */
    [[nodiscard]] uint32_t GetReg32(const std::string& name) const noexcept;
    
    /**
     * @brief Get 64-bit register value.
     */
    [[nodiscard]] uint64_t GetReg64(const std::string& name) const noexcept;
    
    /**
     * @brief Set register value.
     */
    void SetReg(const std::string& name, uint64_t value) noexcept;
    
    /**
     * @brief Convert to string for debugging.
     */
    [[nodiscard]] std::string ToString() const;
};

/**
 * @brief Memory region descriptor.
 */
struct MemoryRegion {
    /// @brief Base address
    uint64_t baseAddress = 0;
    
    /// @brief Region size
    size_t size = 0;
    
    /// @brief Region type
    MemoryRegionType type = MemoryRegionType::Unknown;
    
    /// @brief Protection flags (PAGE_*)
    uint32_t protection = 0;
    
    /// @brief Is readable
    bool readable = false;
    
    /// @brief Is writable
    bool writable = false;
    
    /// @brief Is executable
    bool executable = false;
    
    /// @brief Is committed
    bool committed = false;
    
    /// @brief Associated file/module name
    std::wstring associatedName;
    
    /// @brief Calculated entropy
    double entropy = 0.0;
    
    /// @brief Whether region has been modified
    bool dirty = false;
    
    /// @brief Allocation timestamp
    std::chrono::steady_clock::time_point allocTime{};
};

/**
 * @brief Emulated API call record.
 */
struct APICallRecord {
    /// @brief Timestamp
    std::chrono::steady_clock::time_point timestamp{};
    
    /// @brief Instruction pointer at call
    uint64_t callerAddress = 0;
    
    /// @brief Return address
    uint64_t returnAddress = 0;
    
    /// @brief DLL name
    std::string dllName;
    
    /// @brief Function name
    std::string functionName;
    
    /// @brief API category
    APICategory category = APICategory::Unknown;
    
    /// @brief Severity assessment
    APISeverity severity = APISeverity::Benign;
    
    /// @brief Function arguments (as strings)
    std::vector<std::string> arguments;
    
    /// @brief Return value
    uint64_t returnValue = 0;
    
    /// @brief Whether call succeeded
    bool success = true;
    
    /// @brief Additional notes/analysis
    std::string notes;
    
    /// @brief Instruction count at call time
    uint64_t instructionCount = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
};

/**
 * @brief Dropped file record.
 */
struct DroppedFile {
    /// @brief Virtual path where file was created
    std::wstring virtualPath;
    
    /// @brief File content
    std::vector<uint8_t> content;
    
    /// @brief SHA256 hash
    std::string sha256;
    
    /// @brief MD5 hash
    std::string md5;
    
    /// @brief File size
    size_t size = 0;
    
    /// @brief Detected file type
    std::string fileType;
    
    /// @brief Whether file is executable
    bool isExecutable = false;
    
    /// @brief Whether file is a script
    bool isScript = false;
    
    /// @brief Entropy
    double entropy = 0.0;
    
    /// @brief Creation timestamp
    std::chrono::steady_clock::time_point createTime{};
    
    /// @brief Creating API call
    std::string creatingAPI;
    
    /// @brief YARA matches on this file
    std::vector<std::string> yaraMatches;
    
    /// @brief Whether file is suspicious
    bool isSuspicious = false;
};

/**
 * @brief Registry modification record.
 */
struct RegistryModification {
    /// @brief Operation type
    enum class Operation : uint8_t {
        CreateKey,
        DeleteKey,
        SetValue,
        DeleteValue,
        QueryValue,
        EnumKey,
        EnumValue
    } operation = Operation::QueryValue;
    
    /// @brief Registry key path
    std::wstring keyPath;
    
    /// @brief Value name (for value operations)
    std::wstring valueName;
    
    /// @brief Value type (REG_SZ, REG_DWORD, etc.)
    uint32_t valueType = 0;
    
    /// @brief Value data (as bytes)
    std::vector<uint8_t> valueData;
    
    /// @brief Whether operation succeeded
    bool success = false;
    
    /// @brief Timestamp
    std::chrono::steady_clock::time_point timestamp{};
    
    /// @brief Persistence indicator
    bool isPersistenceAttempt = false;
    
    /// @brief Notes
    std::string notes;
};

/**
 * @brief Network activity record.
 */
struct NetworkActivity {
    /// @brief Activity type
    enum class Type : uint8_t {
        DNSQuery,
        TCPConnect,
        TCPListen,
        UDPSend,
        UDPReceive,
        HTTPRequest,
        HTTPSRequest,
        IRCConnect,
        SMTPSend,
        Unknown
    } type = Type::Unknown;
    
    /// @brief Destination hostname/domain
    std::string hostname;
    
    /// @brief Destination IP address
    std::string ipAddress;
    
    /// @brief Destination port
    uint16_t port = 0;
    
    /// @brief Protocol
    std::string protocol;
    
    /// @brief Request data (for HTTP, etc.)
    std::vector<uint8_t> requestData;
    
    /// @brief Response data (simulated)
    std::vector<uint8_t> responseData;
    
    /// @brief HTTP method (GET, POST, etc.)
    std::string httpMethod;
    
    /// @brief HTTP URL path
    std::string urlPath;
    
    /// @brief HTTP headers
    std::unordered_map<std::string, std::string> httpHeaders;
    
    /// @brief User-Agent string
    std::string userAgent;
    
    /// @brief Timestamp
    std::chrono::steady_clock::time_point timestamp{};
    
    /// @brief Whether connection succeeded (simulated)
    bool success = false;
    
    /// @brief ThreatIntel IOC match
    bool iocMatch = false;
    
    /// @brief C2 indicator
    bool isC2Indicator = false;
    
    /// @brief Notes
    std::string notes;
};

/**
 * @brief Unpacking result for a single layer.
 */
struct UnpackLayer {
    /// @brief Layer number (0 = original)
    uint32_t layerNumber = 0;
    
    /// @brief Detected packer
    PackerType packerType = PackerType::Unknown;
    
    /// @brief Packer version (if detected)
    std::string packerVersion;
    
    /// @brief Entry point before unpacking
    uint64_t originalEntryPoint = 0;
    
    /// @brief Entry point after unpacking (OEP)
    uint64_t unpackedEntryPoint = 0;
    
    /// @brief Unpacked code base address
    uint64_t unpackedBase = 0;
    
    /// @brief Unpacked code size
    size_t unpackedSize = 0;
    
    /// @brief Unpacked code data
    std::vector<uint8_t> unpackedData;
    
    /// @brief SHA256 of unpacked data
    std::string sha256;
    
    /// @brief Entropy before unpacking
    double entropyBefore = 0.0;
    
    /// @brief Entropy after unpacking
    double entropyAfter = 0.0;
    
    /// @brief Instructions executed for this layer
    uint64_t instructionsExecuted = 0;
    
    /// @brief Time to unpack (milliseconds)
    uint64_t unpackTimeMs = 0;
    
    /// @brief Confidence in OEP detection (0.0 - 1.0)
    float oepConfidence = 0.0f;
    
    /// @brief Detection method used
    std::string detectionMethod;
};

/**
 * @brief MITRE ATT&CK technique detected during emulation.
 */
struct DetectedTechnique {
    /// @brief Technique ID (e.g., "T1055")
    std::string techniqueId;
    
    /// @brief Technique name
    std::string techniqueName;
    
    /// @brief Tactic (e.g., "Execution", "Defense Evasion")
    std::string tactic;
    
    /// @brief Confidence (0.0 - 1.0)
    float confidence = 0.0f;
    
    /// @brief Evidence/description
    std::string evidence;
    
    /// @brief Associated API calls
    std::vector<std::string> relatedAPIs;
    
    /// @brief Detection timestamp
    std::chrono::steady_clock::time_point detectionTime{};
};

/**
 * @brief Complete emulation result.
 */
struct EmulationResult {
    // -------------------------------------------------------------------------
    // Detection Status
    // -------------------------------------------------------------------------
    
    /// @brief Whether malicious behavior was detected
    bool isMalicious = false;
    
    /// @brief Malice/threat score (0.0 - 100.0)
    float threatScore = 0.0f;
    
    /// @brief Confidence in verdict (0.0 - 1.0)
    float confidence = 0.0f;
    
    /// @brief Primary threat name (if detected)
    std::string threatName;
    
    /// @brief Threat family
    std::string threatFamily;
    
    /// @brief Threat category
    std::string threatCategory;
    
    // -------------------------------------------------------------------------
    // Emulation Status
    // -------------------------------------------------------------------------
    
    /// @brief Final emulation state
    EmulationState state = EmulationState::Uninitialized;
    
    /// @brief Exit reason
    EmulationExitReason exitReason = EmulationExitReason::Unknown;
    
    /// @brief Backend used
    EmulationBackend backend = EmulationBackend::Auto;
    
    /// @brief Architecture emulated
    EmulationArch architecture = EmulationArch::X64;
    
    /// @brief Emulation completed successfully
    bool emulationComplete = false;
    
    /// @brief Error message (if failed)
    std::wstring errorMessage;
    
    // -------------------------------------------------------------------------
    // Execution Statistics
    // -------------------------------------------------------------------------
    
    /// @brief Total instructions executed
    uint64_t instructionsExecuted = 0;
    
    /// @brief Total emulation time (milliseconds)
    uint64_t emulationTimeMs = 0;
    
    /// @brief Instructions per second achieved
    double instructionsPerSecond = 0.0;
    
    /// @brief Peak memory usage (bytes)
    size_t peakMemoryUsage = 0;
    
    /// @brief Number of context switches
    uint64_t contextSwitches = 0;
    
    /// @brief Number of exceptions handled
    uint32_t exceptionsHandled = 0;
    
    // -------------------------------------------------------------------------
    // API Activity
    // -------------------------------------------------------------------------
    
    /// @brief Total API calls traced
    size_t apiCallCount = 0;
    
    /// @brief Unique API functions called
    size_t uniqueAPIsCount = 0;
    
    /// @brief API call trace (may be truncated)
    std::vector<APICallRecord> apiCalls;
    
    /// @brief Suspicious API calls identified
    std::vector<APICallRecord> suspiciousAPIs;
    
    /// @brief API call summary by category
    std::unordered_map<APICategory, uint32_t> apiSummary;
    
    // -------------------------------------------------------------------------
    // File System Activity
    // -------------------------------------------------------------------------
    
    /// @brief Files dropped/created
    std::vector<DroppedFile> droppedFiles;
    
    /// @brief Files deleted
    std::vector<std::wstring> deletedFiles;
    
    /// @brief Files modified
    std::vector<std::wstring> modifiedFiles;
    
    /// @brief Files read
    std::vector<std::wstring> filesRead;
    
    // -------------------------------------------------------------------------
    // Registry Activity
    // -------------------------------------------------------------------------
    
    /// @brief Registry modifications
    std::vector<RegistryModification> registryModifications;
    
    /// @brief Persistence attempts detected
    std::vector<RegistryModification> persistenceAttempts;
    
    // -------------------------------------------------------------------------
    // Network Activity
    // -------------------------------------------------------------------------
    
    /// @brief Network activities
    std::vector<NetworkActivity> networkActivities;
    
    /// @brief Unique domains contacted
    std::unordered_set<std::string> domainsContacted;
    
    /// @brief Unique IPs contacted
    std::unordered_set<std::string> ipsContacted;
    
    /// @brief C2 indicators
    std::vector<NetworkActivity> c2Indicators;
    
    // -------------------------------------------------------------------------
    // Unpacking Results
    // -------------------------------------------------------------------------
    
    /// @brief Whether sample was packed
    bool wasPacked = false;
    
    /// @brief Detected packer(s)
    std::vector<PackerType> detectedPackers;
    
    /// @brief Primary packer name
    std::string packerName;
    
    /// @brief Unpacking layers
    std::vector<UnpackLayer> unpackLayers;
    
    /// @brief Final unpacked payload
    std::vector<uint8_t> unpackedPayload;
    
    /// @brief SHA256 of unpacked payload
    std::string unpackedSha256;
    
    /// @brief Whether unpacking was successful
    bool unpackSuccessful = false;
    
    // -------------------------------------------------------------------------
    // YARA/Signature Matches
    // -------------------------------------------------------------------------
    
    /// @brief YARA rule matches
    std::vector<std::string> yaraMatches;
    
    /// @brief Memory-based YARA matches
    std::vector<std::string> memoryYaraMatches;
    
    /// @brief Pattern matches (from PatternStore)
    std::vector<std::string> patternMatches;
    
    // -------------------------------------------------------------------------
    // MITRE ATT&CK Mapping
    // -------------------------------------------------------------------------
    
    /// @brief Detected techniques
    std::vector<DetectedTechnique> mitreTechniques;
    
    /// @brief Primary tactic
    std::string primaryTactic;
    
    // -------------------------------------------------------------------------
    // Process Activity
    // -------------------------------------------------------------------------
    
    /// @brief Processes created (attempted)
    std::vector<std::wstring> processesCreated;
    
    /// @brief Process injection attempts
    std::vector<std::string> injectionAttempts;
    
    /// @brief Threads created
    uint32_t threadsCreated = 0;
    
    // -------------------------------------------------------------------------
    // Memory Analysis
    // -------------------------------------------------------------------------
    
    /// @brief Memory regions at exit
    std::vector<MemoryRegion> memoryRegions;
    
    /// @brief Suspicious memory regions
    std::vector<MemoryRegion> suspiciousRegions;
    
    /// @brief RWX regions detected
    std::vector<MemoryRegion> rwxRegions;
    
    /// @brief Final CPU state
    std::optional<CPUState> finalCpuState;
    
    // -------------------------------------------------------------------------
    // Evasion Detection
    // -------------------------------------------------------------------------
    
    /// @brief Anti-analysis techniques detected
    std::vector<std::string> antiAnalysisTechniques;
    
    /// @brief VM detection attempts
    uint32_t vmDetectionAttempts = 0;
    
    /// @brief Debugger detection attempts
    uint32_t debuggerDetectionAttempts = 0;
    
    /// @brief Sandbox detection attempts
    uint32_t sandboxDetectionAttempts = 0;
    
    /// @brief Timing check attempts
    uint32_t timingCheckAttempts = 0;
    
    // -------------------------------------------------------------------------
    // Metadata
    // -------------------------------------------------------------------------
    
    /// @brief Session ID
    uint64_t sessionId = 0;
    
    /// @brief Start time
    std::chrono::system_clock::time_point startTime{};
    
    /// @brief End time
    std::chrono::system_clock::time_point endTime{};
    
    /// @brief Input file SHA256
    std::string inputSha256;
    
    /// @brief Input file size
    size_t inputSize = 0;
    
    /// @brief Input file type
    std::string inputFileType;
    
    // -------------------------------------------------------------------------
    // Utility Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Get summary string.
     */
    [[nodiscard]] std::wstring GetSummary() const;
    
    /**
     * @brief Check if any suspicious activity detected.
     */
    [[nodiscard]] bool HasSuspiciousActivity() const noexcept {
        return isMalicious || wasPacked || !suspiciousAPIs.empty() ||
               !droppedFiles.empty() || !persistenceAttempts.empty() ||
               !c2Indicators.empty() || !antiAnalysisTechniques.empty();
    }
    
    /**
     * @brief Get highest severity API call.
     */
    [[nodiscard]] std::optional<APICallRecord> GetHighestSeverityAPI() const;
    
    /**
     * @brief Clear all data.
     */
    void Clear() noexcept;
};

/**
 * @brief Configuration for emulation session.
 */
struct EmulationConfig {
    // -------------------------------------------------------------------------
    // Backend Selection
    // -------------------------------------------------------------------------
    
    /// @brief Preferred backend
    EmulationBackend preferredBackend = EmulationBackend::Auto;
    
    /// @brief Allow fallback to software emulation
    bool allowFallback = true;
    
    // -------------------------------------------------------------------------
    // Resource Limits
    // -------------------------------------------------------------------------
    
    /// @brief Execution timeout (milliseconds)
    uint32_t timeoutMs = EmulationConstants::DEFAULT_TIMEOUT_MS;
    
    /// @brief Maximum instructions to execute
    uint64_t maxInstructions = EmulationConstants::DEFAULT_MAX_INSTRUCTIONS;
    
    /// @brief Memory limit (bytes)
    size_t memoryLimit = EmulationConstants::DEFAULT_MEMORY_LIMIT;
    
    /// @brief Maximum API calls to trace
    size_t maxAPICalls = EmulationConstants::MAX_API_TRACE;
    
    /// @brief Maximum files to capture
    size_t maxFileDrops = EmulationConstants::MAX_FILE_DROPS;
    
    /// @brief Maximum network connections
    size_t maxNetworkConnections = EmulationConstants::MAX_NETWORK_CONNECTIONS;
    
    // -------------------------------------------------------------------------
    // Emulation Mode
    // -------------------------------------------------------------------------
    
    /// @brief Emulation mode
    EmulationMode mode = EmulationMode::Full;
    
    /// @brief Target architecture (Auto = detect from input)
    EmulationArch targetArch = EmulationArch::X64;
    
    /// @brief Force 32-bit emulation for 64-bit capable files
    bool force32Bit = false;
    
    // -------------------------------------------------------------------------
    // Analysis Features
    // -------------------------------------------------------------------------
    
    /// @brief Enable automatic unpacking
    bool enableUnpacking = true;
    
    /// @brief Maximum unpack layers
    uint32_t maxUnpackLayers = EmulationConstants::MAX_UNPACK_LAYERS;
    
    /// @brief Enable API tracing
    bool enableAPITracing = true;
    
    /// @brief Enable detailed API arguments
    bool traceAPIArguments = true;
    
    /// @brief Enable file system monitoring
    bool enableFileSystemMonitoring = true;
    
    /// @brief Capture dropped files
    bool captureDroppedFiles = true;
    
    /// @brief Enable registry monitoring
    bool enableRegistryMonitoring = true;
    
    /// @brief Enable network monitoring
    bool enableNetworkMonitoring = true;
    
    /// @brief Enable memory scanning (YARA)
    bool enableMemoryScanning = true;
    
    /// @brief YARA scan interval (instructions)
    uint64_t yaraScanInterval = EmulationConstants::YARA_SCAN_INTERVAL;
    
    /// @brief Enable MITRE ATT&CK mapping
    bool enableMitreMapping = true;
    
    // -------------------------------------------------------------------------
    // Anti-Evasion
    // -------------------------------------------------------------------------
    
    /// @brief Enable anti-evasion countermeasures
    bool enableAntiEvasion = true;
    
    /// @brief Hook timing APIs
    bool hookTimingAPIs = true;
    
    /// @brief Simulate human interaction
    bool simulateHumanInteraction = false;
    
    /// @brief Provide realistic environment
    bool realisticEnvironment = true;
    
    /// @brief Hide emulation artifacts
    bool hideEmulationArtifacts = true;
    
    // -------------------------------------------------------------------------
    // Network Simulation
    // -------------------------------------------------------------------------
    
    /// @brief Simulate network connectivity
    bool simulateNetwork = true;
    
    /// @brief Simulate DNS resolution
    bool simulateDNS = true;
    
    /// @brief Simulate HTTP responses
    bool simulateHTTP = true;
    
    /// @brief DNS resolution results (domain -> IP)
    std::unordered_map<std::string, std::string> dnsOverrides;
    
    // -------------------------------------------------------------------------
    // Debugging
    // -------------------------------------------------------------------------
    
    /// @brief Enable debug logging
    bool debugLogging = false;
    
    /// @brief Enable instruction tracing
    bool instructionTracing = false;
    
    /// @brief Instruction trace limit
    uint64_t instructionTraceLimit = 10000;
    
    /// @brief Enable memory access tracing
    bool memoryAccessTracing = false;
    
    /// @brief Set breakpoints at addresses
    std::vector<uint64_t> breakpoints;
    
    // -------------------------------------------------------------------------
    // Output
    // -------------------------------------------------------------------------
    
    /// @brief Save unpacked payload
    bool saveUnpackedPayload = true;
    
    /// @brief Save dropped files
    bool saveDroppedFiles = true;
    
    /// @brief Maximum payload size to save (bytes)
    size_t maxPayloadSaveSize = 100 * 1024 * 1024;  // 100MB
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static EmulationConfig CreateDefault() noexcept {
        return EmulationConfig{};
    }
    
    /**
     * @brief Create fast/minimal configuration.
     */
    [[nodiscard]] static EmulationConfig CreateFast() noexcept {
        EmulationConfig config;
        config.timeoutMs = 5000;
        config.maxInstructions = 10'000'000;
        config.enableMemoryScanning = false;
        config.traceAPIArguments = false;
        config.captureDroppedFiles = false;
        config.enableMitreMapping = false;
        return config;
    }
    
    /**
     * @brief Create unpack-only configuration.
     */
    [[nodiscard]] static EmulationConfig CreateUnpackOnly() noexcept {
        EmulationConfig config;
        config.mode = EmulationMode::UnpackOnly;
        config.enableUnpacking = true;
        config.enableAPITracing = false;
        config.enableNetworkMonitoring = false;
        config.enableRegistryMonitoring = false;
        return config;
    }
    
    /**
     * @brief Create debug configuration.
     */
    [[nodiscard]] static EmulationConfig CreateDebug() noexcept {
        EmulationConfig config;
        config.mode = EmulationMode::Debug;
        config.debugLogging = true;
        config.instructionTracing = true;
        config.memoryAccessTracing = true;
        config.timeoutMs = 300000;  // 5 minutes
        return config;
    }
    
    /**
     * @brief Create shellcode analysis configuration.
     */
    [[nodiscard]] static EmulationConfig CreateShellcode() noexcept {
        EmulationConfig config;
        config.mode = EmulationMode::Shellcode;
        config.maxInstructions = 1'000'000;  // 1M
        config.timeoutMs = 10000;  // 10s
        config.enableUnpacking = false;
        return config;
    }
};

/**
 * @brief Emulation session handle.
 */
struct EmulationSession {
    /// @brief Unique session ID
    uint64_t sessionId = 0;
    
    /// @brief Current state
    std::atomic<EmulationState> state{ EmulationState::Uninitialized };
    
    /// @brief Configuration
    EmulationConfig config;
    
    /// @brief Start time
    std::chrono::steady_clock::time_point startTime{};
    
    /// @brief Current instruction count
    std::atomic<uint64_t> instructionCount{ 0 };
    
    /// @brief Current API call count
    std::atomic<size_t> apiCallCount{ 0 };
    
    /// @brief Backend being used
    EmulationBackend activeBackend = EmulationBackend::Auto;
};

/**
 * @brief Statistics for emulation engine.
 */
struct EmulationStats {
    /// @brief Total sessions created
    std::atomic<uint64_t> totalSessions{ 0 };
    
    /// @brief Successful completions
    std::atomic<uint64_t> successfulCompletions{ 0 };
    
    /// @brief Timeout terminations
    std::atomic<uint64_t> timeouts{ 0 };
    
    /// @brief Error terminations
    std::atomic<uint64_t> errors{ 0 };
    
    /// @brief Malware detections
    std::atomic<uint64_t> malwareDetections{ 0 };
    
    /// @brief Successful unpacks
    std::atomic<uint64_t> successfulUnpacks{ 0 };
    
    /// @brief Total instructions executed
    std::atomic<uint64_t> totalInstructions{ 0 };
    
    /// @brief Total API calls traced
    std::atomic<uint64_t> totalAPICalls{ 0 };
    
    /// @brief Total files captured
    std::atomic<uint64_t> totalFilesCaptured{ 0 };
    
    /// @brief Currently active sessions
    std::atomic<size_t> activeSessions{ 0 };
    
    /// @brief Average emulation time (microseconds)
    std::atomic<uint64_t> avgEmulationTimeUs{ 0 };
    
    /// @brief WHP backend available
    bool whpAvailable = false;
    
    /// @brief Unicorn backend available
    bool unicornAvailable = false;
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalSessions.store(0, std::memory_order_relaxed);
        successfulCompletions.store(0, std::memory_order_relaxed);
        timeouts.store(0, std::memory_order_relaxed);
        errors.store(0, std::memory_order_relaxed);
        malwareDetections.store(0, std::memory_order_relaxed);
        successfulUnpacks.store(0, std::memory_order_relaxed);
        totalInstructions.store(0, std::memory_order_relaxed);
        totalAPICalls.store(0, std::memory_order_relaxed);
        totalFilesCaptured.store(0, std::memory_order_relaxed);
        activeSessions.store(0, std::memory_order_relaxed);
        avgEmulationTimeUs.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types for emulation events.
 */
using EmulationCompleteCallback = std::function<void(const EmulationResult&)>;
using APICallCallback = std::function<void(const APICallRecord&)>;
using FileDropCallback = std::function<void(const DroppedFile&)>;
using NetworkActivityCallback = std::function<void(const NetworkActivity&)>;
using UnpackLayerCallback = std::function<void(const UnpackLayer&)>;
using InstructionCallback = std::function<bool(uint64_t address, const uint8_t* bytes, size_t size)>;

// ============================================================================
// MAIN EMULATION ENGINE CLASS
// ============================================================================

/**
 * @brief Enterprise-grade code emulation engine using Windows Hypervisor Platform.
 *
 * Provides hardware-accelerated code emulation for safe execution and analysis
 * of potentially malicious code. Uses Hyper-V/WHP for near-native performance
 * with complete isolation.
 *
 * Thread Safety: All public methods are thread-safe. Multiple emulation sessions
 * can run concurrently up to MAX_CONCURRENT_SESSIONS.
 *
 * Usage Example:
 * @code
 * auto& engine = EmulationEngine::Instance();
 * 
 * // Initialize with thread pool
 * engine.Initialize(threadPool);
 * 
 * // Configure emulation
 * EmulationConfig config = EmulationConfig::CreateDefault();
 * config.timeoutMs = 10000;
 * config.enableUnpacking = true;
 * 
 * // Emulate a PE file
 * std::vector<uint8_t> peData = LoadFile("suspect.exe");
 * auto result = engine.EmulatePE(peData, config);
 * 
 * if (result.isMalicious) {
 *     LOG_WARN(L"Malware detected: {} (score: {})", 
 *              result.threatName, result.threatScore);
 * }
 * 
 * if (result.wasPacked && result.unpackSuccessful) {
 *     LOG_INFO(L"Unpacked payload SHA256: {}", result.unpackedSha256);
 *     // Scan unpacked payload with signature engine
 * }
 * 
 * // Emulate shellcode
 * auto shellcodeResult = engine.EmulateShellcode(shellcode, true);
 * 
 * engine.Shutdown();
 * @endcode
 */
class EmulationEngine {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global EmulationEngine instance.
     * @note Thread-safe (Meyers' singleton).
     */
    [[nodiscard]] static EmulationEngine& Instance();

    // Non-copyable, non-movable
    EmulationEngine(const EmulationEngine&) = delete;
    EmulationEngine& operator=(const EmulationEngine&) = delete;
    EmulationEngine(EmulationEngine&&) = delete;
    EmulationEngine& operator=(EmulationEngine&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the emulation engine.
     * @param threadPool Thread pool for async operations.
     * @return true on success.
     * @note Detects available backends (WHP, Unicorn) automatically.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with external store references.
     * @param threadPool Thread pool.
     * @param signatureStore For YARA scanning.
     * @param patternStore For packer detection.
     * @param hashStore For hash comparison.
     * @param threatIntel For IOC correlation.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        SignatureStore::SignatureStore* signatureStore,
        PatternStore::PatternStore* patternStore,
        HashStore::HashStore* hashStore,
        ThreatIntel::ThreatIntelIndex* threatIntel
    );

    /**
     * @brief Shutdown the engine and release all resources.
     * @note Terminates any active emulation sessions.
     */
    void Shutdown();

    /**
     * @brief Check if engine is initialized and ready.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Check if hardware acceleration is available.
     */
    [[nodiscard]] bool IsHardwareAccelerationAvailable() const noexcept;

    /**
     * @brief Get available backends.
     */
    [[nodiscard]] std::vector<EmulationBackend> GetAvailableBackends() const;

    // =========================================================================
    // PE Emulation
    // =========================================================================

    /**
     * @brief Emulate a PE (Portable Executable) file.
     * @param fileData Raw PE file bytes.
     * @param config Emulation configuration (default if not specified).
     * @return Complete emulation result.
     */
    [[nodiscard]] EmulationResult EmulatePE(
        const std::vector<uint8_t>& fileData,
        const EmulationConfig& config = EmulationConfig::CreateDefault()
    );

    /**
     * @brief Emulate a PE file (span version).
     */
    [[nodiscard]] EmulationResult EmulatePE(
        std::span<const uint8_t> fileData,
        const EmulationConfig& config = EmulationConfig::CreateDefault()
    );

    /**
     * @brief Emulate a PE file asynchronously.
     * @param fileData Raw PE file bytes.
     * @param config Emulation configuration.
     * @param callback Callback invoked when emulation completes.
     * @return Session ID (0 on failure).
     */
    [[nodiscard]] uint64_t EmulatePEAsync(
        std::vector<uint8_t> fileData,
        const EmulationConfig& config,
        EmulationCompleteCallback callback
    );

    /**
     * @brief Emulate a PE file with legacy parameters (compatibility).
     */
    [[nodiscard]] EmulationResult EmulatePE(
        const std::vector<uint8_t>& fileData,
        uint32_t timeoutMs,
        uint64_t maxInstructions
    );

    // =========================================================================
    // Shellcode Emulation
    // =========================================================================

    /**
     * @brief Emulate raw shellcode.
     * @param code Shellcode bytes.
     * @param is64Bit Whether shellcode is 64-bit.
     * @param config Emulation configuration.
     * @return Emulation result.
     */
    [[nodiscard]] EmulationResult EmulateShellcode(
        const std::vector<uint8_t>& code,
        bool is64Bit,
        const EmulationConfig& config = EmulationConfig::CreateShellcode()
    );

    /**
     * @brief Emulate shellcode (span version).
     */
    [[nodiscard]] EmulationResult EmulateShellcode(
        std::span<const uint8_t> code,
        bool is64Bit,
        const EmulationConfig& config = EmulationConfig::CreateShellcode()
    );

    /**
     * @brief Emulate shellcode asynchronously.
     */
    [[nodiscard]] uint64_t EmulateShellcodeAsync(
        std::vector<uint8_t> code,
        bool is64Bit,
        const EmulationConfig& config,
        EmulationCompleteCallback callback
    );

    // =========================================================================
    // Memory Buffer Emulation
    // =========================================================================

    /**
     * @brief Emulate a memory buffer at specified address.
     * @param buffer Code buffer.
     * @param baseAddress Virtual address to load at.
     * @param entryPoint Entry point offset.
     * @param arch Target architecture.
     * @param config Configuration.
     * @return Emulation result.
     */
    [[nodiscard]] EmulationResult EmulateBuffer(
        std::span<const uint8_t> buffer,
        uint64_t baseAddress,
        uint64_t entryPoint,
        EmulationArch arch,
        const EmulationConfig& config = EmulationConfig::CreateDefault()
    );

    // =========================================================================
    // Unpacking
    // =========================================================================

    /**
     * @brief Attempt to unpack a packed executable.
     * @param fileData Packed PE file.
     * @param config Configuration (unpacking settings).
     * @return Result with unpacked payload if successful.
     */
    [[nodiscard]] EmulationResult UnpackPE(
        const std::vector<uint8_t>& fileData,
        const EmulationConfig& config = EmulationConfig::CreateUnpackOnly()
    );

    /**
     * @brief Detect packer without full unpacking.
     * @param fileData PE file data.
     * @return Detected packer type.
     */
    [[nodiscard]] PackerType DetectPacker(const std::vector<uint8_t>& fileData);

    /**
     * @brief Detect packer with details.
     * @param fileData PE file data.
     * @return Pair of (packer type, packer version string).
     */
    [[nodiscard]] std::pair<PackerType, std::string> DetectPackerDetailed(
        const std::vector<uint8_t>& fileData
    );

    // =========================================================================
    // Session Management
    // =========================================================================

    /**
     * @brief Get active session count.
     */
    [[nodiscard]] size_t GetActiveSessionCount() const noexcept;

    /**
     * @brief Get session by ID.
     * @param sessionId Session identifier.
     * @return Session info or nullopt if not found.
     */
    [[nodiscard]] std::optional<EmulationSession> GetSession(uint64_t sessionId) const;

    /**
     * @brief Terminate a running session.
     * @param sessionId Session to terminate.
     * @return true if session was found and terminated.
     */
    bool TerminateSession(uint64_t sessionId);

    /**
     * @brief Terminate all active sessions.
     */
    void TerminateAllSessions();

    /**
     * @brief Pause a running session.
     */
    bool PauseSession(uint64_t sessionId);

    /**
     * @brief Resume a paused session.
     */
    bool ResumeSession(uint64_t sessionId);

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register callback for API calls.
     * @param callback Function called for each API call.
     * @return Registration ID.
     */
    [[nodiscard]] uint64_t RegisterAPICallback(APICallCallback callback);

    /**
     * @brief Unregister API callback.
     */
    bool UnregisterAPICallback(uint64_t callbackId);

    /**
     * @brief Register callback for file drops.
     */
    [[nodiscard]] uint64_t RegisterFileDropCallback(FileDropCallback callback);

    /**
     * @brief Unregister file drop callback.
     */
    bool UnregisterFileDropCallback(uint64_t callbackId);

    /**
     * @brief Register callback for network activity.
     */
    [[nodiscard]] uint64_t RegisterNetworkCallback(NetworkActivityCallback callback);

    /**
     * @brief Unregister network callback.
     */
    bool UnregisterNetworkCallback(uint64_t callbackId);

    /**
     * @brief Register callback for unpack layers.
     */
    [[nodiscard]] uint64_t RegisterUnpackCallback(UnpackLayerCallback callback);

    /**
     * @brief Unregister unpack callback.
     */
    bool UnregisterUnpackCallback(uint64_t callbackId);

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get engine statistics.
     */
    [[nodiscard]] EmulationStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Configuration
    // =========================================================================

    /**
     * @brief Set default configuration for new sessions.
     */
    void SetDefaultConfig(const EmulationConfig& config);

    /**
     * @brief Get default configuration.
     */
    [[nodiscard]] EmulationConfig GetDefaultConfig() const;

    /**
     * @brief Set store references after initialization.
     */
    void SetSignatureStore(SignatureStore::SignatureStore* store);
    void SetPatternStore(PatternStore::PatternStore* store);
    void SetHashStore(HashStore::HashStore* store);
    void SetThreatIntelIndex(ThreatIntel::ThreatIntelIndex* index);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    EmulationEngine();
    ~EmulationEngine();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Detect and initialize available backends.
     */
    void DetectBackends();

    /**
     * @brief Setup virtual Windows environment.
     */
    void SetupVirtualEnvironment(EmulationSession& session);

    /**
     * @brief Mock file system for emulation.
     */
    void MockFileSystem(EmulationSession& session);

    /**
     * @brief Mock registry for emulation.
     */
    void MockRegistry(EmulationSession& session);

    /**
     * @brief Mock network for emulation.
     */
    void MockNetwork(EmulationSession& session);

    /**
     * @brief Handle API call during emulation.
     */
    void OnApiCall(
        EmulationSession& session,
        const std::string& dll,
        const std::string& func,
        const std::vector<uint64_t>& args
    );

    /**
     * @brief Handle memory access during emulation.
     */
    void OnMemoryAccess(
        EmulationSession& session,
        uint64_t address,
        size_t size,
        bool isWrite
    );

    /**
     * @brief Handle instruction execution.
     */
    bool OnInstruction(
        EmulationSession& session,
        uint64_t address,
        const uint8_t* bytes,
        size_t size
    );

    /**
     * @brief Perform YARA scan on emulated memory.
     */
    void ScanMemoryWithYara(EmulationSession& session, EmulationResult& result);

    /**
     * @brief Check for unpacking completion.
     */
    bool CheckUnpackCompletion(EmulationSession& session, EmulationResult& result);

    /**
     * @brief Calculate threat score from emulation results.
     */
    void CalculateThreatScore(EmulationResult& result);

    /**
     * @brief Add MITRE ATT&CK mappings.
     */
    void AddMitreMappings(EmulationResult& result);

    /**
     * @brief Create new session.
     */
    [[nodiscard]] uint64_t CreateSession(const EmulationConfig& config);

    /**
     * @brief Destroy session.
     */
    void DestroySession(uint64_t sessionId);

    /**
     * @brief Invoke API callbacks.
     */
    void InvokeAPICallbacks(const APICallRecord& record);

    /**
     * @brief Invoke file drop callbacks.
     */
    void InvokeFileDropCallbacks(const DroppedFile& file);

    /**
     * @brief Invoke network callbacks.
     */
    void InvokeNetworkCallbacks(const NetworkActivity& activity);

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Check if Windows Hypervisor Platform is available.
 * @return true if WHP can be used.
 */
[[nodiscard]] bool IsWHPAvailable() noexcept;

/**
 * @brief Check if Hyper-V is enabled.
 * @return true if Hyper-V is enabled and accessible.
 */
[[nodiscard]] bool IsHyperVEnabled() noexcept;

/**
 * @brief Check if running with required privileges for WHP.
 * @return true if privileges are sufficient.
 */
[[nodiscard]] bool HasWHPPrivileges() noexcept;

/**
 * @brief Calculate Shannon entropy of data.
 * @param data Data buffer.
 * @param size Data size.
 * @return Entropy value (0.0 - 8.0).
 */
[[nodiscard]] double CalculateEntropy(const uint8_t* data, size_t size) noexcept;

/**
 * @brief Detect if PE file is likely packed.
 * @param peData PE file data.
 * @return true if packing indicators found.
 */
[[nodiscard]] bool IsPELikelyPacked(std::span<const uint8_t> peData) noexcept;

/**
 * @brief Get Original Entry Point (OEP) heuristically.
 * @param memoryDump Memory dump after emulation.
 * @param imageBase Image base address.
 * @return Suspected OEP or 0 if not found.
 */
[[nodiscard]] uint64_t DetectOEP(
    std::span<const uint8_t> memoryDump,
    uint64_t imageBase
) noexcept;

/**
 * @brief Categorize API call.
 * @param dllName DLL name.
 * @param funcName Function name.
 * @return API category.
 */
[[nodiscard]] APICategory CategorizeAPI(
    std::string_view dllName,
    std::string_view funcName
) noexcept;

/**
 * @brief Assess API call severity.
 * @param dllName DLL name.
 * @param funcName Function name.
 * @param args Function arguments (as strings).
 * @return Severity assessment.
 */
[[nodiscard]] APISeverity AssessAPISeverity(
    std::string_view dllName,
    std::string_view funcName,
    const std::vector<std::string>& args
) noexcept;

} // namespace Engine
} // namespace Core
} // namespace ShadowStrike
