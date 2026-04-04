/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * EnvironmentAntiEvasion.cpp — Hardware/system info faker
 *
 * Builds a complete, internally-consistent CPUID table matching a
 * real Intel i7-12700H (Alder Lake-H) on a Dell Precision 5570.
 * Also provides SMBIOS, MAC, disk/GPU names, and system metrics
 * that pass common VM-detection heuristics.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "EnvironmentAntiEvasion.hpp"
#include <algorithm>
#include <cstring>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// Helpers
// ============================================================================

namespace {

// Pack 4 ASCII characters into a uint32_t (little-endian register encoding)
[[nodiscard]] constexpr uint32_t PackChars(char a, char b, char c, char d) noexcept {
    return static_cast<uint32_t>(static_cast<uint8_t>(a)) |
           (static_cast<uint32_t>(static_cast<uint8_t>(b)) << 8) |
           (static_cast<uint32_t>(static_cast<uint8_t>(c)) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(d)) << 24);
}

// Dell OUI: D4:BE:D9 — NOT a VM prefix
constexpr std::array<uint8_t, 6> kDellMAC = { 0xD4, 0xBE, 0xD9, 0x3A, 0x72, 0x1F };

} // anonymous namespace

// ============================================================================
// Singleton
// ============================================================================

EnvironmentAntiEvasion& EnvironmentAntiEvasion::Instance() noexcept {
    static EnvironmentAntiEvasion instance;
    return instance;
}

// ============================================================================
// Initialize
// ============================================================================

void EnvironmentAntiEvasion::Initialize(const EmulationConfig& config) noexcept {
    if (m_initialized) return;

    m_processorCount   = config.processorCount;
    m_totalPhysicalMem = config.totalPhysicalMem;
    m_totalDiskSpace   = 512ULL * 1024 * 1024 * 1024; // 512 GB NVMe
    m_screenWidth      = 1920;
    m_screenHeight     = 1080;
    m_macAddress       = kDellMAC;

    m_computerName = config.computerName;
    m_userName     = config.userName;
    m_domainName   = config.domainName;

    BuildCPUIDTable();
    BuildSMBIOSTable();

    m_initialized = true;
}

// ============================================================================
// Reset
// ============================================================================

void EnvironmentAntiEvasion::Reset() noexcept {
    std::unique_lock lock(m_mutex);

    m_cpuidTable.clear();
    m_smbios = SMBIOSData{};
    m_processorCount    = 8;
    m_totalPhysicalMem  = 16ULL * 1024 * 1024 * 1024;
    m_totalDiskSpace    = 512ULL * 1024 * 1024 * 1024;
    m_screenWidth       = 1920;
    m_screenHeight      = 1080;
    m_macAddress        = {};
    m_computerName.clear();
    m_userName.clear();
    m_domainName.clear();
    m_initialized       = false;
}

// ============================================================================
// BuildCPUIDTable — Intel i7-12700H (Alder Lake-H)
// ============================================================================

void EnvironmentAntiEvasion::BuildCPUIDTable() noexcept {
    std::unique_lock lock(m_mutex);
    m_cpuidTable.clear();
    m_cpuidTable.reserve(32);

    auto add = [this](uint32_t leaf, uint32_t subleaf,
                      uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx)
    {
        m_cpuidTable.push_back({ leaf, subleaf, { eax, ebx, ecx, edx } });
    };

    // ---- Leaf 0x00: Vendor string "GenuineIntel" ----
    // EBX:EDX:ECX = "Genu" "ineI" "ntel"
    add(0x00, 0,
        0x16,                          // max basic leaf
        0x756E6547,                    // "Genu"
        0x6C65746E,                    // "ntel"
        0x49656E69);                   // "ineI"

    // ---- Leaf 0x01: Version/Feature info ----
    // Family 6, Model 0x9A (Alder Lake), Stepping 3
    // EAX: Stepping=3, Model=0xA, Family=6, ExtModel=0x9
    //      = 0x0009'0A63  →  stepping 3, model nibble A, family 6, ext model 9
    //      Full encoding: (ExtFamily<<20)|(ExtModel<<16)|(Type<<12)|(Family<<8)|(Model<<4)|Stepping
    //      = (0<<20)|(9<<16)|(0<<12)|(6<<8)|(0xA<<4)|3 = 0x000906A3
    const uint32_t leaf1_eax = 0x000906A3;

    // EBX: Brand=0, CLFLUSH line=8 (×8=64B), MaxLogical=20, Initial APIC ID=0
    const uint32_t leaf1_ebx = (0 << 24) | (20 << 16) | (8 << 8) | 0;

    // ECX: Feature flags — Alder Lake features
    // CRITICAL: Bit 31 (hypervisor) MUST be 0
    const uint32_t leaf1_ecx =
        (1u << 0)  | // SSE3
        (1u << 1)  | // PCLMULQDQ
        (1u << 2)  | // DTES64
        (1u << 3)  | // MONITOR
        (1u << 4)  | // DS-CPL
        (1u << 5)  | // VMX (host VMX, NOT hypervisor present)
        (1u << 9)  | // SSSE3
        (1u << 12) | // FMA
        (1u << 13) | // CMPXCHG16B
        (1u << 14) | // xTPR
        (1u << 15) | // PDCM
        (1u << 17) | // PCID
        (1u << 19) | // SSE4.1
        (1u << 20) | // SSE4.2
        (1u << 21) | // x2APIC
        (1u << 22) | // MOVBE
        (1u << 23) | // POPCNT
        (1u << 25) | // AES-NI
        (1u << 26) | // XSAVE
        (1u << 27) | // OSXSAVE
        (1u << 28) | // AVX
        (1u << 29) | // F16C
        (1u << 30);  // RDRAND
    // Bit 31 (hypervisor) = 0 — CRITICAL for VM detection bypass

    // EDX: Classic feature flags
    const uint32_t leaf1_edx =
        (1u << 0)  | // FPU
        (1u << 1)  | // VME
        (1u << 2)  | // DE
        (1u << 3)  | // PSE
        (1u << 4)  | // TSC
        (1u << 5)  | // MSR
        (1u << 6)  | // PAE
        (1u << 7)  | // MCE
        (1u << 8)  | // CX8
        (1u << 9)  | // APIC
        (1u << 11) | // SEP
        (1u << 12) | // MTRR
        (1u << 13) | // PGE
        (1u << 14) | // MCA
        (1u << 15) | // CMOV
        (1u << 16) | // PAT
        (1u << 17) | // PSE-36
        (1u << 19) | // CLFLUSH
        (1u << 21) | // DS
        (1u << 22) | // ACPI
        (1u << 23) | // MMX
        (1u << 24) | // FXSR
        (1u << 25) | // SSE
        (1u << 26) | // SSE2
        (1u << 27) | // SS
        (1u << 28) | // HTT
        (1u << 29);  // TM

    add(0x01, 0, leaf1_eax, leaf1_ebx, leaf1_ecx, leaf1_edx);

    // ---- Leaf 0x02: Cache/TLB descriptors ----
    // Realistic Intel cache descriptor encoding
    add(0x02, 0,
        0x00FEFF01,  // iterations=1, descriptors follow
        0x000000F0,
        0x00000000,
        0x00C30000);

    // ---- Leaf 0x04: Deterministic cache parameters ----
    // Subleaf 0: L1 Data — 48 KB, 12-way, 64-byte line, 64 sets
    add(0x04, 0,
        0x04004121,  // Type=1(Data), Level=1, Self-init, FullyAssoc=0
        0x01C0003F,  // LineSize=64-1=63, Partitions=0, Ways=12-1=11, encoded
        0x0000003F,  // Sets=64-1=63
        0x00000000);

    // Subleaf 1: L1 Instruction — 32 KB, 8-way, 64-byte line
    add(0x04, 1,
        0x04004122,  // Type=2(Instruction), Level=1
        0x01C0003F,  // Ways=8-1=7, LineSize=63
        0x0000003F,
        0x00000000);

    // Subleaf 2: L2 Unified — 1.25 MB, 10-way, 64-byte line
    add(0x04, 2,
        0x04004143,  // Type=3(Unified), Level=2
        0x03C0003F,  // Ways=10-1=9
        0x00000FFF,  // Sets=4096-1
        0x00000000);

    // Subleaf 3: L3 Unified — 24 MB, 16-way, 64-byte line
    add(0x04, 3,
        0x04C04163,  // Type=3(Unified), Level=3
        0x03C0003F,  // Ways=16-1=15
        0x00005FFF,  // Sets=24576-1
        0x00000004); // Complex indexing

    // Subleaf 4: End marker
    add(0x04, 4, 0x00000000, 0x00000000, 0x00000000, 0x00000000);

    // ---- Leaf 0x07: Structured Extended Feature Flags ----
    // Subleaf 0
    const uint32_t leaf7_ebx =
        (1u << 0)  | // FSGSBASE
        (1u << 2)  | // SGX
        (1u << 3)  | // BMI1
        (1u << 5)  | // AVX2
        (1u << 7)  | // SMEP
        (1u << 8)  | // BMI2
        (1u << 9)  | // ERMS
        (1u << 10) | // INVPCID
        (1u << 18) | // RDSEED
        (1u << 19) | // ADX
        (1u << 20) | // SMAP
        (1u << 24) | // CLWB
        (1u << 29);  // SHA

    const uint32_t leaf7_ecx =
        (1u << 1)  | // AVX512_VBMI (not on all Alder Lake SKUs, but common)
        (1u << 4)  | // PKU
        (1u << 22);  // RDPID

    add(0x07, 0,
        0x00000001,  // subleaf count
        leaf7_ebx,
        leaf7_ecx,
        0x00000000);

    // ---- Leaf 0x0B: Extended Topology ----
    // Subleaf 0: SMT level — 2 threads per core
    add(0x0B, 0,
        0x00000001,  // Shift count for next level (1 bit = 2 threads)
        0x00000002,  // Logical procs at this level = 2
        0x00000100,  // Level number=0, Level type=1(SMT)
        0x00000000); // x2APIC ID

    // Subleaf 1: Core level — 14 cores (20 logical = 6P×2 + 8E×1)
    add(0x0B, 1,
        0x00000005,  // Shift count
        0x00000014,  // 20 logical processors total
        0x00000201,  // Level number=1, Level type=2(Core)
        0x00000000);

    // ---- Leaf 0x15: TSC/Crystal Clock Information ----
    // TSC ratio: Core crystal = 38.4 MHz, TSC = 38.4 * ~99 ≈ 3.8 GHz
    add(0x15, 0,
        0x00000002,  // denominator
        0x000000C6,  // numerator (198)
        0x0249F000,  // crystal clock = 38,400,000 Hz
        0x00000000);

    // ---- Leaf 0x16: Processor Frequency Information ----
    add(0x16, 0,
        0x00000A8C,  // Base frequency: 2700 MHz
        0x00001258,  // Max frequency: 4700 MHz
        0x00000064,  // Bus frequency: 100 MHz
        0x00000000);

    // ---- Leaf 0x40000000: Hypervisor CPUID (MUST return 0) ----
    // If hypervisor bit (1:ECX:31) is 0, this leaf should return 0.
    // But if malware queries it anyway, return zeros.
    add(0x40000000, 0, 0, 0, 0, 0);

    // ---- Extended CPUID ----

    // Leaf 0x80000000: Max extended leaf
    add(0x80000000, 0,
        0x80000008,  // max extended leaf
        0x00000000,
        0x00000000,
        0x00000000);

    // Leaf 0x80000001: Extended feature flags
    const uint32_t ext1_ecx =
        (1u << 0)  | // LAHF/SAHF in 64-bit
        (1u << 5);   // LZCNT

    const uint32_t ext1_edx =
        (1u << 11) | // SYSCALL/SYSRET
        (1u << 20) | // NX (Execute Disable)
        (1u << 26) | // 1GB pages
        (1u << 27) | // RDTSCP
        (1u << 29);  // Intel 64 (Long Mode)

    add(0x80000001, 0,
        0x00000000,
        0x00000000,
        ext1_ecx,
        ext1_edx);

    // Leaves 0x80000002-0x80000004: Brand string
    // "Intel(R) Core(TM) i7-12700H" padded to 48 bytes
    const char brand[48] = "Intel(R) Core(TM) i7-12700H\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    auto readU32 = [](const char* p) -> uint32_t {
        uint32_t v = 0;
        std::memcpy(&v, p, 4);
        return v;
    };

    add(0x80000002, 0,
        readU32(&brand[0]),  readU32(&brand[4]),
        readU32(&brand[8]),  readU32(&brand[12]));
    add(0x80000003, 0,
        readU32(&brand[16]), readU32(&brand[20]),
        readU32(&brand[24]), readU32(&brand[28]));
    add(0x80000004, 0,
        readU32(&brand[32]), readU32(&brand[36]),
        readU32(&brand[40]), readU32(&brand[44]));

    // Leaf 0x80000006: L2 Cache info
    // 1280 KB, 20-way, 64-byte line
    add(0x80000006, 0,
        0x00000000,
        0x00000000,
        0x05006040,  // LineSize=64, Assoc=20(0x05=20-way), Size=1280KB
        0x00000000);

    // Leaf 0x80000007: Invariant TSC
    add(0x80000007, 0,
        0x00000000,
        0x00000000,
        0x00000000,
        (1u << 8)); // Invariant TSC

    // Leaf 0x80000008: Address sizes
    // Physical=46 bits, Virtual=48 bits
    add(0x80000008, 0,
        0x0000302E,  // PhysAddr=46, VirtAddr=48
        0x00000000,
        0x00000000,
        0x00000000);
}

// ============================================================================
// BuildSMBIOSTable — Dell Precision 5570
// ============================================================================

void EnvironmentAntiEvasion::BuildSMBIOSTable() noexcept {
    std::unique_lock lock(m_mutex);

    m_smbios.manufacturer = "Dell Inc.";
    m_smbios.product      = "Precision 5570";
    m_smbios.serialNumber = "7FX93K3";
    m_smbios.biosVendor   = "Dell Inc.";
    m_smbios.biosVersion  = "1.18.0";
    m_smbios.biosDate     = "03/14/2025";

    // Build a minimal but realistic raw SMBIOS entry-point + Type 0/1 tables
    // Type 0: BIOS Information
    // Type 1: System Information
    m_smbios.rawTable.clear();
    m_smbios.rawTable.reserve(256);

    // SMBIOS 3.0 Entry Point header (simplified)
    // Anchor: "_SM3_"
    const uint8_t entryPoint[] = {
        '_', 'S', 'M', '3', '_',     // anchor
        0x18,                          // checksum (placeholder)
        0x18,                          // entry point length
        0x03, 0x00,                    // major.minor version 3.0
        0x01,                          // entry point revision
        0x00,                          // reserved
        0x00, 0x01, 0x00, 0x00,       // max structure size (256)
        // 64-bit structure table address (placeholder)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    m_smbios.rawTable.insert(m_smbios.rawTable.end(),
        std::begin(entryPoint), std::end(entryPoint));

    // Type 0: BIOS Information (handle 0x0000)
    const uint8_t type0[] = {
        0x00,       // Type 0
        0x1A,       // Length (26 bytes)
        0x00, 0x00, // Handle
        0x01,       // Vendor string index
        0x02,       // BIOS Version string index
        0x00, 0xE8, // BIOS Starting Address Segment
        0x03,       // BIOS Release Date string index
        0xFF,       // BIOS ROM Size (16 MB encoded)
        // BIOS Characteristics (8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, // ext characteristics
        0x01, 0x12, // BIOS Major/Minor
        0x00, 0x00, // EC Major/Minor
        0x00, 0x00, // Extended ROM size
    };
    m_smbios.rawTable.insert(m_smbios.rawTable.end(),
        std::begin(type0), std::end(type0));

    // String table for Type 0
    auto addString = [this](const char* s) {
        while (*s) { m_smbios.rawTable.push_back(static_cast<uint8_t>(*s++)); }
        m_smbios.rawTable.push_back(0x00);
    };
    addString("Dell Inc.");    // string 1: vendor
    addString("1.18.0");       // string 2: version
    addString("03/14/2025");   // string 3: date
    m_smbios.rawTable.push_back(0x00); // double-null terminator

    // Type 1: System Information (handle 0x0001)
    const uint8_t type1[] = {
        0x01,       // Type 1
        0x1B,       // Length (27 bytes)
        0x01, 0x00, // Handle
        0x01,       // Manufacturer string index
        0x02,       // Product Name string index
        0x00,       // Version string index (none)
        0x03,       // Serial Number string index
        // UUID (random but consistent)
        0x4D, 0xA3, 0x2E, 0x7F, 0xB1, 0x09, 0x4C, 0x82,
        0x9F, 0x1A, 0x6E, 0xD4, 0x53, 0x87, 0xF2, 0xC0,
        0x06,       // Wake-up Type: Power Switch
        0x00,       // SKU Number (none)
        0x00,       // Family (none)
    };
    m_smbios.rawTable.insert(m_smbios.rawTable.end(),
        std::begin(type1), std::end(type1));

    addString("Dell Inc.");        // string 1: manufacturer
    addString("Precision 5570");   // string 2: product
    addString("7FX93K3");          // string 3: serial
    m_smbios.rawTable.push_back(0x00); // double-null terminator
}

// ============================================================================
// GetCPUID — look up the pre-built table
// ============================================================================

CPUIDResult EnvironmentAntiEvasion::GetCPUID(uint32_t leaf, uint32_t subleaf) const noexcept {
    std::shared_lock lock(m_mutex);

    // Exact leaf+subleaf match first
    for (const auto& entry : m_cpuidTable) {
        if (entry.leaf == leaf && entry.subleaf == subleaf) {
            return entry.result;
        }
    }

    // Fallback: match leaf with subleaf 0 (some callers omit subleaf)
    if (subleaf != 0) {
        for (const auto& entry : m_cpuidTable) {
            if (entry.leaf == leaf && entry.subleaf == 0) {
                return entry.result;
            }
        }
    }

    // Unknown leaf: return zeros (standard CPUID behavior)
    return { 0, 0, 0, 0 };
}

// ============================================================================
// System info accessors
// ============================================================================

uint32_t EnvironmentAntiEvasion::GetProcessorCount() const noexcept {
    return m_processorCount;
}

uint64_t EnvironmentAntiEvasion::GetTotalPhysicalMemory() const noexcept {
    return m_totalPhysicalMem;
}

uint64_t EnvironmentAntiEvasion::GetAvailablePhysicalMemory() const noexcept {
    // ~60% available (realistic for a workstation with some apps running)
    return (m_totalPhysicalMem * 60) / 100;
}

uint64_t EnvironmentAntiEvasion::GetTotalDiskSpace() const noexcept {
    return m_totalDiskSpace;
}

uint64_t EnvironmentAntiEvasion::GetFreeDiskSpace() const noexcept {
    // ~45% free (realistic for an in-use system)
    return (m_totalDiskSpace * 45) / 100;
}

uint32_t EnvironmentAntiEvasion::GetScreenWidth() const noexcept {
    return m_screenWidth;
}

uint32_t EnvironmentAntiEvasion::GetScreenHeight() const noexcept {
    return m_screenHeight;
}

// ============================================================================
// MAC address
// ============================================================================

std::array<uint8_t, 6> EnvironmentAntiEvasion::GetMACAddress() const noexcept {
    return m_macAddress;
}

// ============================================================================
// SMBIOS
// ============================================================================

const EnvironmentAntiEvasion::SMBIOSData& EnvironmentAntiEvasion::GetSMBIOS() const noexcept {
    std::shared_lock lock(m_mutex);
    return m_smbios;
}

// ============================================================================
// Device names
// ============================================================================

std::string EnvironmentAntiEvasion::GetDiskModel() const noexcept {
    return "SAMSUNG MZVL2512HCJQ-00BD1";
}

std::string EnvironmentAntiEvasion::GetGPUName() const noexcept {
    return "NVIDIA GeForce RTX 3060 Laptop GPU";
}

// ============================================================================
// Computer / User info
// ============================================================================

const std::wstring& EnvironmentAntiEvasion::GetComputerName() const noexcept {
    return m_computerName;
}

const std::wstring& EnvironmentAntiEvasion::GetUserName() const noexcept {
    return m_userName;
}

const std::wstring& EnvironmentAntiEvasion::GetDomainName() const noexcept {
    return m_domainName;
}

} // namespace Phantom::VirtualOS::AntiEvasion
