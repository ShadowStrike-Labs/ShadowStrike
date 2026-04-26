/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * VMAntiEvasion.cpp — VM/sandbox detection bypass
 *
 * Maintains exhaustive blocklists of VM-specific files, registry keys,
 * processes, drivers, MAC address OUI prefixes, and device names.
 * Every query returns the "bare-metal" answer, while every check
 * attempt is recorded as a behavioral IOC.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "VMAntiEvasion.hpp"
#include "EnvironmentAntiEvasion.hpp"
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <limits>
#include <mutex>
#include <new>
#include <stdexcept>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// Static blocklists
// ============================================================================

namespace {

constexpr size_t kMaxTrackedTechniqueChars = 256;
constexpr size_t kMaxMatcherInputChars = 32768;

// ---- VM File Blocklist (~40 entries) ----
constexpr const wchar_t* kVMFiles[] = {
    // VirtualBox
    L"VBoxGuest.sys",      L"VBoxMouse.sys",     L"VBoxSF.sys",
    L"VBoxVideo.sys",      L"VBoxTray.exe",      L"VBoxService.exe",
    L"VBoxControl.exe",    L"VBoxDisp.dll",      L"VBoxHook.dll",
    L"VBoxMRXNP.dll",      L"VBoxOGL.dll",       L"VBoxOGLcrutil.dll",
    // VMware
    L"vmci.sys",           L"vmhgfs.sys",        L"vmmouse.sys",
    L"vmtools.exe",        L"vmtoolsd.exe",      L"vmwaretray.exe",
    L"vmwareuser.exe",     L"vm3dmp.sys",        L"vmGuestLib.dll",
    L"vmhgfs.dll",         L"vmmemctl.sys",      L"vmx86.sys",
    // QEMU / KVM
    L"qemu-ga.exe",        L"qga.exe",
    L"virtio-win.sys",     L"vioscsi.sys",       L"viostor.sys",
    L"netkvm.sys",         L"balloon.sys",
    // Xen
    L"xennet.sys",         L"xennet6.sys",       L"xenvif.sys",
    L"xenbus.sys",         L"xeniface.sys",      L"xenvbd.sys",
    // Parallels
    L"prl_tools.exe",      L"prl_cc.exe",        L"SharedIntApp.exe",
    L"prleth.sys",         L"prlfs.sys",         L"prlmouse.sys",
    // Sandboxie
    L"SandboxieDll.dll",   L"SandboxieRpcSs.exe", L"SbieDll.dll",
    // Analysis sandboxes
    L"cwsandbox.exe",      L"joesandbox.exe",    L"fakeprocess.exe",
};

// ---- VM Registry Key Blocklist (~30 entries) ----
constexpr const wchar_t* kVMRegistryKeys[] = {
    // VirtualBox
    L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    L"HARDWARE\\ACPI\\DSDT\\VBOX__",
    L"HARDWARE\\ACPI\\FADT\\VBOX__",
    L"HARDWARE\\ACPI\\RSDT\\VBOX__",
    L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
    L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
    L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
    L"SYSTEM\\CurrentControlSet\\Services\\VBoxService",
    L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
    // VMware
    L"SOFTWARE\\VMware, Inc.\\VMware Tools",
    L"SYSTEM\\CurrentControlSet\\Services\\vmci",
    L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
    L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
    L"SYSTEM\\CurrentControlSet\\Services\\vmtools",
    L"SYSTEM\\CurrentControlSet\\Services\\VMMEMCTL",
    L"SYSTEM\\CurrentControlSet\\Services\\vmx86",
    // QEMU
    L"SYSTEM\\CurrentControlSet\\Services\\vioscsi",
    L"SYSTEM\\CurrentControlSet\\Services\\viostor",
    L"SYSTEM\\CurrentControlSet\\Services\\netkvm",
    L"SYSTEM\\CurrentControlSet\\Services\\balloon",
    // Xen
    L"SYSTEM\\CurrentControlSet\\Services\\xenbus",
    L"SYSTEM\\CurrentControlSet\\Services\\xennet",
    L"SYSTEM\\CurrentControlSet\\Services\\xenvif",
    L"SYSTEM\\CurrentControlSet\\Services\\xeniface",
    // Parallels
    L"SYSTEM\\CurrentControlSet\\Services\\prl_boot",
    L"SYSTEM\\CurrentControlSet\\Services\\prl_fs",
    L"SYSTEM\\CurrentControlSet\\Services\\prl_memdev",
    // Wine
    L"SOFTWARE\\Wine",
    // Identifier keys (checked for VBOX/VMWARE/QEMU substrings)
    L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
    L"SYSTEM\\CurrentControlSet\\Enum\\IDE",
    L"SYSTEM\\CurrentControlSet\\Enum\\SCSI",
};

// ---- VM Process Blocklist (~25 entries) ----
constexpr const wchar_t* kVMProcesses[] = {
    // VirtualBox
    L"vboxservice.exe",    L"vboxtray.exe",
    // VMware
    L"vmtoolsd.exe",       L"vmwaretray.exe",    L"vmwareuser.exe",
    // QEMU
    L"qemu-ga.exe",
    // Xen
    L"xenservice.exe",
    // Parallels
    L"prl_tools.exe",      L"prl_cc.exe",
    // Sandbox environments
    L"joeboxcontrol.exe",  L"joeboxserver.exe",
    L"cuckoo.exe",         L"cuckoomon.exe",
    // Sandboxie
    L"sbiesvc.exe",        L"sbiectrl.exe",
    // Analysis tools (often running in sandbox VMs)
    L"procmon.exe",        L"procexp.exe",       L"processhacker.exe",
    L"wireshark.exe",      L"fiddler.exe",       L"dumpcap.exe",
    L"windump.exe",        L"pestudio.exe",      L"peview.exe",
    L"lordpe.exe",         L"die.exe",
};

// ---- VM Driver Blocklist ----
constexpr const wchar_t* kVMDrivers[] = {
    // VirtualBox
    L"VBoxGuest",   L"VBoxMouse",  L"VBoxSF",    L"VBoxVideo",
    // VMware
    L"vmci",        L"vmhgfs",     L"vmmouse",   L"vmx86",
    L"vm3dmp",      L"VMMEMCTL",   L"vmrawdsk",
    // QEMU / Virtio
    L"vioscsi",     L"viostor",    L"netkvm",    L"balloon",
    // Xen
    L"xenbus",      L"xennet",     L"xennet6",   L"xenvif",  L"xenvbd",
    // Parallels
    L"prl_boot",    L"prl_fs",     L"prl_eth",   L"prl_memdev",
};

// ---- VM MAC Address OUI Prefixes (3-byte prefixes) ----
struct MACPrefix {
    uint8_t bytes[3];
};

constexpr MACPrefix kVMMACPrefixes[] = {
    { { 0x08, 0x00, 0x27 } }, // VirtualBox
    { { 0x00, 0x0C, 0x29 } }, // VMware
    { { 0x00, 0x50, 0x56 } }, // VMware
    { { 0x00, 0x05, 0x69 } }, // VMware
    { { 0x00, 0x1C, 0x14 } }, // VMware
    { { 0x00, 0x1C, 0x42 } }, // Parallels
    { { 0x00, 0x16, 0x3E } }, // Xen
    { { 0x52, 0x54, 0x00 } }, // QEMU/KVM
};

// ---- VM Device Name Blocklist ----
constexpr const wchar_t* kVMDeviceNames[] = {
    L"\\\\.\\VBoxMiniRdrDN",
    L"\\\\.\\VBoxGuest",
    L"\\\\.\\VBoxTrayIPC",
    L"\\\\.\\pipe\\VBoxMiniRdDN",
    L"\\\\.\\pipe\\VBoxTrayIPC",
    L"\\\\.\\vmci",
    L"\\\\.\\hgfs",
    L"\\\\.\\vmx86",
    L"\\\\.\\Global\\vmx86",
    L"\\\\.\\SICE",       // SoftICE
    L"\\\\.\\NTICE",      // SoftICE
    L"\\\\.\\REGVXG",     // Regmon
    L"\\\\.\\FILEVXG",    // Filemon
    L"\\\\.\\TRW",        // TRW debugger
};

// Case-insensitive wide char to lower
[[nodiscard]] constexpr wchar_t WToLower(wchar_t c) noexcept {
    if (c >= L'A' && c <= L'Z') return c + (L'a' - L'A');
    return c;
}

// Case-insensitive wide string compare
[[nodiscard]] bool WideStringEqualsCaseInsensitive(
    std::wstring_view a, std::wstring_view b) noexcept
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (WToLower(a[i]) != WToLower(b[i])) return false;
    }
    return true;
}

[[nodiscard]] bool IsReasonableWideText(std::wstring_view text) noexcept {
    if (text.size() > kMaxMatcherInputChars) return false;
    for (const wchar_t ch : text) {
        if (ch == L'\0') return false;
    }
    return true;
}

[[nodiscard]] bool IsReasonableTechnique(std::string_view text) noexcept {
    if (text.empty() || text.size() > kMaxTrackedTechniqueChars) return false;
    for (const char ch : text) {
        const auto value = static_cast<unsigned char>(ch);
        if (value < 0x20 || value == 0x7F) return false;
    }
    return true;
}

void SaturatingIncrement(std::atomic<uint32_t>& counter) noexcept {
    uint32_t current = counter.load(std::memory_order_relaxed);
    while (current != std::numeric_limits<uint32_t>::max()) {
        if (counter.compare_exchange_weak(
                current, current + 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
            return;
        }
    }
}

} // anonymous namespace

// ============================================================================
// Case-insensitive substring search helper
// ============================================================================

bool VMAntiEvasion::WideStringContainsCaseInsensitive(
    std::wstring_view haystack, std::wstring_view needle) noexcept
{
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;

    const size_t limit = haystack.size() - needle.size() + 1;
    for (size_t i = 0; i < limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (WToLower(haystack[i + j]) != WToLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// ============================================================================
// Singleton
// ============================================================================

VMAntiEvasion& VMAntiEvasion::Instance() noexcept {
    static VMAntiEvasion instance;
    return instance;
}

// ============================================================================
// Initialize / Reset
// ============================================================================

void VMAntiEvasion::Initialize(const EmulationConfig& /*config*/) noexcept {
    try {
        std::unique_lock lock(m_mutex);
        if (m_initialized) return;
        m_detectedTechniques.clear();
        m_detectedTechniques.reserve(64);
        m_vmCheckCount.store(0, std::memory_order_relaxed);
        m_initialized = true;
    } catch (const std::bad_alloc&) {
        Reset();
    } catch (const std::length_error&) {
        Reset();
    }
}

void VMAntiEvasion::Reset() noexcept {
    std::unique_lock lock(m_mutex);
    m_detectedTechniques.clear();
    m_vmCheckCount.store(0, std::memory_order_relaxed);
    m_initialized = false;
}

// ============================================================================
// Evasion tracking
// ============================================================================

void VMAntiEvasion::RecordVMCheckAttempt(std::string_view technique) noexcept {
    if (!IsReasonableTechnique(technique)) return;
    SaturatingIncrement(m_vmCheckCount);

    try {
    std::unique_lock lock(m_mutex);
    if (m_detectedTechniques.size() < kMaxTrackedTechniques) {
        m_detectedTechniques.emplace_back(technique);
    }
    } catch (const std::bad_alloc&) {
        return;
    } catch (const std::length_error&) {
        return;
    }
}

uint32_t VMAntiEvasion::GetVMCheckCount() const noexcept {
    return m_vmCheckCount.load(std::memory_order_relaxed);
}

std::vector<std::string> VMAntiEvasion::GetDetectedTechniques() const noexcept {
    try {
    std::shared_lock lock(m_mutex);
    return m_detectedTechniques;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

// ============================================================================
// CPUID-based checks
// ============================================================================

bool VMAntiEvasion::HasHypervisorBit() const noexcept {
    // CPUID leaf 1, ECX bit 31 — MUST be 0
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "CPUID.HypervisorBit");
    return false;
}

std::string VMAntiEvasion::GetCPUVendor() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "CPUID.Vendor");
    return "GenuineIntel";
}

std::string VMAntiEvasion::GetCPUBrandString() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "CPUID.BrandString");
    return "Intel(R) Core(TM) i7-12700H";
}

// ============================================================================
// Registry-based checks
// ============================================================================

bool VMAntiEvasion::HasVMRegistryKeys() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Registry.VMKeys");
    return false;
}

std::vector<std::wstring> VMAntiEvasion::GetSafeRegistryKeys() const noexcept {
    // Return common registry keys that a real system would have
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Registry.SafeKeys");

    try {
    return {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"SOFTWARE\\Intel\\Display",
        L"SOFTWARE\\NVIDIA Corporation\\Global",
        L"SYSTEM\\CurrentControlSet\\Services\\disk",
        L"SYSTEM\\CurrentControlSet\\Services\\intelppm",
    };
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

// ============================================================================
// File system checks
// ============================================================================

bool VMAntiEvasion::HasVMFiles() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "FileSystem.VMFiles");
    return false;
}

bool VMAntiEvasion::HasVMDrivers() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "FileSystem.VMDrivers");
    return false;
}

// ============================================================================
// Process checks
// ============================================================================

bool VMAntiEvasion::HasVMProcesses() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Process.VMProcesses");
    return false;
}

std::vector<std::wstring> VMAntiEvasion::GetVMProcessBlocklist() const noexcept {
    try {
    std::vector<std::wstring> result;
    result.reserve(std::size(kVMProcesses));
    for (const auto* name : kVMProcesses) {
        result.emplace_back(name);
    }
    return result;
    } catch (const std::bad_alloc&) {
        return {};
    } catch (const std::length_error&) {
        return {};
    }
}

// ============================================================================
// Hardware checks
// ============================================================================

bool VMAntiEvasion::HasVMMACAddress() const noexcept {
    // Our MAC uses Dell OUI (D4:BE:D9) — not a VM prefix
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Hardware.MACAddress");
    return false;
}

bool VMAntiEvasion::HasVMDeviceNames() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Hardware.DeviceNames");
    return false;
}

bool VMAntiEvasion::HasSmallDisk() const noexcept {
    // Emulated: 512 GB — VMs often have <80 GB
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Hardware.DiskSize");
    return false;
}

bool VMAntiEvasion::HasFewProcessors() const noexcept {
    // Emulated: 8+ cores — VMs often have 1-2
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Hardware.ProcessorCount");
    return false;
}

bool VMAntiEvasion::HasLowRAM() const noexcept {
    // Emulated: 16 GB — VMs often have 1-4 GB
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Hardware.RAM");
    return false;
}

bool VMAntiEvasion::HasLowScreenResolution() const noexcept {
    // Emulated: 1920×1080 — sandboxes often have 1024×768
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Hardware.ScreenResolution");
    return false;
}

// ============================================================================
// Firmware / SMBIOS checks
// ============================================================================

bool VMAntiEvasion::HasVMFirmware() const noexcept {
    // SMBIOS manufacturer = "Dell Inc." — not VBOX/VMware/QEMU
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Firmware.ACPI");
    return false;
}

bool VMAntiEvasion::HasVMBIOS() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Firmware.BIOS");
    return false;
}

// ============================================================================
// Red pill / blue pill techniques
// ============================================================================

bool VMAntiEvasion::RedPillCheck() const noexcept {
    // SIDT/SGDT: the "Red Pill" checks IDT/GDT base address.
    // On a VM, these are typically at high addresses (0xFF...).
    // On bare metal, they're at lower addresses.
    // We return false = "not detected as VM" (passes the check).
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "RedPill.SIDT");
    return false;
}

bool VMAntiEvasion::NoPillCheck() const noexcept {
    // "No Pill": SLDT returns 0 on bare metal, non-zero on VM.
    // We return false = "not detected as VM".
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "NoPill.SLDT");
    return false;
}

// ============================================================================
// Sandbox-specific checks
// ============================================================================

bool VMAntiEvasion::IsSandbox() const noexcept {
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Sandbox.General");
    return false;
}

bool VMAntiEvasion::HasRecentUserActivity() const noexcept {
    // Sandboxes have zero user activity. We fake a lived-in system.
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Sandbox.UserActivity");
    return true;
}

uint32_t VMAntiEvasion::GetRecentFileCount() const noexcept {
    // Documents + Desktop + Downloads on a real system = ~2000 files
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Sandbox.RecentFileCount");
    return 2147;
}

uint32_t VMAntiEvasion::GetInstalledSoftwareCount() const noexcept {
    // Add/Remove Programs entries on a real workstation
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Sandbox.InstalledSoftware");
    return 47;
}

uint32_t VMAntiEvasion::GetBrowserHistoryCount() const noexcept {
    // Realistic browsing history count
    const_cast<VMAntiEvasion*>(this)->RecordVMCheckAttempt(
        "Sandbox.BrowserHistory");
    return 523;
}

// ============================================================================
// Static blocklist matchers
// ============================================================================

bool VMAntiEvasion::IsVMFileName(std::wstring_view filename) noexcept {
    if (!IsReasonableWideText(filename)) return false;
    // Extract just the filename from a potential full path
    const auto lastSlash = filename.find_last_of(L"\\/");
    const auto baseName = (lastSlash != std::wstring_view::npos)
        ? filename.substr(lastSlash + 1)
        : filename;

    for (const auto* vmFile : kVMFiles) {
        if (WideStringEqualsCaseInsensitive(baseName, vmFile)) {
            return true;
        }
    }
    return false;
}

bool VMAntiEvasion::IsVMRegistryKey(std::wstring_view keyPath) noexcept {
    if (!IsReasonableWideText(keyPath)) return false;
    for (const auto* vmKey : kVMRegistryKeys) {
        if (WideStringContainsCaseInsensitive(keyPath, vmKey)) {
            return true;
        }
    }

    // Also check for VM vendor substrings in generic paths
    static constexpr std::wstring_view kVMSubstrings[] = {
        L"VBOX",    L"VIRTUALBOX",  L"VMWARE",   L"VMTOOLS",
        L"QEMU",    L"VIRTIO",      L"XEN",      L"PARALLELS",
        L"WINE",    L"SANDBOXIE",   L"CUCKOO",   L"JOESANDBOX",
    };

    for (const auto& sub : kVMSubstrings) {
        if (WideStringContainsCaseInsensitive(keyPath, sub)) {
            return true;
        }
    }

    return false;
}

bool VMAntiEvasion::IsVMProcessName(std::wstring_view processName) noexcept {
    if (!IsReasonableWideText(processName)) return false;
    // Extract just the process name from a potential full path
    const auto lastSlash = processName.find_last_of(L"\\/");
    const auto baseName = (lastSlash != std::wstring_view::npos)
        ? processName.substr(lastSlash + 1)
        : processName;

    for (const auto* vmProc : kVMProcesses) {
        if (WideStringEqualsCaseInsensitive(baseName, vmProc)) {
            return true;
        }
    }
    return false;
}

bool VMAntiEvasion::IsVMDriverName(std::wstring_view driverName) noexcept {
    if (!IsReasonableWideText(driverName)) return false;
    // Extract just the driver name
    const auto lastSlash = driverName.find_last_of(L"\\/");
    auto baseName = (lastSlash != std::wstring_view::npos)
        ? driverName.substr(lastSlash + 1)
        : driverName;

    // Strip .sys extension if present
    if (baseName.size() > 4) {
        auto ext = baseName.substr(baseName.size() - 4);
        if (WideStringEqualsCaseInsensitive(ext, L".sys")) {
            baseName = baseName.substr(0, baseName.size() - 4);
        }
    }

    for (const auto* vmDriver : kVMDrivers) {
        if (WideStringEqualsCaseInsensitive(baseName, vmDriver)) {
            return true;
        }
    }
    return false;
}

bool VMAntiEvasion::IsVMMACPrefix(const uint8_t mac[6]) noexcept {
    if (!mac) return false;

    for (const auto& prefix : kVMMACPrefixes) {
        if (mac[0] == prefix.bytes[0] &&
            mac[1] == prefix.bytes[1] &&
            mac[2] == prefix.bytes[2])
        {
            return true;
        }
    }
    return false;
}

bool VMAntiEvasion::IsVMDeviceName(std::wstring_view deviceName) noexcept {
    if (!IsReasonableWideText(deviceName)) return false;
    for (const auto* vmDevice : kVMDeviceNames) {
        if (WideStringEqualsCaseInsensitive(deviceName, vmDevice)) {
            return true;
        }
    }

    // Partial match: check if device name contains VM-related substrings
    static constexpr std::wstring_view kDeviceSubstrings[] = {
        L"VBox",    L"VMware",  L"QEMU",    L"Xen",
        L"virtio",  L"SICE",    L"NTICE",
    };

    for (const auto& sub : kDeviceSubstrings) {
        if (WideStringContainsCaseInsensitive(deviceName, sub)) {
            return true;
        }
    }

    return false;
}

} // namespace Phantom::VirtualOS::AntiEvasion
