/**
 * @file VMEvasionDetector.hpp
 * @brief Enterprise-grade detection of Virtual Machine (VM) and Hypervisor environments
 *
 * ShadowStrike AntiEvasion - VM Evasion Detection Module
 * Copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 *
 * ============================================================================
 * OVERVIEW
 * ============================================================================
 *
 * This module provides comprehensive detection of virtualization environments
 * and anti-VM techniques used by malware to evade security analysis. It detects
 * 100+ distinct VM indicators across multiple detection vectors including:
 *
 * - CPUID-based detection (hypervisor brand string, feature flags, leaf values)
 * - Registry artifacts (VM-specific keys, driver entries, service registrations)
 * - File system artifacts (drivers, executables, configuration files)
 * - Network indicators (MAC OUI prefixes, virtual adapter characteristics)
 * - Hardware fingerprinting (DMI/SMBIOS, ACPI tables, firmware signatures)
 * - Process/Service enumeration (VM tools, guest additions, hypervisor agents)
 * - Memory artifacts (BIOS/ROM strings, mapped firmware regions)
 * - Timing-based detection (VM exit latency, instruction timing anomalies)
 * - I/O port probing (VM-specific I/O ports for backdoor communication)
 * - Device enumeration (PCI/USB device IDs, SCSI controller strings)
 * - WMI queries (ComputerSystem model/manufacturer, BIOS serial numbers)
 * - Anti-analysis behavioral patterns (malware's own VM detection attempts)
 *
 * Supported Hypervisors and Virtualization Technologies:
 * - VMware (Workstation, Fusion, ESXi, vSphere)
 * - VirtualBox (Oracle VM VirtualBox)
 * - Microsoft Hyper-V (Client, Server, Azure)
 * - QEMU/KVM (Kernel-based Virtual Machine)
 * - Xen (Citrix Hypervisor, XenServer)
 * - Parallels Desktop
 * - Bochs emulator
 * - Wine (Windows compatibility layer)
 * - Sandboxie (Application sandboxing)
 * - Docker/WSL2 containers
 * - Amazon EC2 / Google Cloud / Azure VMs
 * - Generic hypervisor detection
 *
 * ============================================================================
 * PERFORMANCE TARGETS
 * ============================================================================
 *
 * - Quick check (CPUID only): < 1ms
 * - Standard detection: < 50ms for full system scan
 * - Deep analysis: < 200ms with all optional checks enabled
 * - Process behavior analysis: < 20ms per process
 * - Batch process analysis (100 processes): < 1 second
 * - Memory region scan: < 100ms per 64MB scanned
 *
 * ============================================================================
 * INTEGRATION POINTS
 * ============================================================================
 *
 * - Utils::SystemUtils - CPUID queries, system information, firmware access
 * - Utils::RegistryUtils - Registry key enumeration and value reading
 * - Utils::FileUtils - Driver and executable existence checks
 * - Utils::NetworkUtils - Network adapter MAC address enumeration
 * - Utils::ProcessUtils - Process/thread enumeration, module listing
 * - Utils::MemoryUtils - Memory region scanning for VM artifacts
 * - Utils::Logger - Structured async logging with performance metrics
 * - ThreatIntel::ThreatIntelStore - Known VM artifact correlation
 * - SignatureStore::SignatureStore - Anti-VM code pattern matching
 *
 * ============================================================================
 * MITRE ATT&CK COVERAGE
 * ============================================================================
 *
 * - T1497: Virtualization/Sandbox Evasion
 * - T1497.001: System Checks (VM detection)
 * - T1082: System Information Discovery
 * - T1016: System Network Configuration Discovery
 * - T1057: Process Discovery
 * - T1012: Query Registry
 * - T1083: File and Directory Discovery
 *
 * ============================================================================
 * USAGE EXAMPLE
 * ============================================================================
 *
 * @code
 *   // Quick detection with default configuration
 *   VMEvasionDetector detector;
 *   auto result = detector.DetectEnvironment();
 *   if (result.isVM) {
 *       SS_LOG_WARN(L"VMDetector", L"Running in %ls (confidence: %.1f%%)",
 *                   detector.VMTypeToString(result.detectedType).c_str(),
 *                   result.confidenceScore);
 *   }
 *
 *   // Custom configuration for deep analysis
 *   VMDetectionConfig config = VMDetectionConfig::CreateDeepAnalysis();
 *   config.enableTimingChecks = true;
 *   config.enableIOPortProbing = true;
 *   VMEvasionDetector deepDetector(nullptr, config);
 *   auto deepResult = deepDetector.DetectEnvironment();
 *
 *   // Analyze a specific process for anti-VM behavior
 *   ProcessVMEvasionResult procResult;
 *   if (detector.AnalyzeProcessAntiVMBehavior(targetPid, procResult)) {
 *       for (const auto& technique : procResult.detectedTechniques) {
 *           SS_LOG_INFO(L"VMDetector", L"Process uses anti-VM technique: %ls",
 *                       technique.description.c_str());
 *       }
 *   }
 * @endcode
 *
 * ============================================================================
 */

#pragma once

 // ============================================================================
 // STANDARD LIBRARY INCLUDES
 // ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <bitset>
#include <span>
#include <variant>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <intrin.h>
#  pragma intrinsic(__cpuid)
#  pragma intrinsic(__cpuidex)
#  pragma intrinsic(__rdtsc)
#endif

// ============================================================================
// SHADOWSTRIKE INTERNAL INCLUDES
// ============================================================================

#include "../Utils/RegistryUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/MemoryUtils.hpp"
#include "../Utils/Logger.hpp"

// Forward declarations to avoid circular dependencies
namespace ShadowStrike::SignatureStore {
    class SignatureStore;
}

namespace ShadowStrike::ThreatIntel {
    class ThreatIntelStore;
}

namespace ShadowStrike::PEParser {
    class PEParser;
    struct PEInfo;
    struct ImportInfo;
    struct SectionInfo;
}

namespace ShadowStrike {
    namespace AntiEvasion {

        // ============================================================================
        // CONSTANTS
        // ============================================================================

        namespace VMConstants {

            /// @brief Maximum artifacts to collect per detection category
            inline constexpr size_t MAX_ARTIFACTS_PER_CATEGORY = 256;

            /// @brief Maximum total artifacts to report
            inline constexpr size_t MAX_TOTAL_ARTIFACTS = 1024;

            /// @brief Maximum processes to scan for VM tools
            inline constexpr size_t MAX_PROCESSES_TO_SCAN = 4096;

            /// @brief Maximum network adapters to check
            inline constexpr size_t MAX_ADAPTERS_TO_CHECK = 64;

            /// @brief Maximum registry keys to enumerate
            inline constexpr size_t MAX_REGISTRY_KEYS = 512;

            /// @brief Default scan timeout in milliseconds
            inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 30000;

            /// @brief Quick scan timeout in milliseconds
            inline constexpr uint32_t QUICK_SCAN_TIMEOUT_MS = 5000;

            /// @brief Cache entry TTL for detection results (seconds)
            inline constexpr uint32_t RESULT_CACHE_TTL_SECONDS = 300;

            /// @brief Maximum cache entries
            inline constexpr size_t MAX_CACHE_ENTRIES = 128;

            /// @brief High confidence threshold (0-100)
            inline constexpr float HIGH_CONFIDENCE_THRESHOLD = 75.0f;

            /// @brief Medium confidence threshold (0-100)
            inline constexpr float MEDIUM_CONFIDENCE_THRESHOLD = 50.0f;

            /// @brief Low confidence threshold (0-100)
            inline constexpr float LOW_CONFIDENCE_THRESHOLD = 25.0f;

            /// @brief Weight multipliers for different detection categories
            inline constexpr float WEIGHT_CPUID = 3.0f;
            inline constexpr float WEIGHT_REGISTRY = 2.0f;
            inline constexpr float WEIGHT_FILESYSTEM = 2.0f;
            inline constexpr float WEIGHT_NETWORK = 1.5f;
            inline constexpr float WEIGHT_FIRMWARE = 3.5f;
            inline constexpr float WEIGHT_PROCESS = 2.0f;
            inline constexpr float WEIGHT_TIMING = 2.5f;
            inline constexpr float WEIGHT_IOPORT = 3.0f;
            inline constexpr float WEIGHT_MEMORY = 2.0f;
            inline constexpr float WEIGHT_DEVICE = 2.5f;
            inline constexpr float WEIGHT_WMI = 2.0f;

            /// @brief CPUID leaf for hypervisor vendor string
            inline constexpr uint32_t CPUID_HYPERVISOR_VENDOR = 0x40000000;

            /// @brief CPUID leaf for hypervisor interface signature
            inline constexpr uint32_t CPUID_HYPERVISOR_INTERFACE = 0x40000001;

            /// @brief CPUID leaf for hypervisor features
            inline constexpr uint32_t CPUID_HYPERVISOR_FEATURES = 0x40000003;

            /// @brief CPUID leaf for processor features (hypervisor bit is bit 31 of ECX)
            inline constexpr uint32_t CPUID_PROCESSOR_FEATURES = 0x00000001;

            /// @brief Hypervisor present bit in CPUID leaf 1 ECX
            inline constexpr uint32_t CPUID_HYPERVISOR_BIT = (1U << 31);

            /// @brief VMware I/O port for backdoor communication
            inline constexpr uint16_t VMWARE_IO_PORT = 0x5658;

            /// @brief VMware magic value for backdoor protocol
            inline constexpr uint32_t VMWARE_MAGIC = 0x564D5868;  // "VMXh"

            /// @brief VirtualBox I/O port range start
            inline constexpr uint16_t VBOX_IO_PORT_START = 0x4042;

            // -------------------------------------------------------------------------
            // Known Hypervisor Vendor Strings (CPUID 0x40000000 EBX+ECX+EDX)
            // -------------------------------------------------------------------------

            /// @brief VMware hypervisor vendor string
            inline constexpr std::string_view VENDOR_VMWARE = "VMwareVMware";

            /// @brief Microsoft Hyper-V vendor string
            inline constexpr std::string_view VENDOR_HYPERV = "Microsoft Hv";

            /// @brief VirtualBox vendor string
            inline constexpr std::string_view VENDOR_VBOX = "VBoxVBoxVBox";

            /// @brief Xen hypervisor vendor string
            inline constexpr std::string_view VENDOR_XEN = "XenVMMXenVMM";

            /// @brief KVM vendor string
            inline constexpr std::string_view VENDOR_KVM = "KVMKVMKVM\0\0\0";

            /// @brief QEMU vendor string (when running without KVM)
            inline constexpr std::string_view VENDOR_QEMU = "TCGTCGTCGTCG";

            /// @brief Parallels vendor string
            inline constexpr std::string_view VENDOR_PARALLELS = " lrpepyh  vr";

            /// @brief Bhyve vendor string (FreeBSD hypervisor)
            inline constexpr std::string_view VENDOR_BHYVE = "bhyve bhyve ";

            /// @brief ACRN hypervisor vendor string
            inline constexpr std::string_view VENDOR_ACRN = "ACRNACRNACRN";

            /// @brief QNX hypervisor vendor string
            inline constexpr std::string_view VENDOR_QNX = "QNXQVMBSQG\0\0";

            // -------------------------------------------------------------------------
            // Known VM-related MAC OUI Prefixes (first 3 bytes)
            // -------------------------------------------------------------------------

            /// @brief VMware MAC OUI prefixes
            inline constexpr std::array<std::array<uint8_t, 3>, 5> VMWARE_MAC_OUIS = { {
                {{ 0x00, 0x05, 0x69 }},
                {{ 0x00, 0x0C, 0x29 }},
                {{ 0x00, 0x1C, 0x14 }},
                {{ 0x00, 0x50, 0x56 }},
                {{ 0x00, 0x1C, 0x42 }}
            } };

            /// @brief VirtualBox MAC OUI prefix
            inline constexpr std::array<uint8_t, 3> VBOX_MAC_OUI = { { 0x08, 0x00, 0x27 } };

            /// @brief Microsoft Hyper-V MAC OUI prefix
            inline constexpr std::array<uint8_t, 3> HYPERV_MAC_OUI = { { 0x00, 0x15, 0x5D } };

            /// @brief Parallels MAC OUI prefix
            inline constexpr std::array<uint8_t, 3> PARALLELS_MAC_OUI = { { 0x00, 0x1C, 0x42 } };

            /// @brief Xen MAC OUI prefix
            inline constexpr std::array<uint8_t, 3> XEN_MAC_OUI = { { 0x00, 0x16, 0x3E } };

            /// @brief QEMU/KVM MAC OUI prefix
            inline constexpr std::array<uint8_t, 3> QEMU_MAC_OUI = { { 0x52, 0x54, 0x00 } };

            // -------------------------------------------------------------------------
            // Known VM Process Names (lowercase for comparison)
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 48> KNOWN_VM_PROCESSES = { {
                    // VMware
                    L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe", L"vmacthlp.exe",
                    L"vmware-vmx.exe", L"vmware.exe", L"vmnat.exe", L"vmnetdhcp.exe",
                    L"vmware-authd.exe", L"vmware-hostd.exe", L"vmware-unity-helper.exe",
                    L"vmware-usbarbitrator.exe", L"vmware-usbarbitrator64.exe",

                    // VirtualBox
                    L"vboxservice.exe", L"vboxtray.exe", L"vboxguest.exe", L"vboxcontrol.exe",
                    L"vboxsf.exe", L"virtualbox.exe", L"vboxwebsrv.exe", L"vboxheadless.exe",
                    L"vboxsdl.exe", L"vboxmanage.exe", L"vboxsvc.exe",

                    // Hyper-V
                    L"vmms.exe", L"vmwp.exe", L"vmcompute.exe", L"vmconnect.exe",

                    // QEMU
                    L"qemu.exe", L"qemu-system-x86_64.exe", L"qemu-system-i386.exe",
                    L"qemu-ga.exe", L"qemu-img.exe",

                    // Xen
                    L"xenservice.exe", L"xensvc.exe", L"xen.exe",

                    // Parallels
                    L"prl_tools.exe", L"prl_cc.exe", L"prl_tools_service.exe",
                    L"coherence.exe",

                    // Sandboxie
                    L"sbiesvc.exe", L"sbiectrl.exe", L"sbiexec.exe",
                    L"start.exe",  // Sandboxie's start

                    // Wine
                    L"wine.exe", L"wineserver.exe", L"winedevice.exe",

                    // Generic
                    L"vmcomputeagent.exe"
                } };

            // -------------------------------------------------------------------------
            // Known VM Service Names (for service enumeration)
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 32> KNOWN_VM_SERVICES = { {
                    // VMware
                    L"VMTools", L"vmtoolsd", L"VMwareCAFCommAmqpListener", L"VMwareCAFManagementAgentHost",
                    L"vmvss", L"VMUSBArbService", L"VMAuthdService",

                    // VirtualBox
                    L"VBoxService", L"VBoxGuest", L"VBoxSF", L"VBoxMouse", L"VBoxVideo",
                    L"VBoxWddm",

                    // Hyper-V
                    L"vmms", L"vmicguestinterface", L"vmicheartbeat", L"vmickvpexchange",
                    L"vmicrdv", L"vmicshutdown", L"vmictimesync", L"vmicvmsession", L"vmicvss",

                    // QEMU
                    L"QEMU-GA", L"qemu-ga",

                    // Xen
                    L"xenbus", L"xenvif", L"xenvbd", L"xennet",

                    // Parallels
                    L"prl_tools", L"Parallels Tools Service",

                    // Sandboxie
                    L"SbieSvc"
                } };

            // -------------------------------------------------------------------------
            // Known VM Registry Keys
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 24> KNOWN_VM_REGISTRY_KEYS = { {
                L"SOFTWARE\\VMware, Inc.\\VMware Tools",
                L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
                L"SOFTWARE\\Parallels\\Parallels Tools",
                L"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
                L"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
                L"SYSTEM\\CurrentControlSet\\Services\\VBoxService",
                L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
                L"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
                L"SYSTEM\\CurrentControlSet\\Services\\vmtools",
                L"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
                L"SYSTEM\\CurrentControlSet\\Services\\vmmouse",
                L"SYSTEM\\CurrentControlSet\\Services\\vmmemctl",
                L"SYSTEM\\CurrentControlSet\\Services\\VMwareCAFCommAmqpListener",
                L"SYSTEM\\CurrentControlSet\\Services\\vmci",
                L"SYSTEM\\CurrentControlSet\\Services\\vmxnet3",
                L"SYSTEM\\CurrentControlSet\\Services\\vmxnet",
                L"HARDWARE\\ACPI\\DSDT\\VBOX__",
                L"HARDWARE\\ACPI\\FADT\\VBOX__",
                L"HARDWARE\\ACPI\\RSDT\\VBOX__",
                L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
                L"SYSTEM\\CurrentControlSet\\Enum\\IDE",
                L"SYSTEM\\CurrentControlSet\\Enum\\SCSI"
            } };

            // -------------------------------------------------------------------------
            // Known VM File Paths
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 40> KNOWN_VM_FILES = { {
                    // VMware
                    L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
                    L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                    L"C:\\Windows\\System32\\drivers\\vmci.sys",
                    L"C:\\Windows\\System32\\drivers\\vmusbmouse.sys",
                    L"C:\\Windows\\System32\\drivers\\vmx_svga.sys",
                    L"C:\\Windows\\System32\\drivers\\vmxnet.sys",
                    L"C:\\Windows\\System32\\drivers\\vmxnet3.sys",
                    L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
                    L"C:\\Program Files\\VMware\\VMware Tools\\vmwaretray.exe",
                    L"C:\\Windows\\System32\\vm3dgl.dll",
                    L"C:\\Windows\\System32\\vm3dver.dll",
                    L"C:\\Windows\\System32\\vmGuestLib.dll",
                    L"C:\\Windows\\System32\\vmhgfs.dll",

                    // VirtualBox
                    L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
                    L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                    L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
                    L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
                    L"C:\\Windows\\System32\\drivers\\VBoxWddm.sys",
                    L"C:\\Windows\\System32\\VBoxControl.exe",
                    L"C:\\Windows\\System32\\VBoxDisp.dll",
                    L"C:\\Windows\\System32\\VBoxHook.dll",
                    L"C:\\Windows\\System32\\VBoxMRXNP.dll",
                    L"C:\\Windows\\System32\\VBoxOGL.dll",
                    L"C:\\Windows\\System32\\VBoxOGLarrayspu.dll",
                    L"C:\\Windows\\System32\\VBoxOGLcrutil.dll",
                    L"C:\\Windows\\System32\\VBoxOGLerrorspu.dll",
                    L"C:\\Windows\\System32\\VBoxOGLfeedbackspu.dll",
                    L"C:\\Windows\\System32\\VBoxOGLpackspu.dll",
                    L"C:\\Windows\\System32\\VBoxOGLpassthroughspu.dll",
                    L"C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxTray.exe",
                    L"C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\VBoxService.exe",

                    // Parallels
                    L"C:\\Windows\\System32\\drivers\\prleth.sys",
                    L"C:\\Windows\\System32\\drivers\\prlfs.sys",
                    L"C:\\Windows\\System32\\drivers\\prlmouse.sys",
                    L"C:\\Windows\\System32\\drivers\\prlvideo.sys",
                    L"C:\\Windows\\System32\\drivers\\prl_pv32.sys",
                    L"C:\\Windows\\System32\\drivers\\prl_paravirt_32.sys",

                    // Xen
                    L"C:\\Windows\\System32\\drivers\\xenbus.sys",
                    L"C:\\Windows\\System32\\drivers\\xenfilt.sys",
                    L"C:\\Windows\\System32\\drivers\\xenvif.sys"
                } };

            // -------------------------------------------------------------------------
            // Known Firmware/SMBIOS Strings (for DMI table checks)
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 24> KNOWN_FIRMWARE_STRINGS = { {
                L"VMware", L"VMWARE", L"Virtual", L"VIRTUAL",
                L"VirtualBox", L"VBOX", L"Oracle", L"VBox",
                L"Hyper-V", L"HYPER-V", L"Microsoft Corporation",
                L"QEMU", L"Bochs", L"SeaBIOS",
                L"Xen", L"XEN", L"Citrix",
                L"Parallels", L"PARALLELS",
                L"KVM", L"Red Hat",
                L"Amazon EC2", L"Google Compute Engine",
                L"innotek GmbH"  // VirtualBox BIOS
            } };

            // -------------------------------------------------------------------------
            // Known Window Class Names (for detecting VM tools windows)
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 12> KNOWN_VM_WINDOW_CLASSES = { {
                L"VMSwitchUserControlClass", L"VMwareUnityWindow", L"VMwareTrayIcon",
                L"VBoxTrayToolWndClass", L"VBoxSDL", L"VBoxGuestDnDWnd",
                L"ParallelsClipboardOwnerWindow", L"PrlToolsClipboard",
                L"Hyper-VWindow", L"VMBusHidWindow",
                L"SandboxieControl", L"SandboxieWindow"
            } };

            // -------------------------------------------------------------------------
            // Known Device Identifiers (for PCI/USB enumeration)
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 20> KNOWN_VM_DEVICE_IDS = { {
                    // VMware
                    L"VEN_15AD",  // VMware vendor ID
                    L"PCI\\VEN_15AD&DEV_0405",  // VMware SVGA II
                    L"PCI\\VEN_15AD&DEV_0740",  // VMware VMCI
                    L"PCI\\VEN_15AD&DEV_0770",  // VMware USB Controller
                    L"PCI\\VEN_15AD&DEV_0790",  // VMware PCI Bridge
                    L"PCI\\VEN_15AD&DEV_07A0",  // VMware PCIE Root Port
                    L"PCI\\VEN_15AD&DEV_07B0",  // VMware VMXNET3
                    L"PCI\\VEN_15AD&DEV_07C0",  // VMware PVSCSI
                    L"PCI\\VEN_15AD&DEV_0801",  // VMware Sound Device

                    // VirtualBox
                    L"VEN_80EE",  // VirtualBox vendor ID
                    L"PCI\\VEN_80EE&DEV_CAFE",  // VirtualBox Graphics Adapter
                    L"PCI\\VEN_80EE&DEV_BEEF",  // VirtualBox Guest Additions

                    // Hyper-V
                    L"VEN_1414",  // Microsoft vendor ID (Hyper-V synthetic devices)
                    L"VMBUS",  // Hyper-V VMBus
                    L"ROOT\\ACPI_HAL",

                    // QEMU/KVM
                    L"VEN_1234",  // QEMU vendor ID
                    L"VEN_1AF4",  // Red Hat (virtio)
                    L"PCI\\VEN_1AF4&DEV_1000",  // VirtIO network
                    L"PCI\\VEN_1AF4&DEV_1001",  // VirtIO block
                    L"PCI\\VEN_1AF4&DEV_1002"   // VirtIO balloon
                } };

            // -------------------------------------------------------------------------
            // ACPI Table Signatures for VM Detection
            // -------------------------------------------------------------------------

            inline constexpr uint32_t ACPI_SIGNATURE_VBOX = 0x584F4256;  // "VBOX"
            inline constexpr uint32_t ACPI_SIGNATURE_VMWARE = 0x45524157;  // "WARE" (part of VMware)
            inline constexpr uint32_t ACPI_SIGNATURE_XEN = 0x004E4558;  // "XEN\0"
            inline constexpr uint32_t ACPI_SIGNATURE_PTLTD = 0x44544C54;  // "PTLTD" (QEMU)

            // -------------------------------------------------------------------------
            // Extended Hypervisor Vendor Strings (Enterprise Cloud Platforms)
            // -------------------------------------------------------------------------

            /// @brief Firecracker (AWS microVM)
            inline constexpr std::string_view VENDOR_FIRECRACKER = "Firecracker\0";

            /// @brief Cloud Hypervisor (Intel)
            inline constexpr std::string_view VENDOR_CLOUD_HV = "CloudHV\0\0\0\0\0";

            /// @brief crosvm (Chrome OS VM)
            inline constexpr std::string_view VENDOR_CROSVM = "crosvmcrosvm";

            /// @brief Apple Virtualization Framework
            inline constexpr std::string_view VENDOR_APPLE_VZ = "Apple VZ\0\0\0\0";

            /// @brief Nutanix AHV
            inline constexpr std::string_view VENDOR_NUTANIX = "NutanixAHV\0\0";

            // -------------------------------------------------------------------------
            // Anti-VM API Indicators (for Import Analysis)
            // -------------------------------------------------------------------------

            /// @brief APIs commonly used for VM detection by malware
            inline constexpr std::array<std::string_view, 32> ANTI_VM_IMPORT_APIS = {{
                // Debugger detection (often paired with VM detection)
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
                "NtQuerySystemInformation",
                "NtSetInformationThread",
                "OutputDebugStringA",
                "OutputDebugStringW",

                // Timing-based detection
                "GetTickCount",
                "GetTickCount64",
                "QueryPerformanceCounter",
                "QueryPerformanceFrequency",
                "timeGetTime",
                "GetSystemTimeAsFileTime",

                // Hardware/System information
                "GetSystemInfo",
                "GetNativeSystemInfo",
                "GetSystemFirmwareTable",
                "EnumSystemFirmwareTables",
                "GetComputerNameA",
                "GetComputerNameW",
                "GetVolumeInformationA",
                "GetVolumeInformationW",

                // Process/Thread manipulation
                "CreateToolhelp32Snapshot",
                "Process32First",
                "Process32Next",
                "Module32First",
                "Module32Next",

                // WMI (often used for VM detection)
                "CoCreateInstance",
                "CoInitializeEx",

                // Low-level hardware access
                "__cpuid",
                "__cpuidex",
                "__rdtsc"
            }};

            /// @brief Suspicious DLL imports indicating anti-VM behavior
            inline constexpr std::array<std::string_view, 12> ANTI_VM_IMPORT_DLLS = {{
                "ntdll.dll",
                "kernel32.dll",
                "wbemuuid.dll",
                "setupapi.dll",
                "cfgmgr32.dll",
                "wmi.dll",
                "ole32.dll",
                "oleaut32.dll",
                "advapi32.dll",
                "user32.dll",
                "winmm.dll",
                "powrprof.dll"
            }};

            // -------------------------------------------------------------------------
            // Instruction Patterns for Zydis-based Analysis
            // -------------------------------------------------------------------------

            /// @brief x86/x64 mnemonics indicative of anti-VM behavior
            inline constexpr std::array<std::string_view, 24> ANTI_VM_MNEMONICS = {{
                "cpuid",      // Hypervisor detection
                "rdtsc",      // Timing attacks
                "rdtscp",     // Timing attacks (serializing)
                "sidt",       // Red Pill (IDT base)
                "sgdt",       // No Pill (GDT base)
                "sldt",       // LDT selector
                "str",        // Task Register (SWIZZ test)
                "in",         // I/O port access (VMware backdoor)
                "out",        // I/O port output
                "vmcall",     // Intel VT-x hypercall
                "vmmcall",    // AMD-V hypercall
                "vmread",     // VMCS read
                "vmwrite",    // VMCS write
                "vmlaunch",   // Launch VM
                "vmresume",   // Resume VM
                "vmxoff",     // Exit VMX operation
                "vmxon",      // Enter VMX operation
                "invd",       // Invalidate cache (privileged)
                "wbinvd",     // Write-back and invalidate
                "rdmsr",      // Read MSR (model-specific register)
                "wrmsr",      // Write MSR
                "smsw",       // Store Machine Status Word
                "lmsw",       // Load Machine Status Word
                "int"         // Software interrupt (INT 2E, etc.)
            }};

            /// @brief Timing threshold for RDTSC-based VM detection (cycles)
            inline constexpr uint64_t RDTSC_VM_THRESHOLD_MIN = 500;
            inline constexpr uint64_t RDTSC_VM_THRESHOLD_MAX = 5000;

            /// @brief CPUID timing threshold (cycles) - VMs have higher latency
            inline constexpr uint64_t CPUID_VM_THRESHOLD = 1500;

            /// @brief Maximum code size to analyze per function (bytes)
            inline constexpr size_t MAX_FUNCTION_ANALYSIS_SIZE = 0x10000;  // 64KB

            /// @brief Maximum instructions to disassemble per analysis
            inline constexpr size_t MAX_INSTRUCTIONS_TO_ANALYZE = 10000;

            /// @brief Minimum entropy threshold for packed/encrypted sections
            inline constexpr double PACKED_SECTION_ENTROPY_THRESHOLD = 7.0;

            // -------------------------------------------------------------------------
            // Cloud-Specific VM Identifiers
            // -------------------------------------------------------------------------

            inline constexpr std::array<std::wstring_view, 16> CLOUD_VM_IDENTIFIERS = {{
                // AWS
                L"Amazon EC2", L"aws", L"Xen", L"HVM domU",
                // Azure
                L"Microsoft Corporation Virtual Machine", L"Hyper-V UEFI",
                // GCP
                L"Google Compute Engine", L"Google",
                // Oracle Cloud
                L"OracleCloud", L"Oracle Corporation",
                // Alibaba Cloud
                L"Alibaba Cloud ECS",
                // DigitalOcean
                L"DigitalOcean Droplet",
                // Linode
                L"Linode",
                // Vultr
                L"Vultr",
                // Hetzner
                L"Hetzner"
            }};

        }  // namespace VMConstants

        // ============================================================================
        // ENUMERATIONS
        // ============================================================================

        /**
         * @brief Types of virtual machine/hypervisor environments detected
         */
        enum class VMType : uint8_t {
            None = 0,               ///< No VM detected (bare metal)
            VMware = 1,             ///< VMware (Workstation, Fusion, ESXi, vSphere)
            VirtualBox = 2,         ///< Oracle VirtualBox
            HyperV = 3,             ///< Microsoft Hyper-V
            QEMU = 4,               ///< QEMU (without KVM)
            KVM = 5,                ///< KVM (Kernel-based Virtual Machine, often with QEMU)
            Xen = 6,                ///< Xen hypervisor (Citrix)
            Parallels = 7,          ///< Parallels Desktop
            Bochs = 8,              ///< Bochs emulator
            Wine = 9,               ///< Wine compatibility layer (not true VM)
            Sandboxie = 10,         ///< Sandboxie application sandbox
            DockerContainer = 11,   ///< Docker/container environment
            WSL = 12,               ///< Windows Subsystem for Linux
            AmazonEC2 = 13,         ///< Amazon EC2 instance
            GoogleCloud = 14,       ///< Google Cloud Platform VM
            AzureVM = 15,           ///< Microsoft Azure VM
            Bhyve = 16,             ///< FreeBSD bhyve hypervisor
            ACRN = 17,              ///< ACRN hypervisor
            AppleVirt = 18,         ///< Apple Virtualization Framework
            GenericHypervisor = 254,///< Unknown/generic hypervisor detected
            Unknown = 255           ///< Detection inconclusive
        };

        /**
         * @brief Categories of VM detection techniques
         */
        enum class VMDetectionCategory : uint16_t {
            None = 0x0000,
            CPUID = 0x0001,   ///< CPUID-based detection
            Registry = 0x0002,   ///< Registry artifact detection
            FileSystem = 0x0004,   ///< File system artifact detection
            Network = 0x0008,   ///< Network adapter (MAC) detection
            Firmware = 0x0010,   ///< SMBIOS/ACPI firmware detection
            Process = 0x0020,   ///< Process/service enumeration
            Timing = 0x0040,   ///< Timing-based detection
            IOPort = 0x0080,   ///< I/O port probing
            Memory = 0x0100,   ///< Memory artifact scanning
            Device = 0x0200,   ///< Device enumeration (PCI/USB)
            WMI = 0x0400,   ///< WMI queries
            Window = 0x0800,   ///< Window class detection
            BehaviorAnalysis = 0x1000,   ///< Behavioral pattern analysis
            All = 0xFFFF    ///< All detection categories
        };

        /**
         * @brief Confidence level for detection results
         */
        enum class VMConfidenceLevel : uint8_t {
            None = 0,           ///< No detection or 0% confidence
            VeryLow = 1,        ///< 1-20% confidence (possible false positive)
            Low = 2,            ///< 21-40% confidence
            Medium = 3,         ///< 41-60% confidence
            High = 4,           ///< 61-80% confidence
            VeryHigh = 5,       ///< 81-95% confidence
            Definitive = 6      ///< >95% confidence (highly reliable indicator)
        };

        /**
         * @brief Types of anti-VM techniques used by malware
         */
        enum class AntiVMTechnique : uint32_t {
            None = 0x00000000,

            // CPUID-based (0x01xxxxxx)
            CPUIDHypervisorCheck = 0x01000001,
            CPUIDVendorString = 0x01000002,
            CPUIDBrandString = 0x01000004,
            CPUIDFeatureFlags = 0x01000008,
            CPUIDLeafEnumeration = 0x01000010,
            CPUIDCoreCount = 0x01000020,
            CPUIDCacheInfo = 0x01000040,

            // Registry-based (0x02xxxxxx)
            RegistryKeyCheck = 0x02000001,
            RegistryValueRead = 0x02000002,
            RegistryEnumeration = 0x02000004,
            RegistryHardwareInfo = 0x02000008,

            // File System (0x03xxxxxx)
            FileExistenceCheck = 0x03000001,
            DriverFileCheck = 0x03000002,
            DirectoryEnumeration = 0x03000004,
            FileAttributeCheck = 0x03000008,

            // Network (0x04xxxxxx)
            MACAddressCheck = 0x04000001,
            AdapterNameCheck = 0x04000002,
            NetworkConfigCheck = 0x04000004,

            // Firmware (0x05xxxxxx)
            SMBIOSCheck = 0x05000001,
            ACPITableCheck = 0x05000002,
            BIOSStringCheck = 0x05000004,
            FirmwareTableQuery = 0x05000008,

            // Process/Service (0x06xxxxxx)
            ProcessEnumeration = 0x06000001,
            ServiceEnumeration = 0x06000002,
            ModuleEnumeration = 0x06000004,
            WindowEnumeration = 0x06000008,

            // Timing (0x07xxxxxx)
            RDTSCTiming = 0x07000001,
            QPCTiming = 0x07000002,
            GetTickCountTiming = 0x07000004,
            InstructionTiming = 0x07000008,

            // I/O Port (0x08xxxxxx)
            VMwareBackdoor = 0x08000001,
            VBoxBackdoor = 0x08000002,
            IOPortProbing = 0x08000004,

            // Memory (0x09xxxxxx)
            MemoryArtifactScan = 0x09000001,
            IDTCheck = 0x09000002,
            GDTCheck = 0x09000004,
            LDTCheck = 0x09000008,

            // Device (0x0Axxxxxx)
            DeviceEnumeration = 0x0A000001,
            DeviceIdCheck = 0x0A000002,
            ControllerStringCheck = 0x0A000004,

            // WMI (0x0Bxxxxxx)
            WMIQuery = 0x0B000001,
            Win32ComputerSystem = 0x0B000002,
            Win32BIOS = 0x0B000004,
            Win32BaseBoard = 0x0B000008,

            // Advanced (0x0Cxxxxxx)
            RedPillTest = 0x0C000001,  // SIDT instruction
            NoPillTest = 0x0C000002,  // SGDT/SLDT instructions
            SWIZZTest = 0x0C000004,  // STR instruction
            INTNCheck = 0x0C000008,  // Interrupt descriptor checks

            // Combined/Multiple
            MultipleCategories = 0xFFFF0000
        };

        /**
         * @brief Bitwise OR operator for VMDetectionCategory flags
         */
        inline constexpr VMDetectionCategory operator|(VMDetectionCategory lhs, VMDetectionCategory rhs) noexcept {
            return static_cast<VMDetectionCategory>(
                static_cast<uint16_t>(lhs) | static_cast<uint16_t>(rhs)
                );
        }

        /**
         * @brief Bitwise AND operator for VMDetectionCategory flags
         */
        inline constexpr VMDetectionCategory operator&(VMDetectionCategory lhs, VMDetectionCategory rhs) noexcept {
            return static_cast<VMDetectionCategory>(
                static_cast<uint16_t>(lhs) & static_cast<uint16_t>(rhs)
                );
        }

        /**
         * @brief Bitwise OR operator for AntiVMTechnique flags
         */
        inline constexpr AntiVMTechnique operator|(AntiVMTechnique lhs, AntiVMTechnique rhs) noexcept {
            return static_cast<AntiVMTechnique>(
                static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs)
                );
        }

        /**
         * @brief Bitwise AND operator for AntiVMTechnique flags
         */
        inline constexpr AntiVMTechnique operator&(AntiVMTechnique lhs, AntiVMTechnique rhs) noexcept {
            return static_cast<AntiVMTechnique>(
                static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs)
                );
        }

        // ============================================================================
        // DATA STRUCTURES
        // ============================================================================

        /**
         * @brief Information about a single detected VM artifact
         */
        struct VMArtifact {
            VMDetectionCategory category = VMDetectionCategory::None;  ///< Detection category
            VMType associatedVMType = VMType::None;                     ///< Which VM this artifact indicates
            float confidence = 0.0f;                                    ///< Confidence score (0-100)
            std::wstring description;                                   ///< Human-readable description
            std::wstring rawValue;                                      ///< Raw detected value
            std::wstring location;                                      ///< Where artifact was found
            std::chrono::system_clock::time_point detectionTime;        ///< When artifact was detected

            /**
             * @brief Get confidence level enum from float score
             */
            [[nodiscard]] VMConfidenceLevel GetConfidenceLevel() const noexcept {
                if (confidence >= 95.0f) return VMConfidenceLevel::Definitive;
                if (confidence >= 80.0f) return VMConfidenceLevel::VeryHigh;
                if (confidence >= 60.0f) return VMConfidenceLevel::High;
                if (confidence >= 40.0f) return VMConfidenceLevel::Medium;
                if (confidence >= 20.0f) return VMConfidenceLevel::Low;
                if (confidence > 0.0f)   return VMConfidenceLevel::VeryLow;
                return VMConfidenceLevel::None;
            }
        };

        /**
         * @brief CPUID-specific detection information
         */
        struct CPUIDInfo {
            bool hypervisorPresent = false;              ///< Hypervisor bit in CPUID.1.ECX
            std::string vendorString;                    ///< 12-byte vendor string from CPUID.0x40000000
            uint32_t maxHypervisorLeaf = 0;              ///< Maximum supported hypervisor CPUID leaf
            std::string hypervisorSignature;             ///< 4-byte interface signature from CPUID.0x40000001
            std::array<uint32_t, 4> hypervisorFeatures{};///< Feature bits from CPUID.0x40000003
            VMType detectedType = VMType::None;          ///< VM type determined from CPUID
            bool isReliable = false;                     ///< True if detection is considered reliable

            /**
             * @brief Reset all fields to default values
             */
            void Clear() noexcept {
                hypervisorPresent = false;
                vendorString.clear();
                maxHypervisorLeaf = 0;
                hypervisorSignature.clear();
                hypervisorFeatures.fill(0);
                detectedType = VMType::None;
                isReliable = false;
            }
        };

        /**
         * @brief Network adapter VM-related information
         */
        struct VMNetworkInfo {
            Utils::NetworkUtils::MacAddress macAddress;  ///< MAC address
            std::wstring adapterName;                    ///< Adapter friendly name
            VMType associatedVMType = VMType::None;      ///< Detected VM type from this adapter
            float confidence = 0.0f;                     ///< Detection confidence
            bool isVirtualAdapter = false;               ///< True if adapter appears virtual
        };

        /**
         * @brief Firmware/SMBIOS detection information
         */
        struct VMFirmwareInfo {
            std::wstring biosVendor;           ///< BIOS vendor string
            std::wstring biosVersion;          ///< BIOS version string
            std::wstring systemManufacturer;   ///< System manufacturer
            std::wstring systemProductName;    ///< System product name
            std::wstring systemSerialNumber;   ///< System serial number
            std::wstring boardManufacturer;    ///< Baseboard manufacturer
            std::wstring boardProductName;     ///< Baseboard product name
            std::vector<std::wstring> acpiSignatures;  ///< ACPI table signatures found
            VMType detectedType = VMType::None;///< VM type from firmware
            float confidence = 0.0f;           ///< Detection confidence

            /**
             * @brief Reset all fields to default values
             */
            void Clear() noexcept {
                biosVendor.clear();
                biosVersion.clear();
                systemManufacturer.clear();
                systemProductName.clear();
                systemSerialNumber.clear();
                boardManufacturer.clear();
                boardProductName.clear();
                acpiSignatures.clear();
                detectedType = VMType::None;
                confidence = 0.0f;
            }
        };

        /**
         * @brief Timing-based detection information
         */
        struct VMTimingInfo {
            uint64_t rdtscDelta = 0;              ///< RDTSC instruction timing delta
            uint64_t qpcDelta = 0;                ///< QueryPerformanceCounter delta
            uint64_t cpuidTimingDelta = 0;        ///< CPUID instruction timing
            bool timingAnomalyDetected = false;   ///< True if timing suggests VM
            float confidence = 0.0f;              ///< Detection confidence
            uint32_t sampleCount = 0;             ///< Number of timing samples taken
            uint64_t averageDelta = 0;            ///< Average timing delta
            uint64_t stdDeviation = 0;            ///< Standard deviation of timing
        };

        // ============================================================================
        // ZYDIS DISASSEMBLY STRUCTURES (Enterprise Enhancement)
        // ============================================================================

        /**
         * @brief Result of disassembling a single instruction
         */
        struct DisassembledInstruction {
            uint64_t address = 0;                      ///< Virtual address of instruction
            size_t length = 0;                         ///< Instruction length in bytes
            std::string mnemonic;                      ///< Instruction mnemonic (e.g., "cpuid")
            std::string operands;                      ///< Formatted operand string
            std::string fullText;                      ///< Complete disassembly text
            std::array<uint8_t, 15> rawBytes{};        ///< Raw instruction bytes (max 15 for x64)
            bool isAntiVM = false;                     ///< True if this is an anti-VM instruction
            AntiVMTechnique associatedTechnique = AntiVMTechnique::None;
        };

        /**
         * @brief Result of Zydis-based code analysis
         */
        struct CodeAnalysisResult {
            std::vector<DisassembledInstruction> antiVMInstructions;  ///< Anti-VM instructions found
            size_t totalInstructionsAnalyzed = 0;      ///< Total instructions disassembled
            size_t cpuidCount = 0;                     ///< CPUID instruction count
            size_t rdtscCount = 0;                     ///< RDTSC/RDTSCP count
            size_t sidtCount = 0;                      ///< SIDT instruction count
            size_t sgdtCount = 0;                      ///< SGDT instruction count
            size_t sldtCount = 0;                      ///< SLDT instruction count
            size_t strCount = 0;                       ///< STR instruction count
            size_t ioPortAccessCount = 0;              ///< IN/OUT instruction count
            size_t vmInstructionCount = 0;             ///< VMCALL/VMMCALL/VMX count
            size_t timingInstructionCount = 0;         ///< Total timing-related instructions
            bool hasCpuidLoop = false;                 ///< Multiple CPUIDs in tight loop
            bool hasRdtscSandwich = false;             ///< RDTSC before/after instruction pattern
            bool hasPrivilegedInstructions = false;    ///< Contains ring-0 only instructions
            float evasionScore = 0.0f;                 ///< Overall evasion likelihood (0-100)
            std::chrono::nanoseconds analysisTime{0};  ///< Time taken for analysis
        };

        // ============================================================================
        // PE ANALYSIS STRUCTURES (Enterprise Enhancement)
        // ============================================================================

        /**
         * @brief Suspicious import detected in PE file
         */
        struct SuspiciousImport {
            std::string dllName;                       ///< Source DLL name
            std::string functionName;                  ///< Imported function name
            uint16_t ordinal = 0;                      ///< Ordinal (if by ordinal)
            AntiVMTechnique associatedTechnique = AntiVMTechnique::None;
            float suspicionScore = 0.0f;               ///< How suspicious (0-100)
            std::wstring reason;                       ///< Why this is suspicious
        };

        /**
         * @brief Result of PE-based anti-VM analysis
         */
        struct PEAnalysisResult {
            bool isPE = false;                         ///< True if valid PE file
            bool is64Bit = false;                      ///< True if PE32+
            bool isDotNet = false;                     ///< True if .NET assembly
            bool isSigned = false;                     ///< True if has Authenticode signature
            bool isPacked = false;                     ///< True if likely packed/encrypted

            // Import analysis
            std::vector<SuspiciousImport> suspiciousImports;
            size_t totalImportedFunctions = 0;         ///< Total import count
            size_t antiVMImportCount = 0;              ///< Anti-VM related imports

            // Section analysis
            size_t executableSectionCount = 0;         ///< Number of executable sections
            size_t writableExecutableSections = 0;     ///< W+X sections (suspicious)
            double highestSectionEntropy = 0.0;        ///< Highest entropy value
            std::wstring highEntropySection;           ///< Name of high-entropy section

            // Entry point analysis
            bool entryPointInWritableSection = false;  ///< EP in writable section
            bool entryPointOutsideCode = false;        ///< EP not in .text
            uint32_t entryPointRva = 0;

            // TLS callbacks (often used for anti-debug/VM)
            size_t tlsCallbackCount = 0;
            std::vector<uint64_t> tlsCallbackAddresses;

            // Anomalies detected
            std::vector<std::wstring> anomalies;

            float overallSuspicionScore = 0.0f;        ///< Combined score (0-100)
            std::chrono::nanoseconds analysisTime{0};
        };

        /**
         * @brief Extended process analysis result with Zydis and PE integration
         */
        struct ExtendedProcessAnalysis {
            Utils::ProcessUtils::ProcessId processId = 0;
            std::wstring processName;
            std::wstring executablePath;

            // Code analysis (Zydis)
            CodeAnalysisResult codeAnalysis;

            // PE analysis
            PEAnalysisResult peAnalysis;

            // Combined results
            bool hasAntiVMBehavior = false;
            float combinedEvasionScore = 0.0f;         ///< Weighted combination of all scores
            AntiVMTechnique detectedTechniques = AntiVMTechnique::None;

            // Memory regions analyzed
            size_t executableRegionsScanned = 0;
            size_t totalBytesScanned = 0;

            bool completed = false;
            std::wstring errorMessage;
            std::chrono::nanoseconds totalAnalysisTime{0};
        };

        /**
         * @brief Configuration for extended analysis with Zydis/PE
         */
        struct ExtendedAnalysisConfig {
            // Zydis options
            bool enableDisassembly = true;             ///< Enable instruction-level analysis
            bool analyzeAllExecutableRegions = true;   ///< Scan all executable memory
            bool detectCpuidLoops = true;              ///< Detect CPUID timing loops
            bool detectRdtscPatterns = true;           ///< Detect RDTSC sandwiches
            size_t maxInstructionsPerRegion = VMConstants::MAX_INSTRUCTIONS_TO_ANALYZE;
            size_t maxRegionsToAnalyze = 64;

            // PE options
            bool enablePEAnalysis = true;              ///< Enable PE header analysis
            bool analyzeImports = true;                ///< Check import table
            bool analyzeSections = true;               ///< Check section characteristics
            bool analyzeEntropy = true;                ///< Calculate section entropy
            bool analyzeTLS = true;                    ///< Check TLS callbacks
            bool detectAnomalies = true;               ///< Check for PE anomalies

            // Thresholds
            double entropyThreshold = VMConstants::PACKED_SECTION_ENTROPY_THRESHOLD;
            size_t minSuspiciousImports = 3;           ///< Min imports to flag as suspicious
            float minEvasionScoreToReport = 25.0f;     ///< Min score to report

            // Timeout and limits
            uint32_t timeoutMs = 30000;
            size_t maxMemoryToScan = 128 * 1024 * 1024; // 128MB
            const std::atomic<bool>* cancelFlag = nullptr;
        };

        /**
         * @brief Complete VM detection result
         */
        struct VMEvasionResult {
            // Primary detection results
            bool isVM = false;                                  ///< True if VM detected
            VMType detectedType = VMType::None;                 ///< Primary VM type detected
            VMType secondaryType = VMType::None;                ///< Secondary/alternate VM type (for nested VMs)
            float confidenceScore = 0.0f;                       ///< Overall confidence (0-100)
            VMConfidenceLevel confidenceLevel = VMConfidenceLevel::None;  ///< Confidence level enum

            // Detection categories that triggered
            VMDetectionCategory triggeredCategories = VMDetectionCategory::None;

            // Detailed detection information
            CPUIDInfo cpuidInfo;                               ///< CPUID detection details
            VMFirmwareInfo firmwareInfo;                       ///< Firmware detection details
            VMTimingInfo timingInfo;                           ///< Timing detection details
            std::vector<VMNetworkInfo> networkIndicators;      ///< Network adapter indicators

            // Collected artifacts
            std::vector<VMArtifact> artifacts;                 ///< All detected artifacts

            // Per-category scores
            std::unordered_map<VMDetectionCategory, float> categoryScores;

            // Timing information
            std::chrono::system_clock::time_point detectionTime;        ///< When detection was performed
            std::chrono::nanoseconds detectionDuration{ 0 };              ///< How long detection took

            // -------------------------------------------------------------------------
            // ENTERPRISE FALSE POSITIVE REDUCTION
            // -------------------------------------------------------------------------
            // These fields help differentiate LEGITIMATE enterprise virtualization
            // (AWS EC2, Azure, GCP, VMware vSphere) from SUSPICIOUS sandbox evasion.
            
            /// True if running in a known legitimate cloud environment (AWS/Azure/GCP)
            bool isLegitimateCloudEnvironment = false;
            
            /// True if running in enterprise virtualization (domain-joined VMware/Hyper-V)
            bool isEnterpriseVirtualization = false;
            
            /// True if VM detection indicates potential malware evasion (not just VM presence)
            bool isSuspiciousEvasion = false;
            
            /// Detected cloud provider (if any)
            std::wstring cloudProvider;
            
            /// Cloud instance metadata (if available)
            std::wstring cloudInstanceId;
            std::wstring cloudRegion;

            // Error/status information
            bool completed = false;                            ///< True if detection completed normally
            bool timedOut = false;                             ///< True if detection timed out
            std::wstring errorMessage;                         ///< Error message if failed

            /**
             * @brief Get human-readable summary string
             */
            [[nodiscard]] std::wstring GetSummary() const;

            /**
             * @brief Get artifacts filtered by category
             */
            [[nodiscard]] std::vector<VMArtifact> GetArtifactsByCategory(VMDetectionCategory category) const;

            /**
             * @brief Get artifacts filtered by VM type
             */
            [[nodiscard]] std::vector<VMArtifact> GetArtifactsByVMType(VMType type) const;

            /**
             * @brief Check if a specific category contributed to detection
             */
            [[nodiscard]] bool HasCategory(VMDetectionCategory category) const noexcept {
                return (triggeredCategories & category) != VMDetectionCategory::None;
            }

            /**
             * @brief Get the number of distinct artifact categories detected
             */
            [[nodiscard]] size_t GetCategoryCount() const noexcept;

            /**
             * @brief Reset all fields to default state
             */
            void Clear() noexcept;

            // Default constructor
            VMEvasionResult() noexcept = default;

            // Copy/move operations
            VMEvasionResult(const VMEvasionResult&) = default;
            VMEvasionResult& operator=(const VMEvasionResult&) = default;
            VMEvasionResult(VMEvasionResult&&) noexcept = default;
            VMEvasionResult& operator=(VMEvasionResult&&) noexcept = default;
        };

        /**
         * @brief Information about an anti-VM technique detected in a process
         */
        struct DetectedAntiVMTechnique {
            AntiVMTechnique technique = AntiVMTechnique::None;  ///< Technique type
            VMDetectionCategory category = VMDetectionCategory::None;  ///< Detection category
            std::wstring description;                           ///< Human-readable description
            std::wstring codeLocation;                          ///< Where in process memory
            uint64_t address = 0;                               ///< Memory address (if applicable)
            std::vector<uint8_t> codePattern;                   ///< Matched code bytes
            float severity = 0.0f;                              ///< Severity score (0-100)
            bool isActive = false;                              ///< True if technique actively used
        };

        /**
         * @brief Result of analyzing a process for anti-VM behavior
         */
        struct ProcessVMEvasionResult {
            Utils::ProcessUtils::ProcessId processId = 0;       ///< Target process ID
            std::wstring processName;                           ///< Process name
            std::wstring executablePath;                        ///< Full executable path

            bool hasAntiVMBehavior = false;                     ///< True if anti-VM behavior detected
            float evasionScore = 0.0f;                          ///< Overall evasion score (0-100)
            AntiVMTechnique detectedTechniques = AntiVMTechnique::None;  ///< Bitmask of techniques

            std::vector<DetectedAntiVMTechnique> techniqueDetails;  ///< Detailed technique info

            // Analysis timing
            std::chrono::nanoseconds analysisTime{ 0 };          ///< How long analysis took

            // Error handling
            bool completed = false;                             ///< True if analysis completed
            std::wstring errorMessage;                          ///< Error message if failed

            /**
             * @brief Get count of detected techniques
             */
            [[nodiscard]] size_t GetTechniqueCount() const noexcept {
                return techniqueDetails.size();
            }

            /**
             * @brief Check if specific technique was detected
             */
            [[nodiscard]] bool HasTechnique(AntiVMTechnique technique) const noexcept {
                return (detectedTechniques & technique) != AntiVMTechnique::None;
            }
        };

        /**
         * @brief Configuration options for VM detection
         */
        struct VMDetectionConfig {
            // Which detection categories to enable
            VMDetectionCategory enabledCategories = VMDetectionCategory::All;

            // Timeout settings
            uint32_t timeoutMs = VMConstants::DEFAULT_SCAN_TIMEOUT_MS;
            uint32_t perCheckTimeoutMs = 2000;                  ///< Timeout per individual check

            // Behavior settings
            bool enableCaching = true;                         ///< Cache detection results
            bool deepAnalysis = false;                         ///< Enable additional slow checks
            bool enableTimingChecks = false;                   ///< Enable timing-based detection (may be noisy)
            bool enableIOPortProbing = false;                  ///< Enable I/O port probing (may crash in some VMs)
            bool enableMemoryScanning = false;                 ///< Enable memory region scanning
            bool enableProcessEnumeration = true;              ///< Enable process listing for VM tools
            bool enableWMIQueries = true;                      ///< Enable WMI queries

            // Threshold settings
            float minimumConfidenceThreshold = 25.0f;          ///< Minimum confidence to report as VM
            size_t minimumArtifactCount = 1;                   ///< Minimum artifacts to report as VM

            // Category weights (for score calculation)
            std::unordered_map<VMDetectionCategory, float> categoryWeights;

            // Cancellation support
            const std::atomic<bool>* cancelFlag = nullptr;     ///< Optional cancellation flag

            /**
             * @brief Create default configuration
             */
            [[nodiscard]] static VMDetectionConfig CreateDefault() noexcept {
                VMDetectionConfig config;
                config.categoryWeights = {
                    { VMDetectionCategory::CPUID, VMConstants::WEIGHT_CPUID },
                    { VMDetectionCategory::Registry, VMConstants::WEIGHT_REGISTRY },
                    { VMDetectionCategory::FileSystem, VMConstants::WEIGHT_FILESYSTEM },
                    { VMDetectionCategory::Network, VMConstants::WEIGHT_NETWORK },
                    { VMDetectionCategory::Firmware, VMConstants::WEIGHT_FIRMWARE },
                    { VMDetectionCategory::Process, VMConstants::WEIGHT_PROCESS },
                    { VMDetectionCategory::Timing, VMConstants::WEIGHT_TIMING },
                    { VMDetectionCategory::IOPort, VMConstants::WEIGHT_IOPORT },
                    { VMDetectionCategory::Memory, VMConstants::WEIGHT_MEMORY },
                    { VMDetectionCategory::Device, VMConstants::WEIGHT_DEVICE },
                    { VMDetectionCategory::WMI, VMConstants::WEIGHT_WMI }
                };
                return config;
            }

            /**
             * @brief Create configuration for quick scan (CPUID + Registry only)
             */
            [[nodiscard]] static VMDetectionConfig CreateQuickScan() noexcept {
                VMDetectionConfig config = CreateDefault();
                config.enabledCategories = VMDetectionCategory::CPUID | VMDetectionCategory::Registry;
                config.timeoutMs = VMConstants::QUICK_SCAN_TIMEOUT_MS;
                config.enableWMIQueries = false;
                config.enableProcessEnumeration = false;
                return config;
            }

            /**
             * @brief Create configuration for deep analysis (all checks enabled)
             */
            [[nodiscard]] static VMDetectionConfig CreateDeepAnalysis() noexcept {
                VMDetectionConfig config = CreateDefault();
                config.enabledCategories = VMDetectionCategory::All;
                config.deepAnalysis = true;
                config.enableTimingChecks = true;
                config.enableMemoryScanning = true;
                config.minimumConfidenceThreshold = 10.0f;
                return config;
            }

            /**
             * @brief Check if a category is enabled
             */
            [[nodiscard]] bool IsCategoryEnabled(VMDetectionCategory category) const noexcept {
                return (enabledCategories & category) != VMDetectionCategory::None;
            }
        };

        /**
         * @brief Configuration for process anti-VM behavior analysis
         */
        struct ProcessAnalysisConfig {
            bool analyzeCodePatterns = true;                   ///< Scan for anti-VM code patterns
            bool analyzeImports = true;                        ///< Check imported APIs
            bool analyzeStrings = true;                        ///< Search for VM-related strings
            bool analyzeMemoryRegions = false;                 ///< Deep memory analysis (slow)
            bool includeSystemProcesses = false;               ///< Include system processes

            uint32_t timeoutMs = 10000;                        ///< Analysis timeout per process
            size_t maxMemoryToScan = 64 * 1024 * 1024;        ///< Max memory to scan per process

            const std::atomic<bool>* cancelFlag = nullptr;
        };

        /**
         * @brief Statistics about VM detection operations
         */
        struct VMDetectionStatistics {
            std::atomic<uint64_t> totalDetections{ 0 };         ///< Total detection runs
            std::atomic<uint64_t> vmDetectedCount{ 0 };         ///< Times VM was detected
            std::atomic<uint64_t> cacheHits{ 0 };               ///< Cache hit count
            std::atomic<uint64_t> cacheMisses{ 0 };             ///< Cache miss count
            std::atomic<uint64_t> totalArtifactsFound{ 0 };     ///< Total artifacts found
            std::atomic<uint64_t> totalProcessesAnalyzed{ 0 };  ///< Total processes analyzed
            std::atomic<uint64_t> antiVMBehaviorDetected{ 0 };  ///< Anti-VM behavior detections

            // Timing statistics
            std::atomic<uint64_t> totalDetectionTimeNs{ 0 };    ///< Cumulative detection time
            std::atomic<uint64_t> minDetectionTimeNs{ UINT64_MAX };
            std::atomic<uint64_t> maxDetectionTimeNs{ 0 };

            // Per-category statistics
            std::array<std::atomic<uint64_t>, 16> categoryTriggerCounts{};

            /**
             * @brief Get average detection time in nanoseconds
             */
            [[nodiscard]] uint64_t GetAverageDetectionTimeNs() const noexcept {
                const uint64_t total = totalDetections.load(std::memory_order_relaxed);
                if (total == 0) return 0;
                return totalDetectionTimeNs.load(std::memory_order_relaxed) / total;
            }

            /**
             * @brief Get cache hit rate (0.0 to 1.0)
             */
            [[nodiscard]] double GetCacheHitRate() const noexcept {
                const uint64_t hits = cacheHits.load(std::memory_order_relaxed);
                const uint64_t misses = cacheMisses.load(std::memory_order_relaxed);
                const uint64_t total = hits + misses;
                if (total == 0) return 0.0;
                return static_cast<double>(hits) / static_cast<double>(total);
            }

            /**
             * @brief Reset all statistics
             */
            void Reset() noexcept {
                totalDetections.store(0, std::memory_order_relaxed);
                vmDetectedCount.store(0, std::memory_order_relaxed);
                cacheHits.store(0, std::memory_order_relaxed);
                cacheMisses.store(0, std::memory_order_relaxed);
                totalArtifactsFound.store(0, std::memory_order_relaxed);
                totalProcessesAnalyzed.store(0, std::memory_order_relaxed);
                antiVMBehaviorDetected.store(0, std::memory_order_relaxed);
                totalDetectionTimeNs.store(0, std::memory_order_relaxed);
                minDetectionTimeNs.store(UINT64_MAX, std::memory_order_relaxed);
                maxDetectionTimeNs.store(0, std::memory_order_relaxed);
                for (auto& counter : categoryTriggerCounts) {
                    counter.store(0, std::memory_order_relaxed);
                }
            }
        };

        // ============================================================================
        // CALLBACK TYPES
        // ============================================================================

        /**
         * @brief Callback invoked when a VM artifact is detected
         * @param artifact The detected artifact
         * @return true to continue detection, false to abort
         */
        using ArtifactCallback = std::function<bool(const VMArtifact& artifact)>;

        /**
         * @brief Callback for progress reporting during detection
         * @param category Current detection category
         * @param progress Progress within category (0.0 to 1.0)
         * @param message Status message
         * @return true to continue, false to cancel
         */
        using ProgressCallback = std::function<bool(VMDetectionCategory category, float progress, std::wstring_view message)>;

        // ============================================================================
        // VMEvasionDetector CLASS
        // ============================================================================

        /**
         * @brief Enterprise-grade detector for VM/hypervisor environments
         *
         * This class provides comprehensive detection of virtualization environments
         * and analysis of anti-VM techniques used by malware. It is thread-safe for
         * concurrent use and supports caching of detection results.
         *
         * Thread Safety:
         * - All public methods are thread-safe
         * - Detection can run concurrently from multiple threads
         * - Configuration changes require exclusive access (use SetConfig)
         *
         * Performance Characteristics:
         * - Quick detection (CPUID only): ~1ms
         * - Standard detection: ~50ms
         * - Deep analysis: ~200ms
         *
         * @see VMDetectionConfig for configuration options
         * @see VMEvasionResult for detection results
         */
        class VMEvasionDetector {
        public:
            // ========================================================================
            // Constructors and Destructor
            // ========================================================================

            /**
             * @brief Default constructor with optional ThreatIntel integration
             * @param threatStore Optional ThreatIntelStore for enhanced artifact correlation
             * @param config Detection configuration (defaults to standard config)
             */
            explicit VMEvasionDetector(
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatStore = nullptr,
                const VMDetectionConfig& config = VMDetectionConfig::CreateDefault()
            );

            /**
             * @brief Constructor with SignatureStore integration for code pattern matching
             * @param threatStore Optional ThreatIntelStore
             * @param signatureStore Optional SignatureStore for anti-VM code detection
             * @param config Detection configuration
             */
            VMEvasionDetector(
                std::shared_ptr<ThreatIntel::ThreatIntelStore> threatStore,
                std::shared_ptr<SignatureStore::SignatureStore> signatureStore,
                const VMDetectionConfig& config = VMDetectionConfig::CreateDefault()
            );

            /**
             * @brief Destructor - cleans up resources and stops any background operations
             */
            ~VMEvasionDetector();

            // Non-copyable
            VMEvasionDetector(const VMEvasionDetector&) = delete;
            VMEvasionDetector& operator=(const VMEvasionDetector&) = delete;

            // Movable
            VMEvasionDetector(VMEvasionDetector&&) noexcept;
            VMEvasionDetector& operator=(VMEvasionDetector&&) noexcept;

            // ========================================================================
            // Primary Detection API
            // ========================================================================

            /**
             * @brief Performs comprehensive VM environment detection
             *
             * This is the primary detection method that scans the system for VM indicators
             * using all enabled detection categories. Results may be cached based on
             * configuration.
             *
             * @return VMEvasionResult containing detection results and artifacts
             *
             * @note Thread-safe - can be called concurrently
             * @note May use cached results if caching is enabled
             * @see InvalidateCache() to force fresh detection
             */
            [[nodiscard]] VMEvasionResult DetectEnvironment();

            /**
             * @brief Performs detection with custom configuration
             *
             * Allows overriding the detector's configuration for a single detection run.
             *
             * @param config Custom configuration for this detection
             * @return VMEvasionResult containing detection results
             *
             * @note Results from custom config are NOT cached
             */
            [[nodiscard]] VMEvasionResult DetectEnvironment(const VMDetectionConfig& config);

            /**
             * @brief Performs detection with progress callback
             *
             * Same as DetectEnvironment() but provides progress updates during detection.
             *
             * @param callback Progress callback (return false to cancel)
             * @return VMEvasionResult containing detection results
             */
            [[nodiscard]] VMEvasionResult DetectEnvironmentWithProgress(ProgressCallback callback);

            /**
             * @brief Performs quick CPUID-only detection
             *
             * Fast path that only checks CPUID for hypervisor presence. Useful when
             * you need a quick yes/no answer with minimal overhead.
             *
             * @return CPUIDInfo with hypervisor detection results
             *
             * @note Always returns fresh results (not cached)
             * @note ~1ms typical execution time
             */
            [[nodiscard]] CPUIDInfo QuickDetectCPUID();

            /**
             * @brief Check if running in any VM environment (fast path)
             *
             * Performs minimal checks to quickly determine if running in a VM.
             * Does not collect detailed artifacts.
             *
             * @return true if VM detected, false otherwise
             *
             * @note Uses cached result if available
             * @note ~1ms typical execution time
             */
            [[nodiscard]] bool IsRunningInVM();

            // ========================================================================
            // Process Analysis API
            // ========================================================================

            /**
             * @brief Analyzes a specific process for anti-VM behavior
             *
             * Scans the target process for code patterns and behaviors that indicate
             * attempts to detect VM environments (common in malware).
             *
             * @param processId Target process ID
             * @param result Output: Analysis results
             * @param config Optional analysis configuration
             * @return true if analysis completed successfully, false on error
             *
             * @note Requires appropriate privileges to access target process
             */
            [[nodiscard]] bool AnalyzeProcessAntiVMBehavior(
                Utils::ProcessUtils::ProcessId processId,
                ProcessVMEvasionResult& result,
                const ProcessAnalysisConfig& config = {}
            );

            /**
             * @brief Analyzes multiple processes for anti-VM behavior (batch)
             *
             * @param processIds List of process IDs to analyze
             * @param results Output: Map of process ID to analysis result
             * @param config Optional analysis configuration
             * @return Number of processes successfully analyzed
             */
            [[nodiscard]] size_t AnalyzeProcessesBatch(
                std::span<const Utils::ProcessUtils::ProcessId> processIds,
                std::unordered_map<Utils::ProcessUtils::ProcessId, ProcessVMEvasionResult>& results,
                const ProcessAnalysisConfig& config = {}
            );

            /**
             * @brief Scans all running processes for anti-VM behavior
             *
             * @param results Output: Map of process ID to analysis result
             * @param config Optional analysis configuration
             * @return Number of processes with anti-VM behavior detected
             */
            [[nodiscard]] size_t ScanAllProcesses(
                std::unordered_map<Utils::ProcessUtils::ProcessId, ProcessVMEvasionResult>& results,
                const ProcessAnalysisConfig& config = {}
            );

            // ========================================================================
            // Extended Analysis API (Zydis + PEParser Integration)
            // ========================================================================

            /**
             * @brief Performs extended process analysis with Zydis disassembly and PE parsing
             *
             * This is the enterprise-grade analysis method that combines:
             * - Zydis-based instruction-level anti-VM detection
             * - PEParser-based import and section analysis
             * - Entropy calculation for packed code detection
             * - TLS callback analysis
             *
             * @param processId Target process ID
             * @param result Output: Extended analysis results
             * @param config Analysis configuration
             * @return true if analysis completed successfully
             */
            [[nodiscard]] bool AnalyzeProcessExtended(
                Utils::ProcessUtils::ProcessId processId,
                ExtendedProcessAnalysis& result,
                const ExtendedAnalysisConfig& config = {}
            );

            /**
             * @brief Analyzes a PE file for anti-VM indicators
             *
             * Performs static analysis of a PE file without executing it:
             * - Import table analysis for anti-VM APIs
             * - Section entropy analysis for packing detection
             * - Entry point anomaly detection
             * - TLS callback enumeration
             *
             * @param filePath Path to PE file
             * @param result Output: PE analysis results
             * @param config Analysis configuration
             * @return true if analysis completed successfully
             */
            [[nodiscard]] bool AnalyzePEFile(
                const std::wstring& filePath,
                PEAnalysisResult& result,
                const ExtendedAnalysisConfig& config = {}
            );

            /**
             * @brief Analyzes a memory buffer for anti-VM code patterns using Zydis
             *
             * Disassembles the provided buffer and identifies anti-VM instructions:
             * - CPUID, RDTSC, SIDT, SGDT, SLDT, STR
             * - IN/OUT port access instructions
             * - VMCALL, VMMCALL, VMX instructions
             * - Timing attack patterns (RDTSC sandwiches)
             *
             * @param buffer Memory buffer to analyze
             * @param virtualAddress Base VA for disassembly (for proper addressing)
             * @param is64Bit True for x64 code, false for x86
             * @param result Output: Code analysis results
             * @param config Analysis configuration
             * @return true if analysis completed successfully
             */
            [[nodiscard]] bool AnalyzeCodeBuffer(
                std::span<const uint8_t> buffer,
                uint64_t virtualAddress,
                bool is64Bit,
                CodeAnalysisResult& result,
                const ExtendedAnalysisConfig& config = {}
            );

            /**
             * @brief Batch analysis of multiple PE files
             *
             * @param filePaths List of PE file paths
             * @param results Output: Map of path to analysis result
             * @param config Analysis configuration
             * @return Number of files successfully analyzed
             */
            [[nodiscard]] size_t AnalyzePEFilesBatch(
                std::span<const std::wstring> filePaths,
                std::unordered_map<std::wstring, PEAnalysisResult>& results,
                const ExtendedAnalysisConfig& config = {}
            );

            /**
             * @brief Checks if a specific import is associated with anti-VM behavior
             *
             * @param dllName Source DLL name
             * @param functionName Imported function name
             * @return Associated technique, or AntiVMTechnique::None
             */
            [[nodiscard]] static AntiVMTechnique ClassifyImport(
                std::string_view dllName,
                std::string_view functionName
            );

            /**
             * @brief Gets the evasion score for a specific instruction mnemonic
             *
             * @param mnemonic Instruction mnemonic (lowercase)
             * @return Score contribution (0-100), 0 if not anti-VM related
             */
            [[nodiscard]] static float GetInstructionEvasionScore(std::string_view mnemonic);

            // ========================================================================
            // Individual Detection Methods
            // ========================================================================

            /**
             * @brief Performs CPUID-based hypervisor detection
             * @param result Output: Detection results to update
             */
            void CheckCPUID(VMEvasionResult& result);

            /**
             * @brief Scans Windows Registry for VM artifacts
             * @param result Output: Detection results to update
             */
            void CheckRegistryArtifacts(VMEvasionResult& result);

            /**
             * @brief Checks file system for VM-related drivers and tools
             * @param result Output: Detection results to update
             */
            void CheckFileArtifacts(VMEvasionResult& result);

            /**
             * @brief Checks network adapters for VM-associated MAC addresses
             * @param result Output: Detection results to update
             */
            void CheckNetworkAdapters(VMEvasionResult& result);

            /**
             * @brief Checks SMBIOS/ACPI firmware tables for VM signatures
             * @param result Output: Detection results to update
             */
            void CheckFirmwareTables(VMEvasionResult& result);

            /**
             * @brief Enumerates running processes for VM tools
             * @param result Output: Detection results to update
             */
            void CheckRunningProcesses(VMEvasionResult& result);

            /**
             * @brief Performs timing-based VM detection
             * @param result Output: Detection results to update
             * @warning May produce false positives on heavily loaded systems
             */
            void CheckTiming(VMEvasionResult& result);

            /**
             * @brief Probes known VM I/O ports
             * @param result Output: Detection results to update
             * @warning May cause issues in some VM environments
             */
            void CheckIOPorts(VMEvasionResult& result);

            /**
             * @brief Scans memory for VM-related artifacts
             * @param result Output: Detection results to update
             */
            void CheckMemoryArtifacts(VMEvasionResult& result);

            /**
             * @brief Enumerates devices for VM-specific hardware IDs
             * @param result Output: Detection results to update
             */
            void CheckDevices(VMEvasionResult& result);

            /**
             * @brief Performs WMI queries for VM detection
             * @param result Output: Detection results to update
             */
            void CheckWMI(VMEvasionResult& result);

            /**
             * @brief Enumerates windows for VM tool window classes
             * @param result Output: Detection results to update
             */
            void CheckWindows(VMEvasionResult& result);

            // ========================================================================
            // Configuration API
            // ========================================================================

            /**
             * @brief Gets the current detection configuration
             * @return Current configuration (copy)
             */
            [[nodiscard]] VMDetectionConfig GetConfig() const;

            /**
             * @brief Sets a new detection configuration
             * @param config New configuration to use
             * @note Invalidates cache when configuration changes
             */
            void SetConfig(const VMDetectionConfig& config);

            /**
             * @brief Updates a specific category's weight
             * @param category Category to update
             * @param weight New weight value
             */
            void SetCategoryWeight(VMDetectionCategory category, float weight);

            /**
             * @brief Enables or disables a detection category
             * @param category Category to modify
             * @param enabled True to enable, false to disable
             */
            void SetCategoryEnabled(VMDetectionCategory category, bool enabled);

            // ========================================================================
            // Cache Management
            // ========================================================================

            /**
             * @brief Invalidates the detection cache
             * Forces next detection to perform fresh checks.
             */
            void InvalidateCache();

            /**
             * @brief Gets the cached result if available and valid
             * @return Cached result, or nullopt if cache invalid/expired
             */
            [[nodiscard]] std::optional<VMEvasionResult> GetCachedResult() const;

            /**
             * @brief Checks if cache is valid and not expired
             * @return true if cached result is available and valid
             */
            [[nodiscard]] bool IsCacheValid() const;

            // ========================================================================
            // Statistics API
            // ========================================================================

            /**
             * @brief Gets detection statistics
             * @return Reference to statistics (thread-safe for reading)
             */
            [[nodiscard]] const VMDetectionStatistics& GetStatistics() const;

            /**
             * @brief Resets detection statistics
             */
            void ResetStatistics();

            // ========================================================================
            // Utility Methods
            // ========================================================================

            /**
             * @brief Converts VMType enum to human-readable string
             * @param type VM type to convert
             * @return Wide string name of the VM type
             */
            [[nodiscard]] static std::wstring VMTypeToString(VMType type);

            /**
             * @brief Converts VMDetectionCategory to human-readable string
             * @param category Category to convert
             * @return Wide string name of the category
             */
            [[nodiscard]] static std::wstring CategoryToString(VMDetectionCategory category);

            /**
             * @brief Converts AntiVMTechnique to human-readable string
             * @param technique Technique to convert
             * @return Wide string description of the technique
             */
            [[nodiscard]] static std::wstring TechniqueToString(AntiVMTechnique technique);

            /**
             * @brief Converts VMConfidenceLevel to human-readable string
             * @param level Confidence level to convert
             * @return Wide string name of the confidence level
             */
            [[nodiscard]] static std::wstring ConfidenceLevelToString(VMConfidenceLevel level);

            /**
             * @brief Parses hypervisor vendor string to VMType
             * @param vendorString 12-byte CPUID vendor string
             * @return Detected VM type, or VMType::Unknown
             */
            [[nodiscard]] static VMType ParseHypervisorVendor(std::string_view vendorString);

            /**
             * @brief Checks if a MAC address matches known VM OUI prefixes
             * @param mac MAC address to check
             * @return Associated VM type, or VMType::None if not a VM MAC
             */
            [[nodiscard]] static VMType CheckMACAddress(const Utils::NetworkUtils::MacAddress& mac);

            /**
             * @brief Gets all known VM-related process names
             * @return Span of known VM process names
             */
            [[nodiscard]] static std::span<const std::wstring_view> GetKnownVMProcesses();

            /**
             * @brief Gets all known VM registry keys
             * @return Span of known VM registry key paths
             */
            [[nodiscard]] static std::span<const std::wstring_view> GetKnownVMRegistryKeys();

            /**
             * @brief Gets all known VM file paths
             * @return Span of known VM file paths
             */
            [[nodiscard]] static std::span<const std::wstring_view> GetKnownVMFiles();

        private:
            // ========================================================================
            // Private Implementation
            // ========================================================================

            struct Impl;
            std::unique_ptr<Impl> m_impl;

            // ========================================================================
            // Internal Helper Methods
            // ========================================================================

            /**
             * @brief Initializes internal state and caches
             */
            void Initialize();

            /**
             * @brief Adds an artifact to the result with proper deduplication
             */
            void AddArtifact(
                VMEvasionResult& result,
                VMDetectionCategory category,
                VMType vmType,
                float confidence,
                std::wstring_view description,
                std::wstring_view rawValue,
                std::wstring_view location
            );

            /**
             * @brief Calculates final confidence score from individual category scores
             */
            void CalculateFinalScore(VMEvasionResult& result);

            /**
             * @brief Determines primary VM type from collected artifacts
             */
            void DetermineVMType(VMEvasionResult& result);

            /**
             * @brief Queries ThreatIntel for known VM artifacts
             */
            [[nodiscard]] bool IsKnownVMArtifact(
                const std::wstring& artifactName,
                const std::wstring& artifactType
            );

            /**
             * @brief Executes CPUID instruction safely
             */
            [[nodiscard]] bool SafeCPUID(uint32_t leaf, uint32_t subleaf, int32_t* regs);

            /**
             * @brief Reads VMware backdoor port (safely)
             */
            [[nodiscard]] bool TryVMwareBackdoor(uint32_t& response);

            /**
             * @brief Performs timing measurement for RDTSC-based detection
             */
            [[nodiscard]] uint64_t MeasureRDTSCDelta(uint32_t iterations);

            /**
             * @brief Checks if detection should be cancelled
             */
            [[nodiscard]] bool IsCancelled() const;

            /**
             * @brief Updates statistics after detection
             */
            void UpdateStatistics(const VMEvasionResult& result, std::chrono::nanoseconds duration);
        };

        // ============================================================================
        // HELPER FREE FUNCTIONS
        // ============================================================================

        /**
         * @brief Quick check if running in a VM (convenience function)
         *
         * Creates a temporary detector and performs quick CPUID-based detection.
         * For repeated checks, create a VMEvasionDetector instance instead.
         *
         * @return true if VM detected, false otherwise
         */
        [[nodiscard]] bool IsVirtualMachine();

        /**
         * @brief Quick detection with result (convenience function)
         *
         * @return VMEvasionResult with detection results
         */
        [[nodiscard]] VMEvasionResult QuickVMDetection();

        /**
         * @brief Full VM detection (convenience function)
         *
         * @return VMEvasionResult with comprehensive detection results
         */
        [[nodiscard]] VMEvasionResult FullVMDetection();

    }  // namespace AntiEvasion
}  // namespace ShadowStrike