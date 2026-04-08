/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "AntiEvasion_TestUtils.hpp"
#include "../../../src/Shared_modules/AntiEvasion/VMEvasionDetector.hpp"

namespace ShadowStrike::AntiEvasion::Tests {

TEST(VMEvasionDetector_Helpers, StringHelpersReturnStableLabels) {
    EXPECT_EQ(L"VMware", VMEvasionDetector::VMTypeToString(VMType::VMware));
    EXPECT_EQ(L"Microsoft Hyper-V", VMEvasionDetector::VMTypeToString(VMType::HyperV));
    EXPECT_EQ(L"Unknown", VMEvasionDetector::VMTypeToString(VMType::Unknown));

    EXPECT_EQ(L"CPUID", VMEvasionDetector::CategoryToString(VMDetectionCategory::CPUID));
    EXPECT_EQ(L"Behavior Analysis", VMEvasionDetector::CategoryToString(VMDetectionCategory::BehaviorAnalysis));

    EXPECT_EQ(L"CPUID-based Detection", VMEvasionDetector::TechniqueToString(AntiVMTechnique::CPUIDHypervisorCheck));
    EXPECT_EQ(L"Registry-based Detection", VMEvasionDetector::TechniqueToString(AntiVMTechnique::RegistryKeyCheck));
    EXPECT_EQ(L"Definitive", VMEvasionDetector::ConfidenceLevelToString(VMConfidenceLevel::Definitive));
}

TEST(VMEvasionDetector_Classification, ImportClassificationMapsRepresentativeAPIs) {
    EXPECT_EQ(AntiVMTechnique::GetTickCountTiming,
        VMEvasionDetector::ClassifyImport("kernel32.dll", "GetTickCount64"));
    EXPECT_EQ(AntiVMTechnique::QPCTiming,
        VMEvasionDetector::ClassifyImport("kernel32", "QueryPerformanceCounter"));
    EXPECT_EQ(AntiVMTechnique::CPUIDHypervisorCheck,
        VMEvasionDetector::ClassifyImport("ntdll.dll", "__cpuidex"));
    EXPECT_EQ(AntiVMTechnique::RegistryKeyCheck,
        VMEvasionDetector::ClassifyImport("advapi32.dll", "RegOpenKeyExW"));
    EXPECT_EQ(AntiVMTechnique::WMIQuery,
        VMEvasionDetector::ClassifyImport("ole32.dll", "CoCreateInstance"));
    EXPECT_EQ(AntiVMTechnique::MACAddressCheck,
        VMEvasionDetector::ClassifyImport("iphlpapi.dll", "GetAdaptersAddresses"));
    EXPECT_EQ(AntiVMTechnique::None,
        VMEvasionDetector::ClassifyImport("kernel32.dll", "IsDebuggerPresent"));
    EXPECT_EQ(AntiVMTechnique::None,
        VMEvasionDetector::ClassifyImport("unknown.dll", "UnknownExport"));
}

TEST(VMEvasionDetector_Heuristics, InstructionScoringAndContextUtilitiesBehavePredictably) {
    EXPECT_FLOAT_EQ(30.0f, VMEvasionDetector::GetInstructionEvasionScore("cpuid"));
    EXPECT_FLOAT_EQ(40.0f, VMEvasionDetector::GetInstructionEvasionScore("RDTSC"));
    EXPECT_FLOAT_EQ(95.0f, VMEvasionDetector::GetInstructionEvasionScore("vmcall"));
    EXPECT_FLOAT_EQ(0.0f, VMEvasionDetector::GetInstructionEvasionScore("mov"));

    const VMDetectionConfig defaultConfig = VMDetectionConfig::CreateDefault();
    EXPECT_TRUE(defaultConfig.IsCategoryEnabled(VMDetectionCategory::CPUID));
    EXPECT_TRUE(defaultConfig.IsCategoryEnabled(VMDetectionCategory::Registry));

    const VMDetectionConfig quickScan = VMDetectionConfig::CreateQuickScan();
    EXPECT_TRUE(quickScan.IsCategoryEnabled(VMDetectionCategory::CPUID));
    EXPECT_TRUE(quickScan.IsCategoryEnabled(VMDetectionCategory::Registry));
    EXPECT_FALSE(quickScan.IsCategoryEnabled(VMDetectionCategory::WMI));
    EXPECT_FALSE(quickScan.enableWMIQueries);
    EXPECT_FALSE(quickScan.enableProcessEnumeration);

    const VMDetectionConfig deepAnalysis = VMDetectionConfig::CreateDeepAnalysis();
    EXPECT_TRUE(deepAnalysis.deepAnalysis);
    EXPECT_TRUE(deepAnalysis.enableTimingChecks);
    EXPECT_TRUE(deepAnalysis.enableMemoryScanning);
    EXPECT_FLOAT_EQ(10.0f, deepAnalysis.minimumConfidenceThreshold);

    VMKernelContext emptyContext;
    EXPECT_FALSE(emptyContext.hasKernelData());

    VMKernelContext populatedContext;
    populatedContext.imagePath = L"C:\\Windows\\System32\\vmtoolsd.exe";
    EXPECT_TRUE(populatedContext.hasKernelData());
}

TEST(VMEvasionDetector_Utilities, VendorMacAndStatisticsHelpersRecognizeKnownSignals) {
    EXPECT_EQ(VMType::VMware, VMEvasionDetector::ParseHypervisorVendor(VMConstants::VENDOR_VMWARE));
    EXPECT_EQ(VMType::HyperV, VMEvasionDetector::ParseHypervisorVendor(VMConstants::VENDOR_HYPERV));
    EXPECT_EQ(VMType::VirtualBox, VMEvasionDetector::ParseHypervisorVendor(VMConstants::VENDOR_VBOX));
    EXPECT_EQ(VMType::Unknown, VMEvasionDetector::ParseHypervisorVendor("NotAHypervisor"));

    EXPECT_EQ(VMType::VMware, VMEvasionDetector::CheckMACAddress(MakeMac({ 0x00, 0x05, 0x69, 0x12, 0x34, 0x56 })));
    EXPECT_EQ(VMType::VirtualBox, VMEvasionDetector::CheckMACAddress(MakeMac({ 0x08, 0x00, 0x27, 0x12, 0x34, 0x56 })));
    EXPECT_EQ(VMType::HyperV, VMEvasionDetector::CheckMACAddress(MakeMac({ 0x00, 0x15, 0x5D, 0x12, 0x34, 0x56 })));
    EXPECT_EQ(VMType::None, VMEvasionDetector::CheckMACAddress(MakeMac({ 0xDE, 0xAD, 0xBE, 0x12, 0x34, 0x56 })));

    VMDetectionStatistics stats;
    stats.totalDetections = 4;
    stats.totalDetectionTimeNs = 800;
    stats.cacheHits = 3;
    stats.cacheMisses = 1;
    stats.vmDetectedCount = 2;
    stats.categoryTriggerCounts[static_cast<size_t>(VMDetectionCategory::CPUID)] = 1;

    EXPECT_EQ(200u, stats.GetAverageDetectionTimeNs());
    EXPECT_DOUBLE_EQ(0.75, stats.GetCacheHitRate());

    stats.Reset();

    EXPECT_EQ(0u, stats.totalDetections.load());
    EXPECT_EQ(0u, stats.vmDetectedCount.load());
    EXPECT_EQ(0u, stats.cacheHits.load());
    EXPECT_EQ(0u, stats.cacheMisses.load());
    EXPECT_EQ(0u, stats.totalDetectionTimeNs.load());
    EXPECT_EQ(UINT64_MAX, stats.minDetectionTimeNs.load());
    EXPECT_EQ(0u, stats.maxDetectionTimeNs.load());
    EXPECT_DOUBLE_EQ(0.0, stats.GetCacheHitRate());
}

} // namespace ShadowStrike::AntiEvasion::Tests
