/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\AccessControlManager deterministic contracts.
 *
 * Focus:
 *   - configuration and restriction/protection preset factories
 *   - statistics reset and SID/validation helper behavior
 *   - callback registration and safe default-state accessors
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/RealTime/AccessControlManager.hpp"
#include "RealTime_TestUtils.hpp"

namespace ShadowStrike::RealTime::Tests {

class AccessControlManagerTest : public ::testing::Test {
protected:
    AccessControlManager& manager = AccessControlManager::Instance();

    void SetUp() override {
        manager.Shutdown();
        manager.ResetStatistics();
    }

    void TearDown() override {
        manager.Shutdown();
    }
};

TEST_F(AccessControlManagerTest, FactoryProfilesPreserveExpectedSecurityDefaults) {
    const auto defaults = AccessControlManagerConfig::CreateDefault();
    const auto enterprise = AccessControlManagerConfig::CreateEnterprise();
    const auto msp = AccessControlManagerConfig::CreateMSP();
    const auto standalone = AccessControlManagerConfig::CreateStandalone();

    EXPECT_TRUE(defaults.enableRBAC);
    EXPECT_TRUE(defaults.requireMFAForAdmin);
    EXPECT_EQ(ProcessProtectionLevel::ELEVATED, defaults.defaultProtectionLevel);
    EXPECT_FALSE(defaults.auditAllAccessDecisions);

    EXPECT_TRUE(enterprise.requireMFAForAdmin);
    EXPECT_TRUE(enterprise.requireMFAForElevation);
    EXPECT_TRUE(enterprise.autoStripDangerousPrivileges);
    EXPECT_EQ(ProcessProtectionLevel::MAXIMUM, enterprise.defaultProtectionLevel);
    EXPECT_TRUE(enterprise.auditAllAccessDecisions);

    EXPECT_TRUE(msp.enableMultiTenant);
    EXPECT_TRUE(msp.auditAllAccessDecisions);

    EXPECT_TRUE(standalone.enableRBAC);
    EXPECT_FALSE(standalone.requireMFAForAdmin);
    EXPECT_TRUE(standalone.auditDeniedOnly);

    const auto minimal = ProcessRestrictionConfig::CreateMinimal();
    const auto moderate = ProcessRestrictionConfig::CreateModerate();
    const auto strict = ProcessRestrictionConfig::CreateStrict();
    const auto sandbox = ProcessRestrictionConfig::CreateSandbox();

    EXPECT_TRUE(minimal.stripAllPrivileges);
    EXPECT_FALSE(minimal.applyJobObject);

    EXPECT_TRUE(moderate.stripAllPrivileges);
    EXPECT_TRUE(moderate.applyJobObject);
    EXPECT_EQ(AccessControlConstants::DEFAULT_MEMORY_LIMIT_BYTES, moderate.memoryLimitBytes);

    EXPECT_TRUE(strict.applyJobObject);
    EXPECT_EQ(256ULL * 1024ULL * 1024ULL, strict.memoryLimitBytes);
    EXPECT_EQ(5u, strict.processLimit);
    EXPECT_EQ(25u, strict.cpuRateLimit);
    EXPECT_TRUE(strict.forceIntegrity);
    EXPECT_EQ(IntegrityLevel::LOW, strict.targetIntegrity);

    EXPECT_EQ(RestrictionType::FULL_SANDBOX, sandbox.primaryRestriction);
    EXPECT_TRUE(sandbox.blockNetwork);
    EXPECT_TRUE(sandbox.disableMaxPrivilege);

    const auto defaultProtection = ProcessProtectionConfig::CreateDefault();
    const auto maximumProtection = ProcessProtectionConfig::CreateMaximum();
    const auto serviceProtection = ProcessProtectionConfig::CreateForService();
    const auto driverProtection = ProcessProtectionConfig::CreateForDriver();

    EXPECT_EQ(ProcessProtectionLevel::STANDARD, defaultProtection.level);
    EXPECT_TRUE(defaultProtection.protectHandles);
    EXPECT_FALSE(defaultProtection.blockThreadCreation);

    EXPECT_EQ(ProcessProtectionLevel::MAXIMUM, maximumProtection.level);
    EXPECT_TRUE(maximumProtection.blockThreadCreation);
    EXPECT_TRUE(maximumProtection.blockMemoryRead);
    EXPECT_TRUE(maximumProtection.blockMemoryWrite);
    EXPECT_TRUE(maximumProtection.blockMemoryExecute);

    EXPECT_EQ(ProcessProtectionLevel::ELEVATED, serviceProtection.level);
    EXPECT_TRUE(serviceProtection.blockThreadCreation);
    EXPECT_TRUE(serviceProtection.preventTerminate);

    EXPECT_EQ(ProcessProtectionLevel::PPL_ANTIMALWARE, driverProtection.level);
    EXPECT_TRUE(driverProtection.blockMemoryWrite);
    EXPECT_TRUE(driverProtection.protectDLLs);
}

TEST_F(AccessControlManagerTest, StatisticsResetAndIdentityHelpersStayDeterministic) {
    AccessControlStatistics stats;
    stats.totalPermissionChecks = 11;
    stats.permissionsGranted = 7;
    stats.permissionsDenied = 4;
    stats.permissionsCached = 3;
    stats.sessionsCreated = 5;
    stats.sessionsExpired = 2;
    stats.sessionsRevoked = 1;
    stats.activeSessions = 6;
    stats.mfaChallenges = 3;
    stats.mfaSuccesses = 2;
    stats.mfaFailures = 1;
    stats.privilegeStrips = 8;
    stats.integrityLowerings = 1;
    stats.processRestrictions = 4;
    stats.processProtections = 2;
    stats.tamperAttempts = 9;
    stats.tamperBlocked = 8;
    stats.errorCount = 1;
    stats.cacheHits = 12;
    stats.cacheMisses = 6;
    stats.totalCheckTimeUs = 900;
    stats.maxCheckTimeUs = 111;

    stats.Reset();

    EXPECT_EQ(0u, stats.totalPermissionChecks);
    EXPECT_EQ(0u, stats.permissionsGranted);
    EXPECT_EQ(0u, stats.permissionsDenied);
    EXPECT_EQ(0u, stats.activeSessions);
    EXPECT_EQ(0u, stats.privilegeStrips);
    EXPECT_EQ(0u, stats.tamperAttempts);
    EXPECT_EQ(0u, stats.cacheHits);
    EXPECT_EQ(0u, stats.maxCheckTimeUs);

    const SecurityIdentifier localSystemSid = AccessControlManager::ParseSid(L"S-1-5-18");
    EXPECT_TRUE(localSystemSid.isValid);
    EXPECT_FALSE(localSystemSid.binarySid.empty());
    EXPECT_EQ(std::wstring(L"S-1-5-18"), AccessControlManager::SidToString(localSystemSid.binarySid));

    const SecurityIdentifier invalidSid = AccessControlManager::ParseSid(L"not-a-sid");
    EXPECT_FALSE(invalidSid.isValid);
    EXPECT_TRUE(AccessControlManager::SidToString(std::span<const uint8_t>{}).empty());

    EXPECT_EQ(std::wstring_view(L"PROTECTION_ENABLE"),
        AccessControlManager::GetPermissionName(Permission::PROTECTION_ENABLE));
    EXPECT_EQ(std::wstring_view(L"SOC_ANALYST_L2"),
        AccessControlManager::GetRoleName(RoleType::SOC_ANALYST_L2));
    EXPECT_EQ(std::wstring_view(L"SeDebugPrivilege"),
        AccessControlManager::GetPrivilegeName(WindowsPrivilege::SE_DEBUG));
    EXPECT_TRUE(AccessControlManager::IsDangerousPrivilege(WindowsPrivilege::SE_DEBUG));
    EXPECT_FALSE(AccessControlManager::IsDangerousPrivilege(WindowsPrivilege::SE_CHANGE_NOTIFY));

    RoleDefinition role;
    role.type = RoleType::SECURITY_ADMIN;
    role.grantedPermissions.set(static_cast<size_t>(Permission::PROTECTION_ENABLE));
    role.grantedPermissions.set(static_cast<size_t>(Permission::LOG_VIEW_EVENTS));

    std::bitset<AccessControlConstants::MAX_PERMISSIONS> creatorPermissions;
    creatorPermissions.set(static_cast<size_t>(Permission::PROTECTION_ENABLE));
    creatorPermissions.set(static_cast<size_t>(Permission::LOG_VIEW_EVENTS));
    EXPECT_TRUE(AccessControlManager::ValidateRolePermissions(role, creatorPermissions));

    creatorPermissions.reset(static_cast<size_t>(Permission::LOG_VIEW_EVENTS));
    EXPECT_FALSE(AccessControlManager::ValidateRolePermissions(role, creatorPermissions));

    EXPECT_TRUE(AccessControlManager::IsValidRoleType(RoleType::STANDARD_USER));
    EXPECT_TRUE(AccessControlManager::IsValidRoleType(static_cast<RoleType>(150)));
    EXPECT_FALSE(AccessControlManager::IsValidRoleType(RoleType::INVALID));
    EXPECT_TRUE(AccessControlManager::IsValidPermission(Permission::API_ADMIN));
    EXPECT_FALSE(AccessControlManager::IsValidPermission(Permission::INVALID_PERMISSION));
    EXPECT_TRUE(AccessControlManager::IsValidIntegrityLevel(
        AccessControlManager::GetCurrentIntegrityLevel()));
}

TEST_F(AccessControlManagerTest, CallbackRegistrationAndDefaultStateRemainSafe) {
    const auto initialStats = manager.GetStatistics();
    EXPECT_EQ(0u, initialStats.totalPermissionChecks);
    EXPECT_EQ(0u, initialStats.permissionsDenied);

    const uint64_t permissionId = manager.RegisterPermissionCheckCallback(
        [](AccessDecision, Permission, const SecurityIdentifier&, std::wstring_view) {});
    const uint64_t sessionId = manager.RegisterSessionEventCallback(
        [](uint64_t, SessionState, SessionState, const SecurityIdentifier&) {});
    const uint64_t tamperId = manager.RegisterTamperAttemptCallback(
        [](uint32_t, uint32_t, std::wstring_view) {});
    const uint64_t auditId = manager.RegisterAuditEventCallback(
        [](const AccessControlAuditEvent&) {});
    const uint64_t privilegeId = manager.RegisterPrivilegeModificationCallback(
        [](uint32_t, WindowsPrivilege, PrivilegeAction, bool) {});

    EXPECT_NE(0u, permissionId);
    EXPECT_NE(0u, sessionId);
    EXPECT_NE(0u, tamperId);
    EXPECT_NE(0u, auditId);
    EXPECT_NE(0u, privilegeId);

    EXPECT_TRUE(manager.UnregisterCallback(permissionId));
    EXPECT_TRUE(manager.UnregisterCallback(sessionId));
    EXPECT_TRUE(manager.UnregisterCallback(tamperId));
    EXPECT_TRUE(manager.UnregisterCallback(auditId));
    EXPECT_TRUE(manager.UnregisterCallback(privilegeId));
    EXPECT_FALSE(manager.UnregisterCallback(privilegeId));
    EXPECT_FALSE(manager.UnregisterCallback(0));
}

TEST_F(AccessControlManagerTest, UnknownHelperMappingsFallBackToExplicitSentinels) {
    EXPECT_EQ(std::wstring_view(L"UNKNOWN"),
        AccessControlManager::GetPermissionName(Permission::INVALID_PERMISSION));
    EXPECT_EQ(std::wstring_view(L"CUSTOM"),
        AccessControlManager::GetRoleName(RoleType::INVALID));
    EXPECT_EQ(std::wstring_view(L"Unknown"),
        AccessControlManager::GetPrivilegeName(WindowsPrivilege::INVALID_PRIVILEGE));
}

}  // namespace ShadowStrike::RealTime::Tests
