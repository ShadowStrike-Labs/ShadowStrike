#include "../../../src/pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/RegistryProtection.hpp"
#include "../../../src/PhantomCore/SelfProtection/ProductExecutables.hpp"
#include "../../../src/PhantomCore/SelfProtection/DigitalSignatureValidator.hpp"

#include <array>
#include <filesystem>
#include <string>
#include <vector>

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(RegistryProtectionTests, ProtectionModesAndValidationRemainConsistent) {
    const RegistryProtectionConfiguration disabled =
        RegistryProtectionConfiguration::FromMode(RegistryProtectionMode::Disabled);
    EXPECT_FALSE(disabled.enableKernelCallbacks);
    EXPECT_FALSE(disabled.enableUserModePolling);
    EXPECT_FALSE(disabled.enableIntegrityMonitoring);
    EXPECT_FALSE(disabled.enableSnapshots);
    EXPECT_EQ(disabled.defaultResponse, RegistryProtectionResponse::None);

    const RegistryProtectionConfiguration rollback =
        RegistryProtectionConfiguration::FromMode(RegistryProtectionMode::Rollback);
    EXPECT_TRUE(rollback.enableKernelCallbacks);
    EXPECT_TRUE(rollback.enableAutoRollback);
    EXPECT_TRUE(rollback.enableSnapshots);
    EXPECT_EQ(static_cast<uint32_t>(rollback.defaultResponse),
              static_cast<uint32_t>(RegistryProtectionResponse::Active |
                                    RegistryProtectionResponse::Rollback));
    EXPECT_TRUE(rollback.IsValid());

    RegistryProtectionConfiguration invalid = rollback;
    invalid.pollingIntervalMs = 99;
    EXPECT_FALSE(invalid.IsValid());

    invalid = rollback;
    invalid.maxSnapshotsPerKey = 0;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(RegistryProtectionTests, EventsSerializeOperationAndDecisionFieldsPredictably) {
    RegistryProtectionEvent event{};
    event.eventId = 51;
    event.type = RegistryProtectionEventType::OperationBlocked;
    event.keyPath = L"HKLM\\Software\\ShadowStrike";
    event.valueName = L"Config";
    event.operation = RegistryOperation::SetValue;
    event.decision = RegistryOperationDecision::Block;
    event.sourceProcessId = 777;
    event.sourceProcessName = L"malware.exe";
    event.wasBlocked = true;
    event.wasRolledBack = true;
    event.description = "Protected configuration change denied";

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("BLOCKED SetValue on HKLM\\Software\\ShadowStrike\\Config"));
    EXPECT_THAT(summary, ::testing::HasSubstr("by PID 777"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 51);
    EXPECT_EQ(payload.at("keyPath").get<std::string>(), "HKLM\\Software\\ShadowStrike");
    EXPECT_EQ(payload.at("valueName").get<std::string>(), "Config");
    EXPECT_EQ(payload.at("operation").get<int>(),
              static_cast<int>(RegistryOperation::SetValue));
    EXPECT_EQ(payload.at("decision").get<int>(),
              static_cast<int>(RegistryOperationDecision::Block));
    EXPECT_TRUE(payload.at("wasBlocked").get<bool>());
    EXPECT_TRUE(payload.at("wasRolledBack").get<bool>());

    event.eventId = 52;
    event.valueName.clear();
    event.sourceProcessId = 0;
    event.sourceProcessName.clear();
    event.wasBlocked = false;
    event.wasRolledBack = false;

    const std::string pidlessSummary = event.GetSummary();
    EXPECT_THAT(pidlessSummary, ::testing::HasSubstr("ALLOWED SetValue on HKLM\\Software\\ShadowStrike"));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("\\Config")));
    EXPECT_THAT(pidlessSummary, ::testing::HasSubstr("by PID 0"));
}

TEST(RegistryProtectionTests, StatisticsAndHelperNamesPreservePublicContracts) {
    RegistryProtectionStatistics stats{};
    stats.totalProtectedKeys = 3;
    stats.totalProtectedValues = 12;
    stats.totalOperations = 40;
    stats.totalBlocked = 5;
    stats.totalRollbacks = 2;
    stats.snapshotsRestored = 1;

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalProtectedKeys").get<int>(), 3);
    EXPECT_EQ(payload.at("totalOperations").get<int>(), 40);
    EXPECT_EQ(payload.at("totalBlocked").get<int>(), 5);
    EXPECT_EQ(payload.at("snapshotsRestored").get<int>(), 1);
    EXPECT_GE(payload.at("uptimeSeconds").get<int64_t>(), 0);

    EXPECT_EQ(GetProtectionModeName(RegistryProtectionMode::Rollback), "Rollback");
    EXPECT_EQ(GetRegistryOperationName(RegistryOperation::RestoreKey), "RestoreKey");
    EXPECT_EQ(GetProtectionTypeName(KeyProtectionType::ValuesOnly), "ValuesOnly");
    EXPECT_EQ(GetIntegrityStatusName(RegistryIntegrityStatus::Restored), "Restored");
    EXPECT_EQ(GetValueTypeName(RegistryValueType::MultiString), "REG_MULTI_SZ");
}

// ============================================================================
// Identity, image hijack and restore (tasks 346, 242, 243)
//
// These run against the real registry under HKCU\Software\ShadowStrikeTests, which a
// standard user can write, and against real processes. The IFEO branch of
// VerifyKeyIntegrity needs HKLM and is pinned by the contract suite instead; the value
// inspection it calls is exercised here on an ordinary key.
// ============================================================================

namespace ProductExecutables = ShadowStrike::Security::ProductExecutables;

class ScratchKey {
public:
    ScratchKey()
        : subKey(L"Software\\ShadowStrikeTests\\RegistryProtection_" +
                 std::to_wstring(::GetCurrentProcessId()) + L"_" + std::to_wstring(::GetTickCount64()) +
                 L"_" + std::to_wstring(s_counter++)) {}
    ~ScratchKey() { (void)::RegDeleteTreeW(HKEY_CURRENT_USER, subKey.c_str()); }

    std::wstring Path() const { return L"HKCU\\" + subKey; }
    bool Exists() const {
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
            return false;
        }
        ::RegCloseKey(key);
        return true;
    }
    void SetString(const std::wstring& name, const std::wstring& value, const std::wstring& below = {}) const {
        const std::wstring target = below.empty() ? subKey : subKey + L"\\" + below;
        ASSERT_EQ(ERROR_SUCCESS, ::RegSetKeyValueW(HKEY_CURRENT_USER, target.c_str(), name.c_str(), REG_SZ,
                                                   value.c_str(),
                                                   static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))));
    }
    void SetDword(const std::wstring& name, DWORD value) const {
        ASSERT_EQ(ERROR_SUCCESS, ::RegSetKeyValueW(HKEY_CURRENT_USER, subKey.c_str(), name.c_str(), REG_DWORD,
                                                   &value, sizeof(value)));
    }
    std::optional<std::wstring> GetString(const std::wstring& name) const {
        wchar_t buffer[512]{};
        DWORD size = sizeof(buffer);
        if (::RegGetValueW(HKEY_CURRENT_USER, subKey.c_str(), name.c_str(), RRF_RT_REG_SZ, nullptr, buffer,
                           &size) != ERROR_SUCCESS) {
            return std::nullopt;
        }
        return std::wstring(buffer);
    }
    DWORD ValueCount() const {
        HKEY key = nullptr;
        DWORD values = 0;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, subKey.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS) {
            (void)::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &values, nullptr,
                                     nullptr, nullptr, nullptr);
            ::RegCloseKey(key);
        }
        return values;
    }
    bool SubkeyExists(const std::wstring& name) const {
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, (subKey + L"\\" + name).c_str(), 0, KEY_READ, &key) !=
            ERROR_SUCCESS) {
            return false;
        }
        ::RegCloseKey(key);
        return true;
    }
    std::wstring subKey;

private:
    static inline int s_counter = 0;
};

// A renamed copy of a Microsoft-signed binary, running. waitfor.exe waits for a signal
// that never comes, so the process stays alive until the destructor ends it.
class RunningCopy {
public:
    RunningCopy(const std::filesystem::path& directory, const std::wstring& fileName) : dir(directory) {
        std::filesystem::create_directories(dir);
        image = dir / fileName;
        wchar_t system[MAX_PATH]{};
        const UINT length = ::GetSystemDirectoryW(system, MAX_PATH);
        source = std::filesystem::path(std::wstring(system, length)) / L"waitfor.exe";
        std::error_code ec;
        std::filesystem::copy_file(source, image, std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            return;
        }
        std::wstring commandLine = L"\"" + image.wstring() + L"\" /t 120 ShadowStrikeRegistryProtectionTest" +
                                   std::to_wstring(::GetCurrentProcessId());
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        if (::CreateProcessW(image.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                             nullptr, nullptr, &si, &pi)) {
            ::CloseHandle(pi.hThread);
            pi.hThread = nullptr;
        }
    }
    ~RunningCopy() {
        if (pi.hProcess) {
            ::TerminateProcess(pi.hProcess, 0);
            ::WaitForSingleObject(pi.hProcess, 5000);
            ::CloseHandle(pi.hProcess);
        }
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
    bool Running() const { return pi.hProcess != nullptr; }
    uint32_t Pid() const { return pi.dwProcessId; }

    std::filesystem::path dir;
    std::filesystem::path source;
    std::filesystem::path image;
    PROCESS_INFORMATION pi{};
};

class RegistryProtectionLiveTest : public ::testing::Test {
protected:
    static RegistryProtection& Module() { return RegistryProtection::Instance(); }

    static void SetUpTestSuite() {
        s_validatorReady = ShadowStrike::Security::DigitalSignatureValidator::Instance().Initialize() ||
                           ShadowStrike::Security::DigitalSignatureValidator::Instance().IsInitialized();
        RegistryProtectionConfiguration config =
            RegistryProtectionConfiguration::FromMode(RegistryProtectionMode::Protect);
        config.enableKernelCallbacks = false;
        config.enableUserModePolling = false;
        config.enableIntegrityMonitoring = false;
        config.enableAutoRollback = false;
        config.enableSnapshots = true;
        s_initialized = Module().Initialize(config);
    }

    static void TearDownTestSuite() {
        if (Module().IsInitialized()) {
            Module().Shutdown(Module().GenerateAuthorizationToken());
        }
    }

    void SetUp() override {
        ASSERT_TRUE(s_initialized) << "RegistryProtection did not initialise";
        ASSERT_TRUE(s_validatorReady) << "DigitalSignatureValidator did not initialise";
    }

    static RegistryOperationDecisionResult SetValueFrom(uint32_t pid, const std::wstring& keyPath) {
        RegistryOperationRequest request;
        request.operation = RegistryOperation::SetValue;
        request.keyPath = keyPath;
        request.valueName = L"Start";
        request.processId = pid;
        return Module().FilterOperation(request);
    }

    static inline bool s_initialized = false;
    static inline bool s_validatorReady = false;
};

// Task 346: the IFEO guard named ShadowStrikeUI.exe and ShadowStrikeUpdater.exe, which the
// installer has never shipped, and left the UI, tray and resume helper unguarded.
TEST_F(RegistryProtectionLiveTest, EveryInstalledExecutableHasItsImageExecutionOptionsKeyGuarded) {
    for (const auto name : ProductExecutables::kNames) {
        EXPECT_TRUE(Module().IsKeyProtected(RegistryProtection::ImageExecutionOptionsKeyFor(name)))
            << std::string(name.begin(), name.end());
    }
    EXPECT_FALSE(Module().IsKeyProtected(RegistryProtection::ImageExecutionOptionsKeyFor(L"ShadowStrikeUI.exe")));
    EXPECT_FALSE(
        Module().IsKeyProtected(RegistryProtection::ImageExecutionOptionsKeyFor(L"ShadowStrikeUpdater.exe")));
}

TEST_F(RegistryProtectionLiveTest, ARenamedSignedBinaryOutsideTheInstallDirectoryIsNotWhitelisted) {
    ScratchKey key;
    key.SetString(L"Start", L"2");
    ASSERT_TRUE(Module().ProtectKey(key.Path(), KeyProtectionType::Full, true));
    RunningCopy impostor(std::filesystem::temp_directory_path() /
                             (L"ss_regprot_" + std::to_wstring(::GetCurrentProcessId())),
                         L"ShadowStrikePhantomService.exe");
    ASSERT_TRUE(impostor.Running());
    // The premise: the copy carries a valid signature, which is all the whitelist used to ask.
    ASSERT_TRUE(ShadowStrike::Security::DigitalSignatureValidator::Instance().VerifyFile(impostor.image.wstring())
                    .isValid)
        << "a copy of waitfor.exe no longer verifies, so this case no longer tests the bypass";

    EXPECT_FALSE(Module().IsWhitelisted(impostor.Pid()));
    const auto decision = SetValueFrom(impostor.Pid(), key.Path());
    EXPECT_EQ(decision.decision, RegistryOperationDecision::Block) << decision.reason;
}

TEST_F(RegistryProtectionLiveTest, TheSameImageInsideTheInstallDirectoryIsWhitelisted) {
    ScratchKey key;
    key.SetString(L"Start", L"2");
    ASSERT_TRUE(Module().ProtectKey(key.Path(), KeyProtectionType::Full, true));
    ASSERT_FALSE(ProductExecutables::InstallDirectory().empty());
    RunningCopy component(std::filesystem::path(ProductExecutables::InstallDirectory()) /
                              (L"ss_regprot_" + std::to_wstring(::GetCurrentProcessId())),
                          L"ShadowStrikePhantomService.exe");
    ASSERT_TRUE(component.Running());

    EXPECT_TRUE(Module().IsWhitelisted(component.Pid()));
    const auto decision = SetValueFrom(component.Pid(), key.Path());
    EXPECT_EQ(decision.decision, RegistryOperationDecision::AllowLogged) << decision.reason;
}

TEST(ProductExecutablesTests, DirectoryContainmentRequiresTheSeparator) {
    EXPECT_TRUE(ProductExecutables::IsInsideDirectory(L"C:\\Program Files\\ShadowStrike\\a.exe",
                                                      L"C:\\Program Files\\ShadowStrike\\"));
    EXPECT_TRUE(ProductExecutables::IsInsideDirectory(L"c:\\program files\\shadowstrike\\sub\\a.exe",
                                                      L"C:\\Program Files\\ShadowStrike\\"));
    EXPECT_FALSE(ProductExecutables::IsInsideDirectory(L"C:\\Program Files\\ShadowStrike2\\a.exe",
                                                       L"C:\\Program Files\\ShadowStrike\\"));
    EXPECT_FALSE(ProductExecutables::IsInsideDirectory(L"C:\\Program Files\\ShadowStrike2\\a.exe",
                                                       L"C:\\Program Files\\ShadowStrike"));
    EXPECT_FALSE(ProductExecutables::IsInsideDirectory(L"C:\\a.exe", L""));
    EXPECT_TRUE(ProductExecutables::IsProductName(L"shadowstrikephantomui.EXE"));
    EXPECT_FALSE(ProductExecutables::IsProductName(L"ShadowStrikeUI.exe"));
}

}  // namespace
