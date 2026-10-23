/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ServiceStartWatchdog.cpp
 * @brief See ServiceStartWatchdog.hpp (task 334).
 */

#include "ServiceStartWatchdog.hpp"

#include <objbase.h>
#include <oleauto.h>
#include <taskschd.h>
#include <wrl/client.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

using Microsoft::WRL::ComPtr;

namespace ShadowStrike::Installer {

namespace {

[[nodiscard]] bool IsAcceptableExecutablePath(const std::wstring& path) noexcept {
    // Absolute drive path ("C:\...") ending in .exe. Quotes, control characters and
    // environment-variable or wildcard syntax would let the stored command mean
    // something other than this one file, so they are refused outright.
    if (path.size() < 8 || path.size() > MAX_PATH) return false;
    if (!(((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
          path[1] == L':' && path[2] == L'\\')) {
        return false;
    }
    for (const wchar_t c : path) {
        if (c < 0x20 || c == L'"' || c == L'%' || c == L'*' || c == L'?' ||
            c == L'<' || c == L'>' || c == L'|') {
            return false;
        }
    }
    const std::wstring tail = path.substr(path.size() - 4);
    return _wcsicmp(tail.c_str(), L".exe") == 0;
}

void AppendXmlEscaped(std::wstring& out, const std::wstring& text) {
    for (const wchar_t c : text) {
        switch (c) {
            case L'&':  out += L"&amp;";  break;
            case L'<':  out += L"&lt;";   break;
            case L'>':  out += L"&gt;";   break;
            case L'\'': out += L"&apos;"; break;
            case L'"':  out += L"&quot;"; break;
            default:    out += c;         break;
        }
    }
}

/// BSTR owned for the lifetime of the scope.
class Bstr final {
public:
    explicit Bstr(const wchar_t* s) noexcept : m_b(::SysAllocString(s)) {}
    ~Bstr() { if (m_b) ::SysFreeString(m_b); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
    [[nodiscard]] BSTR get() const noexcept { return m_b; }
    [[nodiscard]] explicit operator bool() const noexcept { return m_b != nullptr; }
private:
    BSTR m_b;
};

/// COM initialised for this thread, and the task folder, or an error.
class TaskFolderSession final {
public:
    DWORD Open(bool createIfMissing) noexcept {
        const HRESULT co = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        m_uninit = SUCCEEDED(co);
        if (FAILED(co) && co != RPC_E_CHANGED_MODE) return static_cast<DWORD>(co);

        const HRESULT sec = ::CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, 0, nullptr);
        if (FAILED(sec) && sec != RPC_E_TOO_LATE) return static_cast<DWORD>(sec);

        HRESULT hr = ::CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                        IID_PPV_ARGS(&m_service));
        if (FAILED(hr)) return static_cast<DWORD>(hr);

        VARIANT empty;
        ::VariantInit(&empty);
        hr = m_service->Connect(empty, empty, empty, empty);
        if (FAILED(hr)) return static_cast<DWORD>(hr);

        Bstr root(L"\\");
        Bstr folder(kServiceWatchdogTaskFolder);
        if (!root || !folder) return ERROR_OUTOFMEMORY;

        ComPtr<ITaskFolder> rootFolder;
        hr = m_service->GetFolder(root.get(), &rootFolder);
        if (FAILED(hr)) return static_cast<DWORD>(hr);

        hr = rootFolder->GetFolder(folder.get(), &m_folder);
        if (FAILED(hr) && createIfMissing) {
            // Empty SDDL: inherit the task root's ACL (administrators and SYSTEM).
            VARIANT sddl;
            ::VariantInit(&sddl);
            hr = rootFolder->CreateFolder(folder.get(), sddl, &m_folder);
        }
        return FAILED(hr) ? static_cast<DWORD>(hr) : ERROR_SUCCESS;
    }

    ~TaskFolderSession() {
        m_folder.Reset();
        m_service.Reset();
        if (m_uninit) ::CoUninitialize();
    }

    [[nodiscard]] ITaskFolder* folder() const noexcept { return m_folder.Get(); }

private:
    ComPtr<ITaskService> m_service;
    ComPtr<ITaskFolder>  m_folder;
    bool m_uninit = false;
};

} // namespace

std::wstring BuildServiceWatchdogTaskXml(const std::wstring& driverResumePath) {
    if (!IsAcceptableExecutablePath(driverResumePath)) {
        return {};
    }
    std::wstring xml;
    xml.reserve(1536);
    xml += L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
           L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
           L"  <RegistrationInfo>\r\n"
           L"    <Author>ShadowStrike</Author>\r\n"
           L"    <Description>Starts ShadowStrike Phantom Service once after boot if Windows "
           L"gave up on its automatic start.</Description>\r\n"
           L"  </RegistrationInfo>\r\n"
           L"  <Triggers>\r\n"
           L"    <BootTrigger>\r\n"
           L"      <Enabled>true</Enabled>\r\n"
           L"      <Delay>";
    xml += kServiceWatchdogBootDelay;
    xml += L"</Delay>\r\n"
           L"    </BootTrigger>\r\n"
           L"  </Triggers>\r\n"
           L"  <Principals>\r\n"
           L"    <Principal id=\"System\">\r\n"
           L"      <UserId>S-1-5-18</UserId>\r\n"
           L"      <RunLevel>HighestAvailable</RunLevel>\r\n"
           L"    </Principal>\r\n"
           L"  </Principals>\r\n"
           L"  <Settings>\r\n"
           L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
           L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
           L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
           L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
           L"    <StartWhenAvailable>false</StartWhenAvailable>\r\n"
           L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
           L"    <Enabled>true</Enabled>\r\n"
           L"    <Hidden>true</Hidden>\r\n"
           L"    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>\r\n"
           L"    <Priority>4</Priority>\r\n"
           L"  </Settings>\r\n"
           L"  <Actions Context=\"System\">\r\n"
           L"    <Exec>\r\n"
           L"      <Command>";
    AppendXmlEscaped(xml, driverResumePath);
    xml += L"</Command>\r\n"
           L"      <Arguments>--start-service</Arguments>\r\n"
           L"    </Exec>\r\n"
           L"  </Actions>\r\n"
           L"</Task>\r\n";
    return xml;
}

DWORD RegisterServiceWatchdogTask(const std::wstring& driverResumePath) {
    const std::wstring xml = BuildServiceWatchdogTaskXml(driverResumePath);
    if (xml.empty()) {
        LOG_ERROR(L"Service start watchdog: refused executable path '%ls'.",
                  driverResumePath.c_str());
        return ERROR_INVALID_PARAMETER;
    }

    TaskFolderSession session;
    DWORD err = session.Open(/*createIfMissing=*/true);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"Service start watchdog: cannot open task folder %ls (0x%08X).",
                  kServiceWatchdogTaskFolder, err);
        return err;
    }

    Bstr name(kServiceWatchdogTaskName);
    Bstr xmlB(xml.c_str());
    if (!name || !xmlB) return ERROR_OUTOFMEMORY;

    VARIANT user;
    ::VariantInit(&user);
    user.vt = VT_BSTR;
    user.bstrVal = ::SysAllocString(L"SYSTEM");
    VARIANT empty;
    ::VariantInit(&empty);

    ComPtr<IRegisteredTask> registered;
    const HRESULT hr = session.folder()->RegisterTask(
        name.get(), xmlB.get(), TASK_CREATE_OR_UPDATE, user, empty,
        TASK_LOGON_SERVICE_ACCOUNT, empty, &registered);
    ::VariantClear(&user);
    if (FAILED(hr)) {
        LOG_ERROR(L"Service start watchdog: RegisterTask failed (0x%08X).",
                  static_cast<unsigned>(hr));
        return static_cast<DWORD>(hr);
    }
    LOG_INFO(L"Service start watchdog task registered: %ls\\%ls (boot + %ls).",
             kServiceWatchdogTaskFolder, kServiceWatchdogTaskName, kServiceWatchdogBootDelay);
    return ERROR_SUCCESS;
}

DWORD DeleteServiceWatchdogTask() {
    TaskFolderSession session;
    const DWORD err = session.Open(/*createIfMissing=*/false);
    if (err != ERROR_SUCCESS) {
        // No \ShadowStrike folder means there is no task either.
        return (err == static_cast<DWORD>(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)))
            ? ERROR_SUCCESS : err;
    }
    Bstr name(kServiceWatchdogTaskName);
    if (!name) return ERROR_OUTOFMEMORY;
    const HRESULT hr = session.folder()->DeleteTask(name.get(), 0);
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        LOG_WARN(L"Service start watchdog: DeleteTask failed (0x%08X).",
                 static_cast<unsigned>(hr));
        return static_cast<DWORD>(hr);
    }
    LOG_INFO(L"Service start watchdog task removed.");
    return ERROR_SUCCESS;
}

} // namespace ShadowStrike::Installer
