/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APISequenceAnalyzer.cpp — Full implementation of API sequence analysis
 *
 * Implements N-gram pattern matching, Markov chain transition analysis,
 * temporal burst detection, cross-thread correlation, and sliding-window
 * analysis to detect over 200 known malware API call sequences.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "APISequenceAnalyzer.hpp"
#include "../WinAPI/APIDatabase.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstring>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

namespace {

// ============================================================================
// Canonical API Identifiers
// ============================================================================
// Each unique Windows API function gets a compact ID. A/W variants map to the
// same canonical ID so patterns need not duplicate for both suffixes.

enum APIIdValue : APIId {
    API_Unknown = 0,

    // --- Ntdll: Memory ---
    API_NtAllocateVirtualMemory,
    API_NtProtectVirtualMemory,
    API_NtFreeVirtualMemory,
    API_NtReadVirtualMemory,
    API_NtWriteVirtualMemory,
    API_NtQueryVirtualMemory,
    API_NtCreateSection,
    API_NtMapViewOfSection,
    API_NtUnmapViewOfSection,

    // --- Ntdll: File ---
    API_NtCreateFile,
    API_NtReadFile,
    API_NtWriteFile,
    API_NtClose,
    API_NtSetInformationFile,
    API_NtQueryInformationFile,
    API_NtQueryDirectoryFile,
    API_NtDeviceIoControlFile,

    // --- Ntdll: Process ---
    API_NtOpenProcess,
    API_NtTerminateProcess,
    API_NtQueryInformationProcess,

    // --- Ntdll: Thread ---
    API_NtCreateThreadEx,
    API_NtResumeThread,
    API_NtSuspendThread,
    API_NtTerminateThread,
    API_NtSetInformationThread,
    API_NtQueryInformationThread,

    // --- Ntdll: Registry ---
    API_NtOpenKey,
    API_NtCreateKey,
    API_NtSetValueKey,
    API_NtQueryValueKey,
    API_NtDeleteKey,
    API_NtDeleteValueKey,
    API_NtEnumerateKey,
    API_NtEnumerateValueKey,

    // --- Ntdll: System ---
    API_NtQuerySystemInformation,
    API_NtQueryPerformanceCounter,
    API_NtDelayExecution,

    // --- Ntdll: Sync ---
    API_NtWaitForSingleObject,
    API_NtWaitForMultipleObjects,
    API_NtCreateEvent,
    API_NtCreateMutant,

    // --- Ntdll: Security ---
    API_NtOpenProcessToken,
    API_NtQueryInformationToken,
    API_NtAdjustPrivilegesToken,

    // --- Ntdll: Object ---
    API_NtDuplicateObject,
    API_NtQueryObject,

    // --- Ntdll: RTL ---
    API_RtlAllocateHeap,
    API_RtlFreeHeap,
    API_RtlReAllocateHeap,
    API_RtlDecompressBuffer,
    API_RtlGetVersion,
    API_RtlCreateUserThread,

    // --- Ntdll: Loader ---
    API_LdrLoadDll,
    API_LdrGetProcedureAddress,

    // --- Kernel32: File ---
    API_CreateFile,
    API_ReadFile,
    API_WriteFile,
    API_CloseHandle,
    API_DeleteFile,
    API_MoveFile,
    API_CopyFile,
    API_GetFileSize,
    API_SetFilePointer,
    API_FindFirstFile,
    API_FindNextFile,
    API_FindClose,
    API_GetTempPath,
    API_GetFileAttributes,
    API_SetFileAttributes,

    // --- Kernel32: Process ---
    API_CreateProcess,
    API_OpenProcess,
    API_TerminateProcess,
    API_ExitProcess,
    API_GetCurrentProcessId,
    API_IsWow64Process,
    API_GetProcessHeap,

    // --- Kernel32: Memory ---
    API_VirtualAlloc,
    API_VirtualAllocEx,
    API_VirtualFree,
    API_VirtualProtect,
    API_VirtualProtectEx,
    API_VirtualQuery,
    API_ReadProcessMemory,
    API_WriteProcessMemory,
    API_HeapCreate,
    API_HeapAlloc,
    API_HeapFree,
    API_GlobalAlloc,
    API_LocalAlloc,

    // --- Kernel32: Module ---
    API_LoadLibrary,
    API_FreeLibrary,
    API_GetProcAddress,
    API_GetModuleHandle,
    API_GetModuleFileName,

    // --- Kernel32: Thread ---
    API_CreateThread,
    API_CreateRemoteThread,
    API_CreateRemoteThreadEx,
    API_ResumeThread,
    API_SuspendThread,
    API_SetThreadContext,
    API_GetThreadContext,
    API_OpenThread,
    API_QueueUserAPC,

    // --- Kernel32: Sync ---
    API_WaitForSingleObject,
    API_WaitForMultipleObjects,
    API_CreateMutex,
    API_CreateEvent,
    API_SetEvent,
    API_Sleep,

    // --- Kernel32: Time ---
    API_GetTickCount,
    API_GetTickCount64,
    API_QueryPerformanceCounter,
    API_QueryPerformanceFrequency,
    API_GetSystemTime,
    API_GetLocalTime,
    API_GetSystemTimeAsFileTime,

    // --- Kernel32: Environment ---
    API_GetComputerName,
    API_GetUserName,
    API_GetSystemDirectory,
    API_GetWindowsDirectory,
    API_GetEnvironmentVariable,
    API_GetVersionEx,
    API_GetVersion,
    API_GetSystemInfo,
    API_GetNativeSystemInfo,
    API_IsProcessorFeaturePresent,
    API_GetDiskFreeSpaceEx,
    API_GetLogicalDrives,
    API_GetDriveType,

    // --- Kernel32: Debug ---
    API_IsDebuggerPresent,
    API_CheckRemoteDebuggerPresent,
    API_OutputDebugString,

    // --- Kernel32: Error/String ---
    API_GetLastError,
    API_SetLastError,
    API_MultiByteToWideChar,
    API_WideCharToMultiByte,

    // --- Kernel32: Toolhelp ---
    API_CreateToolhelp32Snapshot,
    API_Process32First,
    API_Process32Next,
    API_Module32First,
    API_Module32Next,
    API_Thread32First,
    API_Thread32Next,

    // --- Kernel32: Pipe ---
    API_CreateNamedPipe,
    API_ConnectNamedPipe,

    // --- Kernel32: Misc ---
    API_CreateProcessAsUser,

    // --- Advapi32: Registry ---
    API_RegOpenKeyEx,
    API_RegCreateKeyEx,
    API_RegSetValueEx,
    API_RegQueryValueEx,
    API_RegDeleteKey,
    API_RegDeleteValue,
    API_RegCloseKey,
    API_RegEnumKeyEx,
    API_RegEnumValue,

    // --- Advapi32: Security ---
    API_OpenProcessToken,
    API_AdjustTokenPrivileges,
    API_LookupPrivilegeValue,
    API_GetTokenInformation,
    API_ImpersonateLoggedOnUser,
    API_DuplicateTokenEx,

    // --- Advapi32: Service ---
    API_OpenSCManager,
    API_CreateService,
    API_StartService,
    API_OpenService,
    API_DeleteService,
    API_CloseServiceHandle,

    // --- Advapi32: Crypto ---
    API_CryptAcquireContext,
    API_CryptGenRandom,
    API_CryptEncrypt,
    API_CryptDecrypt,
    API_CryptCreateHash,
    API_CryptHashData,
    API_CryptReleaseContext,
    API_CryptGenKey,
    API_CryptExportKey,
    API_CryptImportKey,
    API_CryptDestroyKey,

    // --- Advapi32: Credential ---
    API_LsaOpenPolicy,
    API_LsaRetrievePrivateData,
    API_CredEnumerate,
    API_CredRead,

    // --- Ws2_32 ---
    API_WSAStartup,
    API_WSACleanup,
    API_socket,
    API_connect,
    API_send,
    API_recv,
    API_bind,
    API_listen,
    API_accept,
    API_closesocket,
    API_getaddrinfo,
    API_gethostbyname,
    API_select,
    API_WSASocket,

    // --- Wininet ---
    API_InternetOpen,
    API_InternetConnect,
    API_HttpOpenRequest,
    API_HttpSendRequest,
    API_InternetReadFile,
    API_InternetCloseHandle,
    API_InternetOpenUrl,
    API_InternetWriteFile,

    // --- Winhttp ---
    API_WinHttpOpen,
    API_WinHttpConnect,
    API_WinHttpOpenRequest,
    API_WinHttpSendRequest,
    API_WinHttpReceiveResponse,
    API_WinHttpReadData,
    API_WinHttpCloseHandle,

    // --- Urlmon ---
    API_URLDownloadToFile,

    // --- User32 ---
    API_MessageBox,
    API_FindWindow,
    API_GetForegroundWindow,
    API_GetDesktopWindow,
    API_EnumWindows,
    API_GetWindowText,
    API_SetWindowsHookEx,
    API_GetAsyncKeyState,
    API_GetMessage,
    API_PeekMessage,
    API_GetClipboardData,

    // --- Shell32 ---
    API_ShellExecute,
    API_ShellExecuteEx,
    API_SHGetFolderPath,

    // --- Ole32 ---
    API_CoInitializeEx,
    API_CoUninitialize,
    API_CoCreateInstance,

    // --- Network Discovery ---
    API_WNetAddConnection2,
    API_NetShareEnum,
    API_NetServerEnum,
    API_NetUserEnum,
    API_NetLocalGroupGetMembers,
    API_GetAdaptersInfo,
    API_GetIpForwardTable,
    API_LookupAccountName,
    API_DnsQuery,

    API_ID_COUNT
};

// ============================================================================
// Function Name → APIId Mapping
// ============================================================================
// Maps exact Win32/NT function names (including A/W variants) to canonical IDs.

struct APINameEntry {
    const char* funcName;
    APIId       id;
};

static const APINameEntry kAPINames[] = {
    // Ntdll
    { "NtAllocateVirtualMemory",    API_NtAllocateVirtualMemory },
    { "NtProtectVirtualMemory",     API_NtProtectVirtualMemory },
    { "NtFreeVirtualMemory",        API_NtFreeVirtualMemory },
    { "NtReadVirtualMemory",        API_NtReadVirtualMemory },
    { "NtWriteVirtualMemory",       API_NtWriteVirtualMemory },
    { "NtQueryVirtualMemory",       API_NtQueryVirtualMemory },
    { "NtCreateSection",            API_NtCreateSection },
    { "NtMapViewOfSection",         API_NtMapViewOfSection },
    { "NtUnmapViewOfSection",       API_NtUnmapViewOfSection },
    { "NtCreateFile",               API_NtCreateFile },
    { "NtReadFile",                 API_NtReadFile },
    { "NtWriteFile",                API_NtWriteFile },
    { "NtClose",                    API_NtClose },
    { "NtSetInformationFile",       API_NtSetInformationFile },
    { "NtQueryInformationFile",     API_NtQueryInformationFile },
    { "NtQueryDirectoryFile",       API_NtQueryDirectoryFile },
    { "NtDeviceIoControlFile",      API_NtDeviceIoControlFile },
    { "NtOpenProcess",              API_NtOpenProcess },
    { "NtTerminateProcess",         API_NtTerminateProcess },
    { "NtQueryInformationProcess",  API_NtQueryInformationProcess },
    { "NtCreateThreadEx",           API_NtCreateThreadEx },
    { "NtResumeThread",             API_NtResumeThread },
    { "NtSuspendThread",            API_NtSuspendThread },
    { "NtTerminateThread",          API_NtTerminateThread },
    { "NtSetInformationThread",     API_NtSetInformationThread },
    { "NtQueryInformationThread",   API_NtQueryInformationThread },
    { "NtOpenKey",                  API_NtOpenKey },
    { "NtCreateKey",                API_NtCreateKey },
    { "NtSetValueKey",              API_NtSetValueKey },
    { "NtQueryValueKey",            API_NtQueryValueKey },
    { "NtDeleteKey",                API_NtDeleteKey },
    { "NtDeleteValueKey",           API_NtDeleteValueKey },
    { "NtEnumerateKey",             API_NtEnumerateKey },
    { "NtEnumerateValueKey",        API_NtEnumerateValueKey },
    { "NtQuerySystemInformation",   API_NtQuerySystemInformation },
    { "NtQueryPerformanceCounter",  API_NtQueryPerformanceCounter },
    { "NtDelayExecution",           API_NtDelayExecution },
    { "NtWaitForSingleObject",      API_NtWaitForSingleObject },
    { "NtWaitForMultipleObjects",   API_NtWaitForMultipleObjects },
    { "NtCreateEvent",              API_NtCreateEvent },
    { "NtCreateMutant",             API_NtCreateMutant },
    { "NtOpenProcessToken",         API_NtOpenProcessToken },
    { "NtQueryInformationToken",    API_NtQueryInformationToken },
    { "NtAdjustPrivilegesToken",    API_NtAdjustPrivilegesToken },
    { "NtDuplicateObject",          API_NtDuplicateObject },
    { "NtQueryObject",              API_NtQueryObject },
    { "RtlAllocateHeap",            API_RtlAllocateHeap },
    { "RtlFreeHeap",                API_RtlFreeHeap },
    { "RtlReAllocateHeap",          API_RtlReAllocateHeap },
    { "RtlDecompressBuffer",        API_RtlDecompressBuffer },
    { "RtlGetVersion",              API_RtlGetVersion },
    { "RtlGetNtVersionNumbers",     API_RtlGetVersion },
    { "RtlCreateUserThread",        API_RtlCreateUserThread },
    { "LdrLoadDll",                 API_LdrLoadDll },
    { "LdrGetProcedureAddress",     API_LdrGetProcedureAddress },
    { "LdrGetDllHandle",            API_GetModuleHandle },
    { "LdrUnloadDll",               API_FreeLibrary },

    // Kernel32: File (A/W variants → canonical)
    { "CreateFileA",                API_CreateFile },
    { "CreateFileW",                API_CreateFile },
    { "ReadFile",                   API_ReadFile },
    { "WriteFile",                  API_WriteFile },
    { "CloseHandle",                API_CloseHandle },
    { "DeleteFileA",                API_DeleteFile },
    { "DeleteFileW",                API_DeleteFile },
    { "MoveFileA",                  API_MoveFile },
    { "MoveFileW",                  API_MoveFile },
    { "CopyFileA",                  API_CopyFile },
    { "CopyFileW",                  API_CopyFile },
    { "GetFileSize",                API_GetFileSize },
    { "GetFileSizeEx",              API_GetFileSize },
    { "SetFilePointer",             API_SetFilePointer },
    { "SetFilePointerEx",           API_SetFilePointer },
    { "GetFileAttributesA",         API_GetFileAttributes },
    { "GetFileAttributesW",         API_GetFileAttributes },
    { "SetFileAttributesA",         API_SetFileAttributes },
    { "SetFileAttributesW",         API_SetFileAttributes },
    { "FindFirstFileA",             API_FindFirstFile },
    { "FindFirstFileW",             API_FindFirstFile },
    { "FindNextFileA",              API_FindNextFile },
    { "FindNextFileW",              API_FindNextFile },
    { "FindClose",                  API_FindClose },
    { "GetTempPathA",               API_GetTempPath },
    { "GetTempPathW",               API_GetTempPath },

    // Kernel32: Process
    { "CreateProcessA",             API_CreateProcess },
    { "CreateProcessW",             API_CreateProcess },
    { "OpenProcess",                API_OpenProcess },
    { "TerminateProcess",           API_TerminateProcess },
    { "ExitProcess",                API_ExitProcess },
    { "GetCurrentProcessId",        API_GetCurrentProcessId },
    { "GetCurrentProcess",          API_GetCurrentProcessId },
    { "IsWow64Process",             API_IsWow64Process },
    { "GetProcessHeap",             API_GetProcessHeap },
    { "CreateProcessAsUserA",       API_CreateProcessAsUser },
    { "CreateProcessAsUserW",       API_CreateProcessAsUser },

    // Kernel32: Memory
    { "VirtualAlloc",               API_VirtualAlloc },
    { "VirtualAllocEx",             API_VirtualAllocEx },
    { "VirtualFree",                API_VirtualFree },
    { "VirtualFreeEx",              API_VirtualFree },
    { "VirtualProtect",             API_VirtualProtect },
    { "VirtualProtectEx",           API_VirtualProtectEx },
    { "VirtualQuery",               API_VirtualQuery },
    { "VirtualQueryEx",             API_VirtualQuery },
    { "ReadProcessMemory",          API_ReadProcessMemory },
    { "WriteProcessMemory",         API_WriteProcessMemory },
    { "HeapCreate",                 API_HeapCreate },
    { "HeapDestroy",                API_HeapCreate },
    { "HeapAlloc",                  API_HeapAlloc },
    { "HeapFree",                   API_HeapFree },
    { "HeapReAlloc",                API_HeapAlloc },
    { "HeapSize",                   API_HeapAlloc },
    { "GlobalAlloc",                API_GlobalAlloc },
    { "GlobalFree",                 API_GlobalAlloc },
    { "LocalAlloc",                 API_LocalAlloc },
    { "LocalFree",                  API_LocalAlloc },

    // Kernel32: Module
    { "LoadLibraryA",               API_LoadLibrary },
    { "LoadLibraryW",               API_LoadLibrary },
    { "LoadLibraryExA",             API_LoadLibrary },
    { "LoadLibraryExW",             API_LoadLibrary },
    { "FreeLibrary",                API_FreeLibrary },
    { "GetProcAddress",             API_GetProcAddress },
    { "GetModuleHandleA",           API_GetModuleHandle },
    { "GetModuleHandleW",           API_GetModuleHandle },
    { "GetModuleFileNameA",         API_GetModuleFileName },
    { "GetModuleFileNameW",         API_GetModuleFileName },

    // Kernel32: Thread
    { "CreateThread",               API_CreateThread },
    { "CreateRemoteThread",         API_CreateRemoteThread },
    { "CreateRemoteThreadEx",       API_CreateRemoteThreadEx },
    { "ResumeThread",               API_ResumeThread },
    { "SuspendThread",              API_SuspendThread },
    { "TerminateThread",            API_CreateThread },
    { "ExitThread",                 API_CreateThread },
    { "SetThreadContext",           API_SetThreadContext },
    { "GetThreadContext",           API_GetThreadContext },
    { "OpenThread",                 API_OpenThread },
    { "QueueUserAPC",               API_QueueUserAPC },
    { "GetCurrentThreadId",         API_CreateThread },
    { "GetCurrentThread",           API_CreateThread },

    // Kernel32: Sync
    { "WaitForSingleObject",        API_WaitForSingleObject },
    { "WaitForMultipleObjects",     API_WaitForMultipleObjects },
    { "CreateMutexA",               API_CreateMutex },
    { "CreateMutexW",               API_CreateMutex },
    { "CreateEventA",               API_CreateEvent },
    { "CreateEventW",               API_CreateEvent },
    { "SetEvent",                   API_SetEvent },
    { "ResetEvent",                 API_SetEvent },
    { "Sleep",                      API_Sleep },
    { "SleepEx",                    API_Sleep },

    // Kernel32: Time
    { "GetTickCount",               API_GetTickCount },
    { "GetTickCount64",             API_GetTickCount64 },
    { "QueryPerformanceCounter",    API_QueryPerformanceCounter },
    { "QueryPerformanceFrequency",  API_QueryPerformanceFrequency },
    { "GetSystemTime",              API_GetSystemTime },
    { "GetLocalTime",               API_GetLocalTime },
    { "GetSystemTimeAsFileTime",    API_GetSystemTimeAsFileTime },

    // Kernel32: Environment
    { "GetComputerNameA",           API_GetComputerName },
    { "GetComputerNameW",           API_GetComputerName },
    { "GetUserNameA",               API_GetUserName },
    { "GetUserNameW",               API_GetUserName },
    { "GetSystemDirectoryA",        API_GetSystemDirectory },
    { "GetSystemDirectoryW",        API_GetSystemDirectory },
    { "GetWindowsDirectoryA",       API_GetWindowsDirectory },
    { "GetWindowsDirectoryW",       API_GetWindowsDirectory },
    { "GetEnvironmentVariableA",    API_GetEnvironmentVariable },
    { "GetEnvironmentVariableW",    API_GetEnvironmentVariable },
    { "GetVersionExA",              API_GetVersionEx },
    { "GetVersionExW",              API_GetVersionEx },
    { "GetVersion",                 API_GetVersion },
    { "GetSystemInfo",              API_GetSystemInfo },
    { "GetNativeSystemInfo",        API_GetNativeSystemInfo },
    { "IsProcessorFeaturePresent",  API_IsProcessorFeaturePresent },
    { "GetDiskFreeSpaceExA",        API_GetDiskFreeSpaceEx },
    { "GetDiskFreeSpaceExW",        API_GetDiskFreeSpaceEx },
    { "GetLogicalDrives",           API_GetLogicalDrives },
    { "GetDriveTypeA",              API_GetDriveType },
    { "GetDriveTypeW",              API_GetDriveType },

    // Kernel32: Debug
    { "IsDebuggerPresent",          API_IsDebuggerPresent },
    { "CheckRemoteDebuggerPresent", API_CheckRemoteDebuggerPresent },
    { "OutputDebugStringA",         API_OutputDebugString },
    { "OutputDebugStringW",         API_OutputDebugString },

    // Kernel32: Error/String
    { "SetLastError",               API_SetLastError },
    { "GetLastError",               API_GetLastError },
    { "MultiByteToWideChar",        API_MultiByteToWideChar },
    { "WideCharToMultiByte",        API_WideCharToMultiByte },
    { "lstrlenA",                   API_Unknown },
    { "lstrlenW",                   API_Unknown },
    { "lstrcmpA",                   API_Unknown },
    { "lstrcmpW",                   API_Unknown },
    { "lstrcpyA",                   API_Unknown },
    { "lstrcpyW",                   API_Unknown },

    // Kernel32: Toolhelp
    { "CreateToolhelp32Snapshot",   API_CreateToolhelp32Snapshot },
    { "Process32First",             API_Process32First },
    { "Process32FirstW",            API_Process32First },
    { "Process32Next",              API_Process32Next },
    { "Process32NextW",             API_Process32Next },
    { "Module32First",              API_Module32First },
    { "Module32FirstW",             API_Module32First },
    { "Module32Next",               API_Module32Next },
    { "Module32NextW",              API_Module32Next },
    { "Thread32First",              API_Thread32First },
    { "Thread32Next",               API_Thread32Next },

    // Kernel32: Pipe
    { "CreateNamedPipeA",           API_CreateNamedPipe },
    { "CreateNamedPipeW",           API_CreateNamedPipe },
    { "ConnectNamedPipe",           API_ConnectNamedPipe },

    // Advapi32: Registry
    { "RegOpenKeyExA",              API_RegOpenKeyEx },
    { "RegOpenKeyExW",              API_RegOpenKeyEx },
    { "RegCreateKeyExA",            API_RegCreateKeyEx },
    { "RegCreateKeyExW",            API_RegCreateKeyEx },
    { "RegSetValueExA",             API_RegSetValueEx },
    { "RegSetValueExW",             API_RegSetValueEx },
    { "RegQueryValueExA",           API_RegQueryValueEx },
    { "RegQueryValueExW",           API_RegQueryValueEx },
    { "RegDeleteKeyA",              API_RegDeleteKey },
    { "RegDeleteKeyW",              API_RegDeleteKey },
    { "RegDeleteValueA",            API_RegDeleteValue },
    { "RegDeleteValueW",            API_RegDeleteValue },
    { "RegCloseKey",                API_RegCloseKey },
    { "RegEnumKeyExA",              API_RegEnumKeyEx },
    { "RegEnumKeyExW",              API_RegEnumKeyEx },
    { "RegEnumValueA",              API_RegEnumValue },
    { "RegEnumValueW",              API_RegEnumValue },

    // Advapi32: Security
    { "OpenProcessToken",           API_OpenProcessToken },
    { "AdjustTokenPrivileges",      API_AdjustTokenPrivileges },
    { "LookupPrivilegeValueA",      API_LookupPrivilegeValue },
    { "LookupPrivilegeValueW",      API_LookupPrivilegeValue },
    { "GetTokenInformation",        API_GetTokenInformation },
    { "ImpersonateLoggedOnUser",    API_ImpersonateLoggedOnUser },
    { "RevertToSelf",               API_ImpersonateLoggedOnUser },
    { "DuplicateTokenEx",           API_DuplicateTokenEx },

    // Advapi32: Service
    { "OpenSCManagerA",             API_OpenSCManager },
    { "OpenSCManagerW",             API_OpenSCManager },
    { "CreateServiceA",             API_CreateService },
    { "CreateServiceW",             API_CreateService },
    { "StartServiceA",              API_StartService },
    { "StartServiceW",              API_StartService },
    { "OpenServiceA",               API_OpenService },
    { "OpenServiceW",               API_OpenService },
    { "DeleteService",              API_DeleteService },
    { "CloseServiceHandle",         API_CloseServiceHandle },

    // Advapi32: Crypto
    { "CryptAcquireContextA",       API_CryptAcquireContext },
    { "CryptAcquireContextW",       API_CryptAcquireContext },
    { "CryptGenRandom",             API_CryptGenRandom },
    { "CryptEncrypt",               API_CryptEncrypt },
    { "CryptDecrypt",               API_CryptDecrypt },
    { "CryptCreateHash",            API_CryptCreateHash },
    { "CryptHashData",              API_CryptHashData },
    { "CryptReleaseContext",        API_CryptReleaseContext },
    { "CryptGenKey",                API_CryptGenKey },
    { "CryptExportKey",             API_CryptExportKey },
    { "CryptImportKey",             API_CryptImportKey },
    { "CryptDestroyKey",            API_CryptDestroyKey },

    // Advapi32: Credential
    { "LsaOpenPolicy",              API_LsaOpenPolicy },
    { "LsaRetrievePrivateData",     API_LsaRetrievePrivateData },
    { "CredEnumerateA",             API_CredEnumerate },
    { "CredEnumerateW",             API_CredEnumerate },
    { "CredReadA",                  API_CredRead },
    { "CredReadW",                  API_CredRead },

    // Ws2_32
    { "WSAStartup",                 API_WSAStartup },
    { "WSACleanup",                 API_WSACleanup },
    { "socket",                     API_socket },
    { "WSASocketA",                 API_WSASocket },
    { "WSASocketW",                 API_WSASocket },
    { "connect",                    API_connect },
    { "send",                       API_send },
    { "recv",                       API_recv },
    { "bind",                       API_bind },
    { "listen",                     API_listen },
    { "accept",                     API_accept },
    { "closesocket",                API_closesocket },
    { "getaddrinfo",                API_getaddrinfo },
    { "GetAddrInfoW",               API_getaddrinfo },
    { "freeaddrinfo",               API_getaddrinfo },
    { "gethostbyname",              API_gethostbyname },
    { "inet_addr",                  API_Unknown },
    { "htons",                      API_Unknown },
    { "ntohs",                      API_Unknown },
    { "WSAGetLastError",            API_Unknown },
    { "select",                     API_select },
    { "ioctlsocket",               API_Unknown },
    { "setsockopt",                 API_Unknown },

    // Wininet
    { "InternetOpenA",              API_InternetOpen },
    { "InternetOpenW",              API_InternetOpen },
    { "InternetConnectA",           API_InternetConnect },
    { "InternetConnectW",           API_InternetConnect },
    { "HttpOpenRequestA",           API_HttpOpenRequest },
    { "HttpOpenRequestW",           API_HttpOpenRequest },
    { "HttpSendRequestA",           API_HttpSendRequest },
    { "HttpSendRequestW",           API_HttpSendRequest },
    { "InternetReadFile",           API_InternetReadFile },
    { "InternetCloseHandle",        API_InternetCloseHandle },
    { "InternetOpenUrlA",           API_InternetOpenUrl },
    { "InternetOpenUrlW",           API_InternetOpenUrl },
    { "InternetWriteFile",          API_InternetWriteFile },

    // Winhttp
    { "WinHttpOpen",                API_WinHttpOpen },
    { "WinHttpConnect",             API_WinHttpConnect },
    { "WinHttpOpenRequest",         API_WinHttpOpenRequest },
    { "WinHttpSendRequest",         API_WinHttpSendRequest },
    { "WinHttpReceiveResponse",     API_WinHttpReceiveResponse },
    { "WinHttpReadData",            API_WinHttpReadData },
    { "WinHttpCloseHandle",         API_WinHttpCloseHandle },

    // Urlmon
    { "URLDownloadToFileA",         API_URLDownloadToFile },
    { "URLDownloadToFileW",         API_URLDownloadToFile },
    { "URLDownloadToCacheFileA",    API_URLDownloadToFile },
    { "URLDownloadToCacheFileW",    API_URLDownloadToFile },

    // User32
    { "MessageBoxA",                API_MessageBox },
    { "MessageBoxW",                API_MessageBox },
    { "FindWindowA",                API_FindWindow },
    { "FindWindowW",                API_FindWindow },
    { "GetForegroundWindow",        API_GetForegroundWindow },
    { "GetDesktopWindow",           API_GetDesktopWindow },
    { "EnumWindows",                API_EnumWindows },
    { "GetWindowTextA",             API_GetWindowText },
    { "GetWindowTextW",             API_GetWindowText },
    { "SetWindowsHookExA",          API_SetWindowsHookEx },
    { "SetWindowsHookExW",          API_SetWindowsHookEx },
    { "GetAsyncKeyState",           API_GetAsyncKeyState },
    { "GetMessageA",                API_GetMessage },
    { "GetMessageW",                API_GetMessage },
    { "PeekMessageA",               API_PeekMessage },
    { "PeekMessageW",               API_PeekMessage },
    { "GetClipboardData",           API_GetClipboardData },

    // Shell32
    { "ShellExecuteA",              API_ShellExecute },
    { "ShellExecuteW",              API_ShellExecute },
    { "ShellExecuteExA",            API_ShellExecuteEx },
    { "ShellExecuteExW",            API_ShellExecuteEx },
    { "SHGetFolderPathA",           API_SHGetFolderPath },
    { "SHGetFolderPathW",           API_SHGetFolderPath },

    // Ole32
    { "CoInitializeEx",             API_CoInitializeEx },
    { "CoUninitialize",             API_CoUninitialize },
    { "CoCreateInstance",           API_CoCreateInstance },
    { "CoGetClassObject",           API_CoCreateInstance },

    // Network Discovery
    { "WNetAddConnection2A",        API_WNetAddConnection2 },
    { "WNetAddConnection2W",        API_WNetAddConnection2 },
    { "NetShareEnum",               API_NetShareEnum },
    { "NetServerEnum",              API_NetServerEnum },
    { "NetUserEnum",                API_NetUserEnum },
    { "NetLocalGroupGetMembers",    API_NetLocalGroupGetMembers },
    { "GetAdaptersInfo",            API_GetAdaptersInfo },
    { "GetIpForwardTable",          API_GetIpForwardTable },
    { "LookupAccountNameA",         API_LookupAccountName },
    { "LookupAccountNameW",         API_LookupAccountName },
    { "DnsQuery_A",                 API_DnsQuery },
    { "DnsQuery_W",                 API_DnsQuery },
    { "DnsQueryEx",                 API_DnsQuery },
};

static constexpr uint32_t kAPINameCount =
    static_cast<uint32_t>(sizeof(kAPINames) / sizeof(kAPINames[0]));

// Build a case-insensitive lookup map (Meyers singleton)
[[nodiscard]] static const std::unordered_map<std::string, APIId>& GetNameMap() noexcept {
    static const auto sMap = []() {
        std::unordered_map<std::string, APIId> m;
        m.reserve(kAPINameCount * 2);
        for (uint32_t i = 0; i < kAPINameCount; ++i) {
            std::string lower;
            lower.reserve(64);
            for (const char* p = kAPINames[i].funcName; *p; ++p)
                lower += static_cast<char>(std::tolower(static_cast<unsigned char>(*p)));
            m.emplace(std::move(lower), kAPINames[i].id);
        }
        return m;
    }();
    return sMap;
}

[[nodiscard]] static APIId ResolveAPIId(const char* funcName) noexcept {
    if (!funcName || !funcName[0]) return API_Unknown;
    char buf[128];
    uint32_t len = 0;
    for (; funcName[len] && len < 127; ++len)
        buf[len] = static_cast<char>(std::tolower(static_cast<unsigned char>(funcName[len])));
    buf[len] = '\0';
    const auto& map = GetNameMap();
    auto it = map.find(std::string(buf, len));
    return (it != map.end()) ? it->second : API_Unknown;
}

// ============================================================================
// Pattern Sequence Data
// ============================================================================
// Each kPxxx array defines the API sequence for one pattern. Patterns are
// matched as ordered subsequences with configurable gap tolerance.

// --- Process Injection (1–20) ---
static const APIId kP1[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_CreateRemoteThread };
static const APIId kP2[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_QueueUserAPC };
static const APIId kP3[] = { API_NtCreateSection, API_NtMapViewOfSection, API_NtMapViewOfSection };
static const APIId kP4[] = { API_CreateProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_QueueUserAPC, API_ResumeThread };
static const APIId kP5[] = { API_OpenThread, API_SuspendThread, API_GetThreadContext, API_SetThreadContext, API_ResumeThread };
static const APIId kP6[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_RtlCreateUserThread };
static const APIId kP7[] = { API_NtAllocateVirtualMemory, API_NtWriteVirtualMemory, API_NtCreateThreadEx };
static const APIId kP8[] = { API_NtAllocateVirtualMemory, API_NtWriteVirtualMemory, API_QueueUserAPC };
static const APIId kP9[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_CreateRemoteThreadEx };
static const APIId kP10[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_VirtualProtectEx, API_CreateRemoteThread };
static const APIId kP11[] = { API_OpenProcess, API_NtAllocateVirtualMemory, API_NtWriteVirtualMemory, API_QueueUserAPC };
static const APIId kP12[] = { API_LoadLibrary, API_GetProcAddress, API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_CreateRemoteThread };
static const APIId kP13[] = { API_VirtualAlloc, API_WriteProcessMemory, API_VirtualProtect, API_CreateThread };
static const APIId kP14[] = { API_NtCreateSection, API_NtMapViewOfSection, API_NtMapViewOfSection, API_NtResumeThread };
static const APIId kP15[] = { API_OpenProcess, API_WriteProcessMemory, API_NtCreateThreadEx };
static const APIId kP16[] = { API_OpenProcess, API_VirtualAllocEx, API_NtWriteVirtualMemory, API_CreateRemoteThread };
static const APIId kP17[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_SetThreadContext };
static const APIId kP18[] = { API_OpenProcess, API_SuspendThread, API_VirtualAllocEx, API_WriteProcessMemory, API_ResumeThread };
static const APIId kP19[] = { API_OpenProcess, API_VirtualProtectEx, API_WriteProcessMemory, API_CreateRemoteThread };
static const APIId kP20[] = { API_NtOpenProcess, API_NtAllocateVirtualMemory, API_NtWriteVirtualMemory, API_NtCreateThreadEx };

// --- Process Hollowing (21–28) ---
static const APIId kP21[] = { API_CreateProcess, API_NtUnmapViewOfSection, API_VirtualAllocEx, API_WriteProcessMemory, API_SetThreadContext, API_ResumeThread };
static const APIId kP22[] = { API_CreateProcess, API_NtUnmapViewOfSection, API_NtAllocateVirtualMemory, API_NtWriteVirtualMemory, API_SetThreadContext, API_ResumeThread };
static const APIId kP23[] = { API_NtCreateSection, API_CreateProcess, API_NtUnmapViewOfSection, API_NtMapViewOfSection, API_ResumeThread };
static const APIId kP24[] = { API_CreateProcess, API_NtUnmapViewOfSection, API_VirtualAllocEx, API_WriteProcessMemory, API_NtResumeThread };
static const APIId kP25[] = { API_CreateProcess, API_WriteProcessMemory, API_SetThreadContext, API_ResumeThread };
static const APIId kP26[] = { API_CreateProcess, API_NtUnmapViewOfSection, API_NtCreateSection, API_NtMapViewOfSection, API_SetThreadContext, API_ResumeThread };
static const APIId kP27[] = { API_CreateProcess, API_NtUnmapViewOfSection, API_VirtualAllocEx, API_WriteProcessMemory, API_GetThreadContext, API_SetThreadContext, API_ResumeThread };
static const APIId kP28[] = { API_CreateProcess, API_ReadProcessMemory, API_NtUnmapViewOfSection, API_VirtualAllocEx, API_WriteProcessMemory, API_ResumeThread };

// --- Credential Theft (29–39) ---
static const APIId kP29[] = { API_OpenProcess, API_ReadProcessMemory, API_ReadProcessMemory };
static const APIId kP30[] = { API_RegOpenKeyEx, API_RegQueryValueEx, API_RegQueryValueEx };
static const APIId kP31[] = { API_LsaOpenPolicy, API_LsaRetrievePrivateData };
static const APIId kP32[] = { API_OpenProcessToken, API_DuplicateTokenEx, API_CreateProcessAsUser };
static const APIId kP33[] = { API_CredEnumerate };
static const APIId kP34[] = { API_CredRead };
static const APIId kP35[] = { API_OpenProcessToken, API_ImpersonateLoggedOnUser };
static const APIId kP36[] = { API_OpenProcessToken, API_AdjustTokenPrivileges, API_CreateProcess };
static const APIId kP37[] = { API_NtOpenProcessToken, API_NtQueryInformationToken, API_NtAdjustPrivilegesToken };
static const APIId kP38[] = { API_OpenProcess, API_ReadProcessMemory, API_ReadProcessMemory, API_ReadProcessMemory };
static const APIId kP39[] = { API_NtOpenProcess, API_NtReadVirtualMemory, API_NtReadVirtualMemory };

// --- Ransomware (40–57) ---
static const APIId kP40[] = { API_FindFirstFile, API_FindNextFile, API_CreateFile, API_ReadFile, API_CryptEncrypt, API_WriteFile, API_CloseHandle };
static const APIId kP41[] = { API_FindFirstFile, API_FindNextFile, API_CreateFile, API_ReadFile, API_CryptGenRandom, API_WriteFile };
static const APIId kP42[] = { API_CryptAcquireContext, API_CryptGenKey, API_FindFirstFile, API_FindNextFile, API_CryptEncrypt };
static const APIId kP43[] = { API_CryptAcquireContext, API_CryptGenKey, API_CryptExportKey };
static const APIId kP44[] = { API_GetLogicalDrives, API_GetDriveType, API_FindFirstFile };
static const APIId kP45[] = { API_FindFirstFile, API_FindNextFile, API_MoveFile };
static const APIId kP46[] = { API_FindFirstFile, API_FindNextFile, API_DeleteFile };
static const APIId kP47[] = { API_CreateFile, API_WriteFile, API_CloseHandle, API_DeleteFile };
static const APIId kP48[] = { API_FindFirstFile, API_FindNextFile, API_FindFirstFile };
static const APIId kP49[] = { API_CreateFile, API_ReadFile, API_CryptEncrypt, API_WriteFile, API_MoveFile };
static const APIId kP50[] = { API_CryptAcquireContext, API_CryptImportKey, API_CryptEncrypt };
static const APIId kP51[] = { API_GetLogicalDrives, API_GetDriveType, API_FindFirstFile, API_FindNextFile, API_CreateFile, API_ReadFile, API_CryptEncrypt, API_WriteFile };
static const APIId kP52[] = { API_FindFirstFile, API_FindNextFile, API_ReadFile, API_WriteFile, API_MoveFile };
static const APIId kP53[] = { API_CryptAcquireContext, API_CryptGenRandom, API_CreateFile, API_WriteFile };
static const APIId kP54[] = { API_FindFirstFile, API_FindNextFile, API_CreateFile, API_WriteFile, API_DeleteFile };
static const APIId kP55[] = { API_CryptAcquireContext, API_CryptGenKey, API_CryptExportKey, API_FindFirstFile, API_CryptEncrypt };
static const APIId kP56[] = { API_FindFirstFile, API_FindNextFile, API_ReadFile, API_CryptEncrypt, API_WriteFile };
static const APIId kP57[] = { API_GetLogicalDrives, API_GetDriveType, API_FindFirstFile, API_FindNextFile, API_CryptEncrypt };

// --- Downloader/Dropper (58–72) ---
static const APIId kP58[] = { API_InternetOpen, API_InternetOpenUrl, API_InternetReadFile, API_CreateFile, API_WriteFile };
static const APIId kP59[] = { API_URLDownloadToFile, API_CreateProcess };
static const APIId kP60[] = { API_WinHttpOpen, API_WinHttpConnect, API_WinHttpOpenRequest, API_WinHttpSendRequest, API_WinHttpReceiveResponse };
static const APIId kP61[] = { API_WSAStartup, API_socket, API_connect, API_send, API_recv, API_CreateFile, API_WriteFile };
static const APIId kP62[] = { API_CoCreateInstance, API_InternetReadFile, API_CreateFile, API_WriteFile };
static const APIId kP63[] = { API_LoadLibrary, API_GetProcAddress, API_InternetOpen, API_InternetOpenUrl, API_InternetReadFile };
static const APIId kP64[] = { API_InternetOpen, API_InternetConnect, API_HttpOpenRequest, API_HttpSendRequest, API_InternetReadFile, API_CreateFile, API_WriteFile };
static const APIId kP65[] = { API_InternetReadFile, API_CreateFile, API_WriteFile, API_CreateProcess };
static const APIId kP66[] = { API_WinHttpOpen, API_WinHttpConnect, API_WinHttpOpenRequest, API_WinHttpSendRequest, API_WinHttpReceiveResponse, API_WinHttpReadData, API_CreateFile, API_WriteFile };
static const APIId kP67[] = { API_gethostbyname, API_socket, API_connect, API_recv, API_CreateFile, API_WriteFile };
static const APIId kP68[] = { API_URLDownloadToFile, API_ShellExecute };
static const APIId kP69[] = { API_InternetOpen, API_InternetOpenUrl, API_InternetReadFile, API_CreateFile, API_WriteFile, API_CreateProcess };
static const APIId kP70[] = { API_WSAStartup, API_socket, API_connect, API_recv, API_CreateProcess };
static const APIId kP71[] = { API_URLDownloadToFile, API_LoadLibrary };
static const APIId kP72[] = { API_WinHttpOpen, API_WinHttpConnect, API_WinHttpOpenRequest, API_WinHttpSendRequest, API_WinHttpReceiveResponse, API_WinHttpReadData, API_CreateProcess };

// --- Persistence (73–89) ---
static const APIId kP73[] = { API_RegOpenKeyEx, API_RegSetValueEx };
static const APIId kP74[] = { API_RegCreateKeyEx, API_RegSetValueEx };
static const APIId kP75[] = { API_OpenSCManager, API_CreateService };
static const APIId kP76[] = { API_CopyFile, API_RegOpenKeyEx, API_RegSetValueEx };
static const APIId kP77[] = { API_SHGetFolderPath, API_CopyFile };
static const APIId kP78[] = { API_OpenSCManager, API_OpenService, API_StartService };
static const APIId kP79[] = { API_NtOpenKey, API_NtSetValueKey };
static const APIId kP80[] = { API_RegCreateKeyEx, API_RegSetValueEx, API_RegCloseKey };
static const APIId kP81[] = { API_RegOpenKeyEx, API_RegSetValueEx, API_RegSetValueEx };
static const APIId kP82[] = { API_OpenSCManager, API_CreateService, API_StartService };
static const APIId kP83[] = { API_NtCreateKey, API_NtSetValueKey };
static const APIId kP84[] = { API_CreateFile, API_WriteFile, API_RegOpenKeyEx, API_RegSetValueEx };
static const APIId kP85[] = { API_CopyFile, API_OpenSCManager, API_CreateService, API_StartService };
static const APIId kP86[] = { API_SHGetFolderPath, API_CreateFile, API_WriteFile };
static const APIId kP87[] = { API_GetTempPath, API_CreateFile, API_WriteFile, API_CreateProcess };
static const APIId kP88[] = { API_RegOpenKeyEx, API_RegSetValueEx, API_RegOpenKeyEx, API_RegSetValueEx };
static const APIId kP89[] = { API_GetModuleFileName, API_CopyFile, API_RegOpenKeyEx, API_RegSetValueEx };

// --- Evasion (90–109) ---
static const APIId kP90[] = { API_IsDebuggerPresent };
static const APIId kP91[] = { API_NtQueryInformationProcess };
static const APIId kP92[] = { API_GetTickCount, API_GetTickCount };
static const APIId kP93[] = { API_CreateToolhelp32Snapshot, API_Process32First, API_Process32Next };
static const APIId kP94[] = { API_NtSetInformationThread };
static const APIId kP95[] = { API_GetModuleHandle, API_GetProcAddress, API_VirtualProtect };
static const APIId kP96[] = { API_QueryPerformanceCounter, API_QueryPerformanceCounter };
static const APIId kP97[] = { API_FindWindow };
static const APIId kP98[] = { API_NtQuerySystemInformation };
static const APIId kP99[] = { API_CheckRemoteDebuggerPresent };
static const APIId kP100[] = { API_Sleep, API_GetTickCount };
static const APIId kP101[] = { API_GetComputerName, API_GetUserName, API_GetSystemInfo };
static const APIId kP102[] = { API_GetDiskFreeSpaceEx };
static const APIId kP103[] = { API_GetTickCount64, API_GetTickCount64 };
static const APIId kP104[] = { API_OutputDebugString, API_GetLastError };
static const APIId kP105[] = { API_NtQueryInformationProcess, API_NtQueryInformationProcess };
static const APIId kP106[] = { API_GetModuleHandle, API_GetProcAddress, API_VirtualProtect, API_WriteProcessMemory };
static const APIId kP107[] = { API_LoadLibrary, API_CreateFile, API_ReadFile, API_VirtualProtect };
static const APIId kP108[] = { API_IsDebuggerPresent, API_CheckRemoteDebuggerPresent };
static const APIId kP109[] = { API_NtQueryInformationProcess, API_NtQuerySystemInformation };

// --- Keylogger (110–117) ---
static const APIId kP110[] = { API_SetWindowsHookEx, API_GetMessage };
static const APIId kP111[] = { API_SetWindowsHookEx, API_PeekMessage };
static const APIId kP112[] = { API_GetAsyncKeyState, API_GetAsyncKeyState };
static const APIId kP113[] = { API_GetForegroundWindow, API_GetWindowText, API_GetAsyncKeyState };
static const APIId kP114[] = { API_GetForegroundWindow, API_GetWindowText };
static const APIId kP115[] = { API_SetWindowsHookEx, API_CreateFile, API_WriteFile };
static const APIId kP116[] = { API_GetAsyncKeyState, API_CreateFile, API_WriteFile };
static const APIId kP117[] = { API_SetWindowsHookEx, API_GetMessage, API_CreateFile, API_WriteFile };

// --- Lateral Movement (118–127) ---
static const APIId kP118[] = { API_WNetAddConnection2, API_CopyFile, API_OpenSCManager, API_CreateService, API_StartService };
static const APIId kP119[] = { API_CoCreateInstance, API_CreateProcess };
static const APIId kP120[] = { API_OpenSCManager, API_CreateService, API_StartService };
static const APIId kP121[] = { API_WNetAddConnection2, API_CopyFile, API_CreateProcess };
static const APIId kP122[] = { API_OpenSCManager, API_OpenService, API_StartService };
static const APIId kP123[] = { API_NetShareEnum, API_NetServerEnum };
static const APIId kP124[] = { API_WNetAddConnection2, API_CopyFile };
static const APIId kP125[] = { API_WNetAddConnection2, API_OpenSCManager, API_CreateService };
static const APIId kP126[] = { API_NetShareEnum, API_WNetAddConnection2, API_CopyFile };
static const APIId kP127[] = { API_CoCreateInstance, API_CoCreateInstance, API_CreateProcess };

// --- C2 Communication (128–143) ---
static const APIId kP128[] = { API_InternetOpen, API_InternetConnect, API_HttpOpenRequest, API_HttpSendRequest, API_InternetReadFile };
static const APIId kP129[] = { API_InternetConnect, API_HttpOpenRequest, API_HttpSendRequest, API_InternetReadFile, API_Sleep };
static const APIId kP130[] = { API_DnsQuery, API_Sleep, API_DnsQuery };
static const APIId kP131[] = { API_socket, API_connect, API_send, API_recv, API_Sleep };
static const APIId kP132[] = { API_CreateNamedPipe, API_ConnectNamedPipe, API_ReadFile, API_WriteFile };
static const APIId kP133[] = { API_WinHttpOpen, API_WinHttpConnect, API_WinHttpOpenRequest, API_WinHttpSendRequest, API_WinHttpReceiveResponse, API_WinHttpReadData };
static const APIId kP134[] = { API_InternetOpen, API_InternetConnect, API_HttpOpenRequest, API_HttpSendRequest };
static const APIId kP135[] = { API_WSAStartup, API_socket, API_connect, API_CreateProcess };
static const APIId kP136[] = { API_socket, API_connect, API_send, API_recv, API_send, API_recv };
static const APIId kP137[] = { API_gethostbyname, API_socket, API_connect, API_send, API_recv };
static const APIId kP138[] = { API_InternetOpen, API_InternetConnect, API_HttpOpenRequest, API_HttpSendRequest, API_Sleep, API_HttpOpenRequest };
static const APIId kP139[] = { API_InternetOpen, API_InternetConnect, API_HttpOpenRequest, API_InternetWriteFile };
static const APIId kP140[] = { API_socket, API_connect, API_send, API_recv };
static const APIId kP141[] = { API_WSAStartup, API_socket, API_connect, API_send, API_recv, API_Sleep };
static const APIId kP142[] = { API_socket, API_bind, API_listen, API_accept, API_recv };
static const APIId kP143[] = { API_WSAStartup, API_socket, API_connect, API_recv, API_send, API_Sleep, API_recv };

// --- Discovery (144–161) ---
static const APIId kP144[] = { API_CreateToolhelp32Snapshot, API_Process32First, API_Process32Next };
static const APIId kP145[] = { API_CreateToolhelp32Snapshot, API_Module32First, API_Module32Next };
static const APIId kP146[] = { API_CreateToolhelp32Snapshot, API_Thread32First, API_Thread32Next };
static const APIId kP147[] = { API_NetShareEnum };
static const APIId kP148[] = { API_NetServerEnum };
static const APIId kP149[] = { API_GetAdaptersInfo };
static const APIId kP150[] = { API_GetIpForwardTable };
static const APIId kP151[] = { API_LookupAccountName, API_NetUserEnum };
static const APIId kP152[] = { API_NetLocalGroupGetMembers };
static const APIId kP153[] = { API_GetComputerName, API_GetUserName, API_GetSystemInfo, API_GetVersionEx };
static const APIId kP154[] = { API_GetLogicalDrives, API_GetDriveType, API_GetDiskFreeSpaceEx };
static const APIId kP155[] = { API_RegOpenKeyEx, API_RegQueryValueEx, API_RegOpenKeyEx, API_RegQueryValueEx };
static const APIId kP156[] = { API_Process32Next, API_Process32Next, API_Process32Next };
static const APIId kP157[] = { API_GetComputerName, API_GetUserName };
static const APIId kP158[] = { API_GetVersionEx, API_GetSystemInfo, API_IsWow64Process };
static const APIId kP159[] = { API_CreateToolhelp32Snapshot, API_Process32First, API_Process32Next, API_Process32Next, API_Process32Next };
static const APIId kP160[] = { API_GetAdaptersInfo, API_GetIpForwardTable };
static const APIId kP161[] = { API_NetShareEnum, API_WNetAddConnection2 };

// --- Data Exfiltration (162–174) ---
static const APIId kP162[] = { API_ReadFile, API_send };
static const APIId kP163[] = { API_CryptEncrypt, API_send };
static const APIId kP164[] = { API_CreateFile, API_ReadFile, API_HttpSendRequest };
static const APIId kP165[] = { API_CreateFile, API_ReadFile, API_WinHttpSendRequest };
static const APIId kP166[] = { API_CreateFile, API_ReadFile, API_InternetWriteFile };
static const APIId kP167[] = { API_InternetOpen, API_InternetConnect, API_CreateFile, API_ReadFile };
static const APIId kP168[] = { API_CreateFile, API_ReadFile, API_CryptEncrypt, API_send };
static const APIId kP169[] = { API_GetClipboardData, API_send };
static const APIId kP170[] = { API_ReadFile, API_CryptEncrypt, API_HttpSendRequest };
static const APIId kP171[] = { API_FindFirstFile, API_FindNextFile, API_ReadFile, API_send };
static const APIId kP172[] = { API_CreateFile, API_ReadFile, API_CryptEncrypt, API_InternetWriteFile };
static const APIId kP173[] = { API_CreateFile, API_ReadFile, API_CryptEncrypt, API_WinHttpSendRequest };
static const APIId kP174[] = { API_FindFirstFile, API_FindNextFile, API_ReadFile, API_CryptEncrypt, API_send };

// --- DLL Injection (175–182) ---
static const APIId kP175[] = { API_LoadLibrary, API_GetProcAddress, API_SetWindowsHookEx };
static const APIId kP176[] = { API_LdrLoadDll };
static const APIId kP177[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_CreateRemoteThread };
static const APIId kP178[] = { API_RegCreateKeyEx, API_RegSetValueEx };
static const APIId kP179[] = { API_OpenProcess, API_VirtualAllocEx, API_WriteProcessMemory, API_NtCreateThreadEx };
static const APIId kP180[] = { API_LoadLibrary, API_GetProcAddress, API_OpenProcess, API_CreateRemoteThread };
static const APIId kP181[] = { API_NtOpenProcess, API_NtAllocateVirtualMemory, API_NtWriteVirtualMemory, API_RtlCreateUserThread };
static const APIId kP182[] = { API_OpenProcess, API_NtMapViewOfSection, API_CreateRemoteThread };

// --- Privilege Escalation (183–192) ---
static const APIId kP183[] = { API_OpenProcessToken, API_LookupPrivilegeValue, API_AdjustTokenPrivileges };
static const APIId kP184[] = { API_OpenProcessToken, API_DuplicateTokenEx, API_CreateProcessAsUser };
static const APIId kP185[] = { API_CreateNamedPipe, API_ConnectNamedPipe, API_ImpersonateLoggedOnUser };
static const APIId kP186[] = { API_OpenSCManager, API_CreateService, API_StartService };
static const APIId kP187[] = { API_CoCreateInstance, API_ShellExecute };
static const APIId kP188[] = { API_NtOpenProcessToken, API_NtAdjustPrivilegesToken };
static const APIId kP189[] = { API_OpenProcessToken, API_GetTokenInformation, API_DuplicateTokenEx };
static const APIId kP190[] = { API_OpenProcessToken, API_AdjustTokenPrivileges, API_OpenProcess };
static const APIId kP191[] = { API_NtOpenProcessToken, API_NtQueryInformationToken, API_NtDuplicateObject };
static const APIId kP192[] = { API_LookupPrivilegeValue, API_AdjustTokenPrivileges, API_CreateProcess };

// --- Additional Evasion / Defense Evasion (193–204) ---
static const APIId kP193[] = { API_VirtualAlloc, API_VirtualProtect, API_CreateThread };
static const APIId kP194[] = { API_GetModuleHandle, API_GetProcAddress, API_VirtualProtect, API_WriteProcessMemory };
static const APIId kP195[] = { API_NtAllocateVirtualMemory, API_NtProtectVirtualMemory, API_NtCreateThreadEx };
static const APIId kP196[] = { API_LoadLibrary, API_GetProcAddress, API_VirtualAlloc };
static const APIId kP197[] = { API_NtQueryInformationProcess, API_IsDebuggerPresent };
static const APIId kP198[] = { API_GetModuleHandle, API_GetModuleHandle, API_GetModuleHandle };
static const APIId kP199[] = { API_FindWindow, API_FindWindow, API_FindWindow };
static const APIId kP200[] = { API_CreateToolhelp32Snapshot, API_Process32First, API_Process32Next, API_OpenProcess };
static const APIId kP201[] = { API_GetTickCount, API_Sleep, API_GetTickCount };
static const APIId kP202[] = { API_RtlDecompressBuffer, API_VirtualAlloc, API_VirtualProtect, API_CreateThread };
static const APIId kP203[] = { API_VirtualAlloc, API_RtlDecompressBuffer, API_VirtualProtect };
static const APIId kP204[] = { API_NtAllocateVirtualMemory, API_RtlDecompressBuffer, API_NtProtectVirtualMemory, API_NtCreateThreadEx };

// --- Shellcode Execution (205–212) ---
static const APIId kP205[] = { API_VirtualAlloc, API_WriteProcessMemory, API_CreateThread };
static const APIId kP206[] = { API_VirtualAlloc, API_VirtualProtect, API_CreateRemoteThread };
static const APIId kP207[] = { API_NtAllocateVirtualMemory, API_NtProtectVirtualMemory, API_CreateThread };
static const APIId kP208[] = { API_HeapCreate, API_HeapAlloc, API_VirtualProtect, API_CreateThread };
static const APIId kP209[] = { API_VirtualAlloc, API_LoadLibrary, API_GetProcAddress, API_CreateThread };
static const APIId kP210[] = { API_NtAllocateVirtualMemory, API_NtWriteVirtualMemory, API_NtProtectVirtualMemory };
static const APIId kP211[] = { API_VirtualAlloc, API_CopyFile, API_VirtualProtect, API_CreateThread };
static const APIId kP212[] = { API_GlobalAlloc, API_VirtualProtect, API_CreateThread };

// --- Wiper / Destruction (213–218) ---
static const APIId kP213[] = { API_FindFirstFile, API_FindNextFile, API_CreateFile, API_WriteFile, API_CloseHandle, API_FindNextFile };
static const APIId kP214[] = { API_GetLogicalDrives, API_GetDriveType, API_FindFirstFile, API_FindNextFile, API_DeleteFile };
static const APIId kP215[] = { API_CreateFile, API_SetFilePointer, API_WriteFile, API_CloseHandle };
static const APIId kP216[] = { API_FindFirstFile, API_FindNextFile, API_SetFileAttributes, API_DeleteFile };
static const APIId kP217[] = { API_GetLogicalDrives, API_GetDriveType, API_FindFirstFile, API_DeleteFile, API_FindNextFile, API_DeleteFile };
static const APIId kP218[] = { API_FindFirstFile, API_FindNextFile, API_MoveFile, API_DeleteFile };

// --- Reflective Loading (219–224) ---
static const APIId kP219[] = { API_VirtualAlloc, API_ReadFile, API_VirtualProtect, API_CreateThread };
static const APIId kP220[] = { API_NtAllocateVirtualMemory, API_NtReadFile, API_NtProtectVirtualMemory, API_NtCreateThreadEx };
static const APIId kP221[] = { API_InternetReadFile, API_VirtualAlloc, API_VirtualProtect, API_CreateThread };
static const APIId kP222[] = { API_recv, API_VirtualAlloc, API_VirtualProtect, API_CreateThread };
static const APIId kP223[] = { API_CreateFile, API_ReadFile, API_VirtualAlloc, API_VirtualProtect, API_CreateThread };
static const APIId kP224[] = { API_WinHttpReadData, API_VirtualAlloc, API_VirtualProtect, API_CreateThread };

// --- Service Manipulation / Persistence Extended (225–230) ---
static const APIId kP225[] = { API_OpenSCManager, API_CreateService, API_StartService, API_CloseServiceHandle };
static const APIId kP226[] = { API_OpenSCManager, API_OpenService, API_DeleteService };
static const APIId kP227[] = { API_OpenSCManager, API_OpenService, API_StartService, API_CloseServiceHandle };
static const APIId kP228[] = { API_GetModuleFileName, API_OpenSCManager, API_CreateService };
static const APIId kP229[] = { API_CopyFile, API_RegCreateKeyEx, API_RegSetValueEx, API_RegCloseKey };
static const APIId kP230[] = { API_GetTempPath, API_CopyFile, API_RegOpenKeyEx, API_RegSetValueEx };

// ============================================================================
// Pattern Metadata Table
// ============================================================================

struct PatternDef {
    uint16_t    id;
    const char* name;
    const char* mitreId;
    uint8_t     severity;   // 0-4 maps to ThreatLevel
    uint8_t     maxGap;     // Max non-matching calls between consecutive elements
    const APIId* sequence;
    uint8_t     length;
};

#define PDEF(idx, nm, mitre, sev, gap) \
    { idx, nm, mitre, sev, gap, kP##idx, static_cast<uint8_t>(sizeof(kP##idx) / sizeof(APIId)) }

static const PatternDef kPatterns[] = {
    // --- Process Injection (T1055) ---
    PDEF(1, "Classic Remote Thread Injection",               "T1055.002", 4, 12),
    PDEF(2, "APC Queue Injection",                           "T1055.004", 4, 12),
    PDEF(3, "Section Mapping Injection",                     "T1055.012", 4, 10),
    PDEF(4, "Early Bird APC Injection",                      "T1055.004", 4, 14),
    PDEF(5, "Thread Execution Hijacking",                    "T1055.003", 4, 10),
    PDEF(6, "RtlCreateUserThread Injection",                 "T1055.002", 4, 12),
    PDEF(7, "Nt* API Process Injection",                     "T1055.002", 4, 10),
    PDEF(8, "Nt* APC Injection",                             "T1055.004", 4, 10),
    PDEF(9, "CreateRemoteThreadEx Injection",                "T1055.002", 4, 12),
    PDEF(10, "VirtualProtectEx + Remote Thread Injection",    "T1055.002", 4, 14),
    PDEF(11, "Nt* Memory + APC Injection",                    "T1055.004", 4, 12),
    PDEF(12, "Dynamic API Resolve + Injection",               "T1055.001", 4, 20),
    PDEF(13, "Self-Injection via VirtualAlloc",               "T1055.002", 3, 10),
    PDEF(14, "Section Map Double-Map Injection",              "T1055.012", 4, 12),
    PDEF(15, "WriteProcessMemory + NtCreateThreadEx",         "T1055.002", 4, 10),
    PDEF(16, "Mixed API Injection (VA + Nt Write)",           "T1055.002", 4, 12),
    PDEF(17, "Stack Pivot via SetThreadContext",              "T1055.003", 4, 12),
    PDEF(18, "Suspend-Inject-Resume",                         "T1055.003", 4, 14),
    PDEF(19, "Module Stomping Injection",                     "T1055.002", 4, 12),
    PDEF(20, "Full Nt* Injection Chain",                      "T1055.002", 4, 10),

    // --- Process Hollowing (T1055.012) ---
    PDEF(21, "Classic Process Hollowing",                     "T1055.012", 4, 14),
    PDEF(22, "Nt* Process Hollowing",                         "T1055.012", 4, 14),
    PDEF(23, "Transacted Section Hollowing",                  "T1055.013", 4, 14),
    PDEF(24, "Hollowing + NtResumeThread",                    "T1055.012", 4, 14),
    PDEF(25, "Minimal Process Hollowing",                     "T1055.012", 4, 12),
    PDEF(26, "Section-Based Process Hollowing",               "T1055.012", 4, 14),
    PDEF(27, "Hollowing with Context Manipulation",           "T1055.012", 4, 16),
    PDEF(28, "Hollowing with Memory Read",                    "T1055.012", 4, 16),

    // --- Credential Theft (T1003) ---
    PDEF(29, "LSASS Memory Dump",                             "T1003.001", 4, 8),
    PDEF(30, "SAM Registry Credential Dump",                  "T1003.002", 3, 8),
    PDEF(31, "LSA Secret Retrieval",                          "T1003.004", 4, 6),
    PDEF(32, "Token Theft + Process Creation",                "T1134.002", 4, 10),
    PDEF(33, "Credential Vault Enumeration",                  "T1555",     3, 4),
    PDEF(34, "Credential Vault Read",                         "T1555",     3, 4),
    PDEF(35, "Token Impersonation",                           "T1134.001", 3, 8),
    PDEF(36, "Privilege Token + Process Spawn",               "T1134.002", 4, 12),
    PDEF(37, "Nt* Token Privilege Manipulation",              "T1134.001", 3, 8),
    PDEF(38, "Repeated LSASS Memory Read",                    "T1003.001", 4, 10),
    PDEF(39, "Nt* Remote Memory Dump",                        "T1003.001", 4, 8),

    // --- Ransomware (T1486) ---
    PDEF(40, "File Encryption Loop (CryptEncrypt)",           "T1486",     4, 12),
    PDEF(41, "File Encryption Loop (CryptGenRandom)",         "T1486",     4, 12),
    PDEF(42, "Ransomware Key Gen + Encrypt",                  "T1486",     4, 16),
    PDEF(43, "Crypto Key Generation + Export",                "T1486",     3, 8),
    PDEF(44, "Drive Enumeration for Encryption",              "T1486",     3, 8),
    PDEF(45, "Mass File Rename",                              "T1486",     3, 8),
    PDEF(46, "Mass File Deletion",                            "T1485",     4, 8),
    PDEF(47, "File Overwrite + Delete",                       "T1485",     3, 6),
    PDEF(48, "Recursive Directory Enumeration",               "T1083",     2, 10),
    PDEF(49, "Encrypt-then-Rename",                           "T1486",     4, 10),
    PDEF(50, "Key Import + Encrypt",                          "T1486",     4, 8),
    PDEF(51, "Full Drive Ransomware Chain",                   "T1486",     4, 20),
    PDEF(52, "File Enum + Read/Write/Rename",                 "T1486",     3, 12),
    PDEF(53, "Random Data File Write",                        "T1486",     3, 8),
    PDEF(54, "File Enum + Overwrite + Delete",                "T1485",     4, 10),
    PDEF(55, "Full Key Gen + Encrypt Chain",                  "T1486",     4, 18),
    PDEF(56, "File Read + Encrypt + Write",                   "T1486",     4, 10),
    PDEF(57, "Drive Enum + Encrypt",                          "T1486",     4, 14),

    // --- Downloader/Dropper (T1105) ---
    PDEF(58, "WinINet URL Download",                          "T1105",     3, 10),
    PDEF(59, "URLDownloadToFile + Execute",                   "T1105",     4, 8),
    PDEF(60, "WinHTTP Download",                              "T1071.001", 3, 10),
    PDEF(61, "Winsock Raw Download to File",                  "T1105",     3, 14),
    PDEF(62, "COM-based HTTP Download",                       "T1105",     3, 12),
    PDEF(63, "Dynamic API Resolve Download",                  "T1105",     3, 16),
    PDEF(64, "WinINet Full HTTP Download Chain",              "T1105",     3, 14),
    PDEF(65, "Download + Execute Chain",                      "T1105",     4, 10),
    PDEF(66, "WinHTTP Full Download to File",                 "T1105",     3, 18),
    PDEF(67, "DNS Resolve + Socket Download",                 "T1105",     3, 14),
    PDEF(68, "URLDownloadToFile + ShellExecute",              "T1105",     4, 8),
    PDEF(69, "WinINet Download + Execute",                    "T1105",     4, 14),
    PDEF(70, "Socket Download + Execute",                     "T1105",     4, 12),
    PDEF(71, "URLDownloadToFile + LoadLibrary",               "T1105",     4, 8),
    PDEF(72, "WinHTTP Download + Execute",                    "T1105",     4, 18),

    // --- Persistence (T1547, T1543, T1053) ---
    PDEF(73, "Registry Run Key Persistence",                  "T1547.001", 3, 8),
    PDEF(74, "Registry Create + Run Key",                     "T1547.001", 3, 8),
    PDEF(75, "Service Creation Persistence",                  "T1543.003", 3, 8),
    PDEF(76, "File Copy + Registry Persistence",              "T1547.001", 4, 12),
    PDEF(77, "Startup Folder File Drop",                      "T1547.009", 3, 8),
    PDEF(78, "Service Open + Start",                          "T1569.002", 2, 8),
    PDEF(79, "Nt Registry Persistence",                       "T1547.001", 3, 8),
    PDEF(80, "Registry Create + Set + Close",                 "T1547.001", 3, 8),
    PDEF(81, "Multiple Registry Value Writes",                "T1547.001", 3, 10),
    PDEF(82, "Service Create + Start",                        "T1543.003", 3, 8),
    PDEF(83, "Nt Registry Key Create + Set",                  "T1547.001", 3, 8),
    PDEF(84, "File Drop + Registry Persistence",              "T1547.001", 4, 12),
    PDEF(85, "File Copy + Service Persistence",               "T1543.003", 4, 14),
    PDEF(86, "Startup Folder Direct Write",                   "T1547.009", 3, 10),
    PDEF(87, "Temp File Drop + Execute",                      "T1105",     3, 10),
    PDEF(88, "Multi-Key Registry Persistence",                "T1547.001", 3, 14),
    PDEF(89, "Self-Copy + Registry Persistence",              "T1547.001", 4, 14),

    // --- Evasion (T1622, T1497) ---
    PDEF(90, "IsDebuggerPresent Check",                       "T1622",     2, 4),
    PDEF(91, "NtQueryInformationProcess Debug Check",         "T1622",     2, 4),
    PDEF(92, "GetTickCount Timing Check",                     "T1497.003", 2, 6),
    PDEF(93, "Process Enumeration (Sandbox Check)",           "T1057",     2, 8),
    PDEF(94, "ThreadHideFromDebugger",                        "T1622",     3, 4),
    PDEF(95, "AMSI/ETW Bypass Setup",                         "T1562.001", 4, 10),
    PDEF(96, "QPC Timing Check",                              "T1497.003", 2, 6),
    PDEF(97, "FindWindow Anti-Debug",                         "T1622",     2, 4),
    PDEF(98, "NtQuerySystemInformation Evasion",              "T1082",     2, 4),
    PDEF(99, "CheckRemoteDebuggerPresent",                    "T1622",     2, 4),
    PDEF(100, "Sleep + Timing Validation",                     "T1497.003", 2, 6),
    PDEF(101, "Environment Fingerprinting",                    "T1497.001", 2, 10),
    PDEF(102, "Disk Size Sandbox Check",                       "T1497.001", 2, 4),
    PDEF(103, "GetTickCount64 Timing Check",                   "T1497.003", 2, 6),
    PDEF(104, "OutputDebugString Debugger Detect",             "T1622",     2, 6),
    PDEF(105, "Repeated Debug Port Query",                     "T1622",     3, 6),
    PDEF(106, "AMSI Patch (VirtualProtect + Write)",           "T1562.001", 4, 10),
    PDEF(107, "Module Unhooking",                              "T1562.001", 4, 12),
    PDEF(108, "Multi-Method Debug Detection",                  "T1622",     3, 8),
    PDEF(109, "Combined System Query Evasion",                 "T1497.001", 3, 8),

    // --- Keylogger (T1056.001) ---
    PDEF(110, "Hook-based Keylogger (GetMessage)",             "T1056.001", 4, 8),
    PDEF(111, "Hook-based Keylogger (PeekMessage)",            "T1056.001", 4, 8),
    PDEF(112, "Polling Keylogger (GetAsyncKeyState)",          "T1056.001", 3, 4),
    PDEF(113, "Targeted Window Keylogger",                     "T1056.001", 4, 8),
    PDEF(114, "Window Title Monitor",                          "T1056.001", 2, 6),
    PDEF(115, "Keylogger with File Log",                       "T1056.001", 4, 10),
    PDEF(116, "Polling Keylogger + File Write",                "T1056.001", 4, 8),
    PDEF(117, "Full Hook Keylogger Chain",                     "T1056.001", 4, 12),

    // --- Lateral Movement (T1021) ---
    PDEF(118, "PsExec-style Lateral Movement",                 "T1021.002", 4, 16),
    PDEF(119, "WMI/COM Lateral Execution",                     "T1021.003", 3, 10),
    PDEF(120, "Remote Service Creation + Start",               "T1569.002", 3, 10),
    PDEF(121, "File Copy + Remote Execution",                  "T1021.002", 4, 12),
    PDEF(122, "Remote Service Start",                          "T1569.002", 3, 8),
    PDEF(123, "Network Share + Host Enumeration",              "T1018",     2, 6),
    PDEF(124, "Admin Share File Copy",                         "T1021.002", 3, 8),
    PDEF(125, "Remote Service Install via Share",              "T1021.002", 4, 12),
    PDEF(126, "Share Enum + File Copy",                        "T1021.002", 3, 12),
    PDEF(127, "COM Multi-Object Lateral",                      "T1021.003", 3, 12),

    // --- C2 Communication (T1071) ---
    PDEF(128, "HTTP C2 (WinINet)",                             "T1071.001", 3, 10),
    PDEF(129, "HTTP C2 Beacon Loop",                           "T1071.001", 4, 12),
    PDEF(130, "DNS C2 Beacon",                                 "T1071.004", 3, 8),
    PDEF(131, "Raw Socket C2 with Sleep",                      "T1071.001", 3, 10),
    PDEF(132, "Named Pipe C2",                                 "T1071",     3, 8),
    PDEF(133, "WinHTTP C2 Full Chain",                         "T1071.001", 3, 12),
    PDEF(134, "HTTP Request Chain",                            "T1071.001", 2, 10),
    PDEF(135, "Reverse Shell via Socket",                      "T1059",     4, 10),
    PDEF(136, "Socket Keep-Alive C2",                          "T1071.001", 3, 10),
    PDEF(137, "DNS Resolve + Socket C2",                       "T1071.001", 3, 10),
    PDEF(138, "HTTP C2 Polling Loop",                          "T1071.001", 4, 14),
    PDEF(139, "HTTP Upload C2",                                "T1071.001", 3, 10),
    PDEF(140, "Raw Socket C2",                                 "T1071.001", 2, 8),
    PDEF(141, "Socket C2 with Sleep",                          "T1071.001", 3, 12),
    PDEF(142, "Listening Backdoor",                            "T1071.001", 3, 10),
    PDEF(143, "Full Bidirectional Socket C2",                  "T1071.001", 4, 16),

    // --- Discovery (T1057, T1082, T1083, T1016, T1018, T1087) ---
    PDEF(144, "Process Enumeration",                           "T1057",     2, 8),
    PDEF(145, "Module Enumeration",                            "T1057",     2, 8),
    PDEF(146, "Thread Enumeration",                            "T1057",     2, 8),
    PDEF(147, "Network Share Discovery",                       "T1135",     2, 4),
    PDEF(148, "Remote System Discovery",                       "T1018",     2, 4),
    PDEF(149, "Network Adapter Discovery",                     "T1016",     2, 4),
    PDEF(150, "Routing Table Discovery",                       "T1016",     2, 4),
    PDEF(151, "Account Discovery",                             "T1087",     2, 6),
    PDEF(152, "Local Group Membership Enum",                   "T1087.001", 2, 4),
    PDEF(153, "Full System Fingerprint",                       "T1082",     3, 12),
    PDEF(154, "Volume + Drive Enumeration",                    "T1082",     2, 8),
    PDEF(155, "Registry System Info Probing",                  "T1012",     2, 10),
    PDEF(156, "Extended Process Enumeration",                  "T1057",     2, 6),
    PDEF(157, "User + Computer Name Discovery",               "T1033",     2, 6),
    PDEF(158, "System Version Fingerprint",                    "T1082",     2, 8),
    PDEF(159, "Deep Process Enumeration",                      "T1057",     2, 10),
    PDEF(160, "Full Network Config Discovery",                 "T1016",     2, 8),
    PDEF(161, "Share Enum + Connection",                       "T1135",     2, 8),

    // --- Data Exfiltration (T1041, T1048) ---
    PDEF(162, "File Read + Socket Exfil",                      "T1041",     3, 8),
    PDEF(163, "Encrypted Socket Exfil",                        "T1048",     4, 6),
    PDEF(164, "HTTP File Exfiltration",                        "T1041",     3, 10),
    PDEF(165, "WinHTTP File Exfiltration",                     "T1041",     3, 10),
    PDEF(166, "HTTP Upload Exfil",                             "T1041",     3, 10),
    PDEF(167, "FTP-style Exfiltration",                        "T1048",     3, 10),
    PDEF(168, "Encrypted File + Socket Exfil",                 "T1048",     4, 10),
    PDEF(169, "Clipboard Data Exfil",                          "T1115",     3, 8),
    PDEF(170, "Encrypted HTTP Exfil",                          "T1048",     4, 10),
    PDEF(171, "File Enum + Socket Exfil",                      "T1041",     3, 12),
    PDEF(172, "Encrypted HTTP Upload Exfil",                   "T1048",     4, 12),
    PDEF(173, "Encrypted WinHTTP Exfil",                       "T1048",     4, 12),
    PDEF(174, "Full Enum + Encrypted Exfil",                   "T1048",     4, 14),

    // --- DLL Injection (T1055.001) ---
    PDEF(175, "SetWindowsHookEx DLL Injection",                "T1055.001", 3, 10),
    PDEF(176, "LdrLoadDll Injection",                          "T1055.001", 3, 4),
    PDEF(177, "Remote Thread DLL Injection",                   "T1055.001", 4, 12),
    PDEF(178, "AppInit_DLLs Persistence",                      "T1546.010", 3, 8),
    PDEF(179, "DLL Injection via NtCreateThreadEx",            "T1055.001", 4, 12),
    PDEF(180, "Dynamic Resolve + Remote Thread DLL Load",      "T1055.001", 4, 14),
    PDEF(181, "Nt* DLL Injection Chain",                       "T1055.001", 4, 12),
    PDEF(182, "Section Map + Remote Thread DLL",               "T1055.001", 4, 10),

    // --- Privilege Escalation (T1134, T1543) ---
    PDEF(183, "SeDebugPrivilege Escalation",                   "T1134.001", 3, 8),
    PDEF(184, "Token Duplication + Process Spawn",             "T1134.002", 4, 10),
    PDEF(185, "Named Pipe Impersonation",                      "T1134.001", 3, 8),
    PDEF(186, "Service-based Privilege Escalation",            "T1543.003", 3, 10),
    PDEF(187, "COM UAC Bypass",                                "T1548.002", 3, 10),
    PDEF(188, "Nt* Token Privilege Adjust",                    "T1134.001", 3, 6),
    PDEF(189, "Token Info + Duplication",                      "T1134.001", 3, 8),
    PDEF(190, "Privilege Adjust + Process Open",               "T1134.001", 3, 10),
    PDEF(191, "Nt* Token Query + Duplicate",                   "T1134.001", 3, 8),
    PDEF(192, "Privilege Escalation + Execute",                "T1134.002", 4, 10),

    // --- Additional Defense Evasion (T1140, T1027) ---
    PDEF(193, "Self-Modifying Code Execution",                 "T1027",     3, 8),
    PDEF(194, "API Hook Bypass (AMSI/ETW Patch)",              "T1562.001", 4, 10),
    PDEF(195, "Nt* Shellcode Alloc + Execute",                 "T1055.002", 4, 8),
    PDEF(196, "Dynamic API Resolution Setup",                  "T1027",     2, 8),
    PDEF(197, "Combined Anti-Debug Checks",                    "T1622",     3, 8),
    PDEF(198, "Multi-Module Sandbox Detection",                "T1497.001", 3, 6),
    PDEF(199, "Window-based Analysis Tool Detection",          "T1497.001", 3, 6),
    PDEF(200, "Process Enum + Target Open",                    "T1057",     3, 12),
    PDEF(201, "Sleep Timing Validation",                       "T1497.003", 3, 8),
    PDEF(202, "Packed Code Decompress + Execute",              "T1027.002", 3, 10),
    PDEF(203, "Decompression + Memory Execute",                "T1027.002", 3, 8),
    PDEF(204, "Nt* Decompress + Execute Chain",                "T1027.002", 4, 10),

    // --- Shellcode Execution ---
    PDEF(205, "VirtualAlloc + Write + Thread",                 "T1055.002", 3, 8),
    PDEF(206, "VirtualAlloc + Protect + Remote Thread",        "T1055.002", 4, 10),
    PDEF(207, "Nt* Shellcode Alloc + Protect + Thread",        "T1055.002", 4, 8),
    PDEF(208, "Heap Shellcode Execution",                      "T1055.002", 3, 10),
    PDEF(209, "Alloc + Dynamic Resolve + Thread",              "T1055.002", 3, 12),
    PDEF(210, "Nt* Alloc + Write + Protect Chain",             "T1055.002", 3, 8),
    PDEF(211, "File Copy + Shellcode Execute",                 "T1055.002", 3, 10),
    PDEF(212, "GlobalAlloc Shellcode Execution",               "T1055.002", 3, 8),

    // --- Wiper / Destruction ---
    PDEF(213, "File Overwrite Loop",                           "T1485",     4, 12),
    PDEF(214, "Drive Wiper (Delete)",                          "T1485",     4, 14),
    PDEF(215, "File Content Overwrite",                        "T1485",     3, 8),
    PDEF(216, "Attribute Clear + Delete",                      "T1485",     4, 10),
    PDEF(217, "Full Drive File Destruction",                   "T1485",     4, 16),
    PDEF(218, "Rename + Delete (Secure Delete)",               "T1485",     3, 8),

    // --- Reflective Loading ---
    PDEF(219, "Reflective PE Load from File",                  "T1620",     4, 10),
    PDEF(220, "Nt* Reflective PE Load",                        "T1620",     4, 10),
    PDEF(221, "HTTP Reflective Load",                          "T1620",     4, 12),
    PDEF(222, "Socket Reflective Load",                        "T1620",     4, 10),
    PDEF(223, "File-backed Reflective Load",                   "T1620",     4, 12),
    PDEF(224, "WinHTTP Reflective Load",                       "T1620",     4, 12),

    // --- Service Manipulation Extended ---
    PDEF(225, "Full Service Creation Chain",                   "T1543.003", 3, 10),
    PDEF(226, "Service Deletion",                              "T1489",     3, 8),
    PDEF(227, "Service Open + Start + Close",                  "T1569.002", 2, 10),
    PDEF(228, "Self-Install as Service",                       "T1543.003", 4, 12),
    PDEF(229, "File Copy + Registry Persist (Full)",           "T1547.001", 4, 12),
    PDEF(230, "Temp Copy + Registry Persist",                  "T1547.001", 4, 12),
};

#undef PDEF

static constexpr uint32_t kPatternCount =
    static_cast<uint32_t>(sizeof(kPatterns) / sizeof(kPatterns[0]));

// ============================================================================
// Pattern Index — maps first APIId to list of pattern indices
// ============================================================================

static constexpr uint32_t kMaxFirstAPIBuckets = API_ID_COUNT;

struct PatternIndex {
    std::array<std::vector<uint16_t>, kMaxFirstAPIBuckets> byFirstAPI;

    PatternIndex() {
        for (uint32_t i = 0; i < kPatternCount; ++i) {
            APIId first = kPatterns[i].sequence[0];
            if (first < kMaxFirstAPIBuckets)
                byFirstAPI[first].push_back(static_cast<uint16_t>(i));
        }
    }
};

[[nodiscard]] static const PatternIndex& GetPatternIndex() noexcept {
    static const PatternIndex sIndex;
    return sIndex;
}

// ============================================================================
// Markov Chain Baseline — Benign transition probabilities
// ============================================================================
// Transitions that legitimate software commonly makes receive high baseline
// probabilities. Transitions absent from this table receive a default low
// probability, making them more likely to trigger anomaly detection.

struct BaselineTransition {
    APIId   from;
    APIId   to;
    float   probability;
};

static const BaselineTransition kBaseline[] = {
    // Module loading (extremely common in any program)
    { API_GetModuleHandle,   API_GetProcAddress,        0.70f },
    { API_LoadLibrary,       API_GetProcAddress,        0.80f },
    { API_LoadLibrary,       API_FreeLibrary,           0.15f },
    { API_LdrLoadDll,        API_LdrGetProcedureAddress,0.75f },
    { API_GetProcAddress,    API_GetProcAddress,        0.30f },
    { API_GetModuleHandle,   API_GetModuleHandle,       0.15f },
    { API_LoadLibrary,       API_LoadLibrary,           0.10f },
    { API_GetModuleHandle,   API_LoadLibrary,           0.08f },

    // File I/O (standard patterns)
    { API_CreateFile,        API_ReadFile,              0.40f },
    { API_CreateFile,        API_WriteFile,             0.30f },
    { API_CreateFile,        API_GetFileSize,           0.15f },
    { API_CreateFile,        API_SetFilePointer,        0.08f },
    { API_ReadFile,          API_CloseHandle,           0.30f },
    { API_WriteFile,         API_CloseHandle,           0.35f },
    { API_ReadFile,          API_ReadFile,              0.25f },
    { API_WriteFile,         API_WriteFile,             0.20f },
    { API_ReadFile,          API_WriteFile,             0.10f },
    { API_SetFilePointer,    API_ReadFile,              0.40f },
    { API_SetFilePointer,    API_WriteFile,             0.30f },
    { API_GetFileSize,       API_ReadFile,              0.25f },
    { API_GetFileSize,       API_SetFilePointer,        0.15f },
    { API_FindFirstFile,     API_FindNextFile,          0.65f },
    { API_FindNextFile,      API_FindNextFile,          0.50f },
    { API_FindNextFile,      API_FindClose,             0.25f },
    { API_FindNextFile,      API_CreateFile,            0.10f },
    { API_FindClose,         API_CloseHandle,           0.05f },
    { API_GetTempPath,       API_CreateFile,            0.30f },
    { API_GetFileAttributes, API_CreateFile,            0.15f },
    { API_CopyFile,          API_CloseHandle,           0.05f },
    { API_DeleteFile,        API_DeleteFile,            0.08f },

    // Memory management (benign)
    { API_VirtualAlloc,      API_VirtualFree,           0.10f },
    { API_VirtualAlloc,      API_VirtualProtect,        0.08f },
    { API_HeapAlloc,         API_HeapFree,              0.15f },
    { API_HeapAlloc,         API_HeapAlloc,             0.20f },
    { API_HeapFree,          API_HeapAlloc,             0.15f },
    { API_RtlAllocateHeap,   API_RtlFreeHeap,          0.15f },
    { API_RtlAllocateHeap,   API_RtlAllocateHeap,      0.20f },
    { API_GlobalAlloc,       API_GlobalAlloc,           0.10f },
    { API_GetProcessHeap,    API_HeapAlloc,             0.30f },
    { API_GetProcessHeap,    API_RtlAllocateHeap,       0.25f },
    { API_VirtualAlloc,      API_WriteFile,             0.03f },

    // Registry (benign)
    { API_RegOpenKeyEx,      API_RegQueryValueEx,       0.55f },
    { API_RegOpenKeyEx,      API_RegSetValueEx,         0.15f },
    { API_RegOpenKeyEx,      API_RegEnumKeyEx,          0.10f },
    { API_RegOpenKeyEx,      API_RegEnumValue,          0.08f },
    { API_RegQueryValueEx,   API_RegCloseKey,           0.30f },
    { API_RegQueryValueEx,   API_RegQueryValueEx,       0.25f },
    { API_RegSetValueEx,     API_RegCloseKey,           0.35f },
    { API_RegSetValueEx,     API_RegSetValueEx,         0.10f },
    { API_RegEnumKeyEx,      API_RegEnumKeyEx,          0.40f },
    { API_RegEnumKeyEx,      API_RegCloseKey,           0.15f },
    { API_RegEnumValue,      API_RegEnumValue,          0.35f },
    { API_RegCloseKey,       API_RegOpenKeyEx,          0.15f },
    { API_NtOpenKey,         API_NtQueryValueKey,       0.50f },
    { API_NtQueryValueKey,   API_NtClose,              0.30f },
    { API_RegCreateKeyEx,    API_RegSetValueEx,         0.40f },

    // Network: Winsock (benign chain)
    { API_WSAStartup,        API_socket,                0.60f },
    { API_WSAStartup,        API_getaddrinfo,           0.15f },
    { API_socket,            API_connect,               0.40f },
    { API_socket,            API_bind,                  0.25f },
    { API_getaddrinfo,       API_socket,                0.35f },
    { API_gethostbyname,     API_socket,                0.30f },
    { API_connect,           API_send,                  0.35f },
    { API_connect,           API_select,                0.10f },
    { API_send,              API_recv,                  0.40f },
    { API_recv,              API_send,                  0.20f },
    { API_recv,              API_recv,                  0.15f },
    { API_recv,              API_closesocket,           0.10f },
    { API_send,              API_closesocket,           0.08f },
    { API_bind,              API_listen,                0.45f },
    { API_listen,            API_accept,                0.50f },
    { API_accept,            API_recv,                  0.35f },
    { API_closesocket,       API_WSACleanup,            0.15f },

    // Network: WinINet (benign chain)
    { API_InternetOpen,      API_InternetConnect,       0.60f },
    { API_InternetOpen,      API_InternetOpenUrl,       0.25f },
    { API_InternetConnect,   API_HttpOpenRequest,       0.55f },
    { API_HttpOpenRequest,   API_HttpSendRequest,       0.65f },
    { API_HttpSendRequest,   API_InternetReadFile,      0.55f },
    { API_InternetReadFile,  API_InternetReadFile,      0.30f },
    { API_InternetReadFile,  API_InternetCloseHandle,   0.25f },
    { API_InternetOpenUrl,   API_InternetReadFile,      0.55f },
    { API_InternetCloseHandle, API_InternetCloseHandle, 0.15f },

    // Network: WinHTTP (benign chain)
    { API_WinHttpOpen,       API_WinHttpConnect,        0.60f },
    { API_WinHttpConnect,    API_WinHttpOpenRequest,    0.60f },
    { API_WinHttpOpenRequest,API_WinHttpSendRequest,    0.65f },
    { API_WinHttpSendRequest,API_WinHttpReceiveResponse,0.65f },
    { API_WinHttpReceiveResponse, API_WinHttpReadData,  0.60f },
    { API_WinHttpReadData,   API_WinHttpReadData,       0.25f },
    { API_WinHttpReadData,   API_WinHttpCloseHandle,    0.20f },

    // Process/Thread (benign)
    { API_CreateThread,      API_WaitForSingleObject,   0.20f },
    { API_CreateProcess,     API_WaitForSingleObject,   0.15f },
    { API_CreateProcess,     API_CloseHandle,           0.10f },
    { API_CreateProcess,     API_ResumeThread,          0.08f },
    { API_ExitProcess,       API_Unknown,               0.90f },
    { API_GetCurrentProcessId, API_GetCurrentProcessId, 0.01f },

    // Synchronization (benign)
    { API_CreateMutex,       API_WaitForSingleObject,   0.25f },
    { API_CreateEvent,       API_SetEvent,              0.20f },
    { API_CreateEvent,       API_WaitForSingleObject,   0.20f },
    { API_WaitForSingleObject, API_CloseHandle,         0.10f },
    { API_SetEvent,          API_WaitForSingleObject,   0.12f },

    // COM (benign)
    { API_CoInitializeEx,    API_CoCreateInstance,      0.45f },
    { API_CoCreateInstance,  API_CoUninitialize,        0.10f },
    { API_CoCreateInstance,  API_CoCreateInstance,      0.05f },

    // Time (benign)
    { API_Sleep,             API_GetTickCount,          0.08f },
    { API_GetTickCount,      API_Sleep,                 0.05f },
    { API_QueryPerformanceCounter, API_QueryPerformanceFrequency, 0.10f },
    { API_GetSystemTime,     API_GetLocalTime,          0.05f },

    // Environment (benign)
    { API_GetComputerName,   API_GetUserName,           0.10f },
    { API_GetSystemDirectory, API_GetWindowsDirectory,  0.08f },
    { API_GetVersionEx,      API_GetSystemInfo,         0.10f },

    // Crypto (benign chain for legitimate encryption)
    { API_CryptAcquireContext, API_CryptCreateHash,     0.20f },
    { API_CryptCreateHash,   API_CryptHashData,        0.50f },
    { API_CryptHashData,     API_CryptHashData,        0.20f },
    { API_CryptAcquireContext, API_CryptGenRandom,      0.10f },
    { API_CryptAcquireContext, API_CryptReleaseContext, 0.05f },
    { API_CryptEncrypt,      API_CryptReleaseContext,   0.05f },

    // Shell (benign)
    { API_SHGetFolderPath,   API_CreateFile,            0.15f },
    { API_GetTempPath,       API_GetTempPath,           0.02f },

    // Error handling (benign)
    { API_GetLastError,      API_SetLastError,          0.03f },
    { API_SetLastError,      API_GetLastError,          0.02f },
};

static constexpr uint32_t kBaselineCount =
    static_cast<uint32_t>(sizeof(kBaseline) / sizeof(kBaseline[0]));

// Build a lookup map for baseline transitions
struct TransitionKey {
    APIId from;
    APIId to;
    bool operator==(const TransitionKey& o) const noexcept {
        return from == o.from && to == o.to;
    }
};

struct TransitionKeyHash {
    size_t operator()(const TransitionKey& k) const noexcept {
        return (static_cast<size_t>(k.from) << 16) | static_cast<size_t>(k.to);
    }
};

[[nodiscard]] static const std::unordered_map<TransitionKey, float, TransitionKeyHash>&
GetBaselineMap() noexcept {
    static const auto sMap = []() {
        std::unordered_map<TransitionKey, float, TransitionKeyHash> m;
        m.reserve(kBaselineCount * 2);
        for (uint32_t i = 0; i < kBaselineCount; ++i)
            m[{ kBaseline[i].from, kBaseline[i].to }] = kBaseline[i].probability;
        return m;
    }();
    return sMap;
}

// Default probability for transitions not in the baseline
static constexpr double kDefaultTransitionProb = 0.0005;

} // anonymous namespace

// ============================================================================
// Impl — Private implementation of APISequenceAnalyzer
// ============================================================================

struct APISequenceAnalyzer::Impl {
    bool enabled = false;

    // --- Capacity caps ---
    static constexpr uint32_t kMaxMatches       = 4096;
    static constexpr uint32_t kMaxAnomalies     = 4096;
    static constexpr uint32_t kMaxActiveMatches = 16384;
    static constexpr uint32_t kMaxSequenceLen   = 131072;
    static constexpr uint32_t kMaxThreads       = 64;
    static constexpr uint32_t kMaxFreqEntries   = 1024;

    // --- Anomaly threshold ---
    double anomalyThreshold = 0.001;

    // --- API call sequence (ring buffer) ---
    std::vector<APIId> sequence;
    uint32_t totalCalls = 0;

    // --- Per-thread tracking ---
    struct ThreadState {
        APIId    lastAPIId      = kInvalidAPIId;
        uint32_t callCount      = 0;
        uint32_t lastInstNum    = 0;
        uint32_t burstCount     = 0;
        uint32_t burstStart     = 0;
        // Per-thread sliding window (most recent API IDs)
        std::array<APIId, 64> window{};
        uint32_t windowPos      = 0;
        uint32_t windowFill     = 0;
        // Tight-loop detection: last N unique APIs
        APIId    lastUniqueAPIs[4] = {};
        uint8_t  lastUniqueCount   = 0;
        uint32_t repeatCount       = 0;
    };
    std::unordered_map<uint16_t, ThreadState> threads;

    // --- Cross-thread correlation ---
    // Tracks injection-relevant APIs across threads to detect coordinated attacks.
    // Key: thread ID, Value: set of suspicious API categories observed.
    struct CrossThreadEvent {
        uint16_t threadId;
        APIId    apiId;
        uint32_t callIndex;
        uint32_t instrNum;
    };
    static constexpr uint32_t kMaxCrossThreadEvents = 256;
    std::vector<CrossThreadEvent> crossThreadEvents;
    // Injection-relevant API IDs for cross-thread detection
    static bool IsInjectionRelated(APIId id) noexcept {
        switch (id) {
            case API_OpenProcess: case API_VirtualAllocEx: case API_WriteProcessMemory:
            case API_CreateRemoteThread: case API_CreateRemoteThreadEx:
            case API_QueueUserAPC: case API_SetThreadContext: case API_ResumeThread:
            case API_NtAllocateVirtualMemory: case API_NtWriteVirtualMemory:
            case API_NtCreateThreadEx: case API_NtMapViewOfSection:
            case API_RtlCreateUserThread: case API_SuspendThread:
            case API_ReadProcessMemory: case API_NtReadVirtualMemory:
            case API_VirtualProtectEx:
                return true;
            default:
                return false;
        }
    }

    // --- Call graph (caller return address → callee API) ---
    struct CallGraphEdge {
        GuestAddress callerAddr;
        APIId        calleeAPI;
        uint32_t     count;
    };
    static constexpr uint32_t kMaxCallGraphEdges = 4096;
    std::unordered_map<uint64_t, uint32_t> callGraphIndex; // hash(callerAddr,apiId) → edge index
    std::vector<CallGraphEdge> callGraph;

    // --- Pattern matching state ---
    struct ActiveMatch {
        uint16_t patternIdx;        // Index into kPatterns[]
        uint8_t  matchPos;          // Next element to match in pattern
        uint32_t startCallIndex;    // Call index where match started
        uint32_t lastMatchIndex;    // Call index of last matched element
        uint16_t threadId;
        uint8_t  gapAccum;          // Accumulated gap since last match
    };
    std::vector<ActiveMatch> activeMatches;

    // --- Markov chain state ---
    std::unordered_map<TransitionKey, uint32_t, TransitionKeyHash> transitionCounts;
    std::unordered_map<APIId, uint32_t> fromCounts;
    APIId globalLastAPI = kInvalidAPIId;

    // --- Results ---
    std::vector<SequenceMatch> matches;
    std::vector<TransitionAnomaly> anomalies;
    uint8_t maxSeverity = 0;

    // --- API frequency ---
    std::unordered_map<APIId, uint32_t> frequency;

    // --- Deduplication: avoid reporting the same pattern at the same start ---
    std::unordered_set<uint64_t> reportedSet;

    // --- Sliding window sizes ---
    static constexpr uint32_t kWindowSizes[] = { 4, 8, 16, 32, 64 };
    static constexpr uint32_t kNumWindows = 5;

    // --- Temporal analysis ---
    static constexpr uint32_t kBurstThreshold    = 50;
    static constexpr uint32_t kBurstWindowInstr  = 200;
    static constexpr uint32_t kTightLoopCount    = 20;
    static constexpr uint32_t kTightLoopInstr    = 300;

    // ========================================================================
    // Initialization
    // ========================================================================

    explicit Impl(const EmulationConfig& config) noexcept
        : enabled(config.enableAPISequenceAnalysis)
    {
        if (!enabled) return;
        sequence.reserve(std::min<uint32_t>(
            static_cast<uint32_t>(config.maxAPIcalls), kMaxSequenceLen));
        activeMatches.reserve(1024);
        matches.reserve(256);
        anomalies.reserve(256);
        threads.reserve(config.maxThreads);
        transitionCounts.reserve(4096);
        fromCounts.reserve(512);
        frequency.reserve(512);
        reportedSet.reserve(512);
        crossThreadEvents.reserve(kMaxCrossThreadEvents);
        callGraph.reserve(512);
        callGraphIndex.reserve(512);
    }

    // ========================================================================
    // Core: Process an incoming API call
    // ========================================================================

    void ProcessCall(const APICallDetail& call, uint32_t callIndex) noexcept {
        if (!enabled) return;

        APIId apiId = ResolveAPIId(call.funcName);

        // Record in sequence buffer (capped)
        if (sequence.size() < kMaxSequenceLen)
            sequence.push_back(apiId);

        ++totalCalls;

        // Update frequency
        if (apiId != API_Unknown && frequency.size() < kMaxFreqEntries)
            ++frequency[apiId];

        // Per-thread state
        auto& ts = threads[call.threadId];
        ts.lastAPIId = apiId;
        ++ts.callCount;

        // Update per-thread sliding window
        if (apiId != API_Unknown) {
            ts.window[ts.windowPos % 64] = apiId;
            ++ts.windowPos;
            if (ts.windowFill < 64) ++ts.windowFill;
        }

        // Tight-loop detection within thread
        DetectTightLoop(ts, apiId, call.threadId, callIndex);

        // Temporal burst detection
        DetectBurst(ts, call.instructionNum, call.threadId, callIndex);

        // Markov chain transition analysis
        if (globalLastAPI != kInvalidAPIId && apiId != API_Unknown)
            AnalyzeTransition(globalLastAPI, apiId, callIndex);

        if (apiId != API_Unknown)
            globalLastAPI = apiId;

        ts.lastInstNum = call.instructionNum;

        // Cross-thread correlation for injection patterns
        if (apiId != API_Unknown && IsInjectionRelated(apiId))
            AnalyzeCrossThread(apiId, call.threadId, callIndex, call.instructionNum);

        // Call graph construction
        if (apiId != API_Unknown && call.returnAddress != 0)
            UpdateCallGraph(call.returnAddress, apiId);

        // Sliding window pattern check (every 8 calls to avoid per-call overhead)
        if (apiId != API_Unknown && (totalCalls & 7) == 0)
            SlidingWindowCheck(call.threadId, callIndex);

        // Pattern matching (streaming NFA)
        if (apiId != API_Unknown)
            AdvancePatternMatching(apiId, callIndex, call.threadId);
    }

    // ========================================================================
    // Pattern Matching Engine
    // ========================================================================

    void AdvancePatternMatching(APIId apiId, uint32_t callIndex, uint16_t threadId) noexcept {
        // 1. Start new matches for any pattern whose first element is this API
        const auto& idx = GetPatternIndex();
        if (apiId < kMaxFirstAPIBuckets) {
            const auto& candidates = idx.byFirstAPI[apiId];
            for (uint16_t patIdx : candidates) {
                if (activeMatches.size() >= kMaxActiveMatches) break;
                const auto& pat = kPatterns[patIdx];
                if (pat.length == 1) {
                    // Single-element pattern — immediate match
                    RecordMatch(patIdx, callIndex, callIndex, threadId);
                } else {
                    activeMatches.push_back({
                        patIdx,
                        1,              // next element to match
                        callIndex,
                        callIndex,
                        threadId,
                        0
                    });
                }
            }
        }

        // 2. Advance existing active matches
        uint32_t writeIdx = 0;
        for (uint32_t i = 0; i < activeMatches.size(); ++i) {
            auto& am = activeMatches[i];
            const auto& pat = kPatterns[am.patternIdx];

            if (pat.sequence[am.matchPos] == apiId) {
                // Element matched
                am.lastMatchIndex = callIndex;
                am.gapAccum = 0;
                ++am.matchPos;

                if (am.matchPos >= pat.length) {
                    // Full pattern matched
                    RecordMatch(am.patternIdx, am.startCallIndex, callIndex, am.threadId);
                    continue; // Consume this match
                }
            } else {
                // Gap
                ++am.gapAccum;
                if (am.gapAccum > pat.maxGap) {
                    continue; // Exceeded gap tolerance — discard
                }
            }

            // Retain this active match
            if (writeIdx != i)
                activeMatches[writeIdx] = am;
            ++writeIdx;
        }
        activeMatches.resize(writeIdx);
    }

    void RecordMatch(uint16_t patIdx, uint32_t startIdx, uint32_t endIdx,
                     uint16_t threadId) noexcept {
        if (matches.size() >= kMaxMatches) return;

        // Dedup: same pattern starting at same call index
        uint64_t dedupKey = (static_cast<uint64_t>(kPatterns[patIdx].id) << 32) |
                            static_cast<uint64_t>(startIdx);
        if (!reportedSet.insert(dedupKey).second) return;

        const auto& pat = kPatterns[patIdx];

        // Confidence: longer patterns and smaller gaps → higher confidence
        float confidence = 0.5f + 0.5f * (static_cast<float>(pat.length) / 8.0f);
        if (confidence > 1.0f) confidence = 1.0f;

        // Boost confidence for longer matches relative to window
        uint32_t span = (endIdx > startIdx) ? (endIdx - startIdx + 1) : 1;
        float density = static_cast<float>(pat.length) / static_cast<float>(span);
        confidence = confidence * 0.6f + density * 0.4f;
        if (confidence > 1.0f) confidence = 1.0f;

        matches.push_back({
            pat.id,
            pat.name,
            pat.mitreId,
            confidence,
            pat.severity,
            startIdx,
            endIdx,
            threadId
        });

        if (pat.severity > maxSeverity)
            maxSeverity = pat.severity;
    }

    // ========================================================================
    // Markov Chain Transition Analysis
    // ========================================================================

    void AnalyzeTransition(APIId from, APIId to, uint32_t callIndex) noexcept {
        TransitionKey key{ from, to };
        ++transitionCounts[key];
        ++fromCounts[from];

        // Look up baseline probability
        const auto& baseline = GetBaselineMap();
        auto baseIt = baseline.find(key);
        double prob = (baseIt != baseline.end())
                      ? static_cast<double>(baseIt->second)
                      : kDefaultTransitionProb;

        // Once we have enough observations, use empirical probability
        auto fromIt = fromCounts.find(from);
        if (fromIt != fromCounts.end() && fromIt->second >= 10) {
            auto tcIt = transitionCounts.find(key);
            double empirical = static_cast<double>(tcIt->second) /
                               static_cast<double>(fromIt->second);
            // Blend: weight empirical more as sample size grows
            double alpha = std::min(1.0, static_cast<double>(fromIt->second) / 100.0);
            prob = alpha * empirical + (1.0 - alpha) * prob;
        }

        if (prob < anomalyThreshold && anomalies.size() < kMaxAnomalies) {
            anomalies.push_back({ from, to, prob, anomalyThreshold, callIndex });
        }
    }

    // ========================================================================
    // Tight-Loop Detection
    // ========================================================================
    // Detects the same API (or very short cycle) repeated many times,
    // which is characteristic of keyloggers, polling, and brute-force attacks.

    void DetectTightLoop(ThreadState& ts, APIId apiId, uint16_t threadId,
                         uint32_t callIndex) noexcept {
        if (apiId == API_Unknown) return;

        // Check if current API matches the most recent unique API
        if (ts.lastUniqueCount > 0 && ts.lastUniqueAPIs[0] == apiId) {
            ++ts.repeatCount;
            if (ts.repeatCount >= kTightLoopCount) {
                // Tight loop detected
                if (anomalies.size() < kMaxAnomalies) {
                    anomalies.push_back({
                        apiId, apiId,
                        0.00005,    // Extremely low probability for tight loops
                        anomalyThreshold,
                        callIndex
                    });
                }
                ts.repeatCount = 0;
            }
        } else {
            ts.repeatCount = 1;
            // Shift unique API history
            for (int i = 3; i > 0; --i)
                ts.lastUniqueAPIs[i] = ts.lastUniqueAPIs[i - 1];
            ts.lastUniqueAPIs[0] = apiId;
            if (ts.lastUniqueCount < 4) ++ts.lastUniqueCount;
        }
    }

    // ========================================================================
    // Cross-Thread Correlation Analysis
    // ========================================================================
    // Detects coordinated multi-thread API usage patterns that indicate
    // process injection: e.g., thread A allocates memory while thread B
    // writes to it and thread C creates a remote thread.

    void AnalyzeCrossThread(APIId apiId, uint16_t threadId,
                            uint32_t callIndex, uint32_t instrNum) noexcept {
        // Record injection-related event
        if (crossThreadEvents.size() < kMaxCrossThreadEvents) {
            crossThreadEvents.push_back({ threadId, apiId, callIndex, instrNum });
        } else {
            // Evict oldest half when full
            auto mid = crossThreadEvents.begin() +
                       static_cast<ptrdiff_t>(crossThreadEvents.size() / 2);
            crossThreadEvents.erase(crossThreadEvents.begin(), mid);
            crossThreadEvents.push_back({ threadId, apiId, callIndex, instrNum });
        }

        // Analyze: look for injection-related APIs from different threads
        // within a recent window (last 32 events)
        if (crossThreadEvents.size() < 3) return;

        uint32_t windowStart = 0;
        if (crossThreadEvents.size() > 32)
            windowStart = static_cast<uint32_t>(crossThreadEvents.size()) - 32;

        // Count distinct threads performing injection-related APIs
        std::unordered_set<uint16_t> injectionThreads;
        bool hasAlloc = false, hasWrite = false, hasExec = false;

        for (uint32_t i = windowStart; i < crossThreadEvents.size(); ++i) {
            const auto& evt = crossThreadEvents[i];
            injectionThreads.insert(evt.threadId);

            switch (evt.apiId) {
                case API_VirtualAllocEx: case API_NtAllocateVirtualMemory:
                    hasAlloc = true; break;
                case API_WriteProcessMemory: case API_NtWriteVirtualMemory:
                    hasWrite = true; break;
                case API_CreateRemoteThread: case API_CreateRemoteThreadEx:
                case API_NtCreateThreadEx: case API_QueueUserAPC:
                case API_RtlCreateUserThread:
                    hasExec = true; break;
                default: break;
            }
        }

        // If multiple threads are coordinating injection-like activity, flag it
        if (injectionThreads.size() >= 2 && hasAlloc && hasWrite && hasExec) {
            if (anomalies.size() < kMaxAnomalies) {
                anomalies.push_back({
                    API_Unknown,    // Cross-thread, no single source
                    apiId,
                    0.00001,        // Extremely suspicious
                    anomalyThreshold,
                    callIndex
                });
            }
        }
    }

    // ========================================================================
    // Call Graph Construction
    // ========================================================================
    // Builds a caller→callee graph from return addresses. This reveals
    // the structure of the malware's execution flow.

    void UpdateCallGraph(GuestAddress callerAddr, APIId calleeAPI) noexcept {
        if (callGraph.size() >= kMaxCallGraphEdges) return;

        uint64_t edgeKey = (callerAddr << 16) ^ static_cast<uint64_t>(calleeAPI);
        auto it = callGraphIndex.find(edgeKey);
        if (it != callGraphIndex.end()) {
            if (it->second < callGraph.size())
                ++callGraph[it->second].count;
        } else {
            uint32_t idx = static_cast<uint32_t>(callGraph.size());
            callGraph.push_back({ callerAddr, calleeAPI, 1 });
            callGraphIndex[edgeKey] = idx;
        }
    }

    // ========================================================================
    // Sliding Window Pattern Check
    // ========================================================================
    // Periodically checks the per-thread sliding windows against patterns.
    // This catches patterns that the streaming NFA might miss due to ordering
    // across interleaved threads, and also detects density-based anomalies.

    void SlidingWindowCheck(uint16_t threadId, uint32_t callIndex) noexcept {
        auto threadIt = threads.find(threadId);
        if (threadIt == threads.end()) return;
        const auto& ts = threadIt->second;
        if (ts.windowFill < 4) return;

        // Check each window size
        for (uint32_t w = 0; w < kNumWindows; ++w) {
            uint32_t winSize = kWindowSizes[w];
            if (ts.windowFill < winSize) continue;

            // Extract the current window content
            uint32_t start = (ts.windowPos >= winSize)
                             ? (ts.windowPos - winSize) : 0;

            // Count unique APIs in this window — very low diversity is suspicious
            std::unordered_set<APIId> unique;
            for (uint32_t i = 0; i < winSize && i < ts.windowFill; ++i) {
                uint32_t idx = (start + i) % 64;
                if (ts.window[idx] != API_Unknown)
                    unique.insert(ts.window[idx]);
            }

            // If a window of 16+ calls has ≤ 2 unique APIs, that's anomalous
            // (likely a tight polling/brute-force loop)
            if (winSize >= 16 && unique.size() <= 2 && unique.size() > 0) {
                if (anomalies.size() < kMaxAnomalies) {
                    APIId firstApi = *unique.begin();
                    anomalies.push_back({
                        firstApi, firstApi,
                        0.0002,
                        anomalyThreshold,
                        callIndex
                    });
                }
            }

            // Check for crypto + file I/O density (ransomware indicator)
            uint32_t cryptoCount = 0, fileCount = 0;
            for (uint32_t i = 0; i < winSize && i < ts.windowFill; ++i) {
                uint32_t idx = (start + i) % 64;
                APIId api = ts.window[idx];
                switch (api) {
                    case API_CryptEncrypt: case API_CryptDecrypt:
                    case API_CryptGenRandom: case API_CryptGenKey:
                        ++cryptoCount; break;
                    case API_ReadFile: case API_WriteFile:
                    case API_CreateFile: case API_FindFirstFile:
                    case API_FindNextFile:
                        ++fileCount; break;
                    default: break;
                }
            }

            // If ≥ 25% of a 16+ window is crypto + file ops, flag ransomware
            if (winSize >= 16 && (cryptoCount + fileCount) >= (winSize / 4)
                && cryptoCount >= 2 && fileCount >= 2) {
                if (anomalies.size() < kMaxAnomalies) {
                    anomalies.push_back({
                        API_CryptEncrypt, API_WriteFile,
                        0.0003,
                        anomalyThreshold,
                        callIndex
                    });
                }
            }

            // Check for network + process combo (C2 + lateral movement)
            uint32_t netCount = 0, procCount = 0;
            for (uint32_t i = 0; i < winSize && i < ts.windowFill; ++i) {
                uint32_t idx = (start + i) % 64;
                APIId api = ts.window[idx];
                switch (api) {
                    case API_send: case API_recv: case API_connect:
                    case API_InternetReadFile: case API_HttpSendRequest:
                    case API_WinHttpSendRequest: case API_WinHttpReadData:
                        ++netCount; break;
                    case API_CreateProcess: case API_ShellExecute:
                    case API_CreateRemoteThread: case API_WriteProcessMemory:
                        ++procCount; break;
                    default: break;
                }
            }

            if (winSize >= 8 && netCount >= 2 && procCount >= 1) {
                if (anomalies.size() < kMaxAnomalies) {
                    anomalies.push_back({
                        API_recv, API_CreateProcess,
                        0.0004,
                        anomalyThreshold,
                        callIndex
                    });
                }
            }
        }
    }

    // ========================================================================
    // Temporal Burst Detection
    // ========================================================================

    void DetectBurst(ThreadState& ts, uint32_t instrNum,
                     uint16_t threadId, uint32_t callIndex) noexcept {
        if (ts.lastInstNum == 0) {
            ts.burstStart = instrNum;
            ts.burstCount = 1;
            return;
        }

        uint32_t delta = (instrNum >= ts.lastInstNum)
                         ? (instrNum - ts.lastInstNum) : 0;

        if (delta < kBurstWindowInstr) {
            ++ts.burstCount;
            if (ts.burstCount >= kBurstThreshold) {
                // Burst detected — record as anomaly
                if (anomalies.size() < kMaxAnomalies) {
                    anomalies.push_back({
                        ts.lastAPIId,
                        ts.lastAPIId,
                        0.0001,     // Very low probability for burst
                        anomalyThreshold,
                        callIndex
                    });
                }
                ts.burstCount = 0;
                ts.burstStart = instrNum;
            }
        } else {
            ts.burstCount = 1;
            ts.burstStart = instrNum;
        }
    }

    // ========================================================================
    // Reset
    // ========================================================================

    void ResetState() noexcept {
        sequence.clear();
        totalCalls = 0;
        threads.clear();
        activeMatches.clear();
        transitionCounts.clear();
        fromCounts.clear();
        globalLastAPI = kInvalidAPIId;
        matches.clear();
        anomalies.clear();
        maxSeverity = 0;
        frequency.clear();
        reportedSet.clear();
        crossThreadEvents.clear();
        callGraph.clear();
        callGraphIndex.clear();
    }
};

// ============================================================================
// APISequenceAnalyzer — Public Interface
// ============================================================================

APISequenceAnalyzer::APISequenceAnalyzer(const EmulationConfig& config) noexcept
    : m_impl(std::make_unique<Impl>(config))
{
}

APISequenceAnalyzer::~APISequenceAnalyzer() noexcept = default;

APISequenceAnalyzer::APISequenceAnalyzer(APISequenceAnalyzer&&) noexcept = default;
APISequenceAnalyzer& APISequenceAnalyzer::operator=(APISequenceAnalyzer&&) noexcept = default;

void APISequenceAnalyzer::OnAPICall(const APICallDetail& call, uint32_t callIndex) noexcept {
    if (m_impl) m_impl->ProcessCall(call, callIndex);
}

const std::vector<SequenceMatch>& APISequenceAnalyzer::GetMatches() const noexcept {
    static const std::vector<SequenceMatch> kEmpty;
    return m_impl ? m_impl->matches : kEmpty;
}

const std::vector<TransitionAnomaly>& APISequenceAnalyzer::GetAnomalies() const noexcept {
    static const std::vector<TransitionAnomaly> kEmpty;
    return m_impl ? m_impl->anomalies : kEmpty;
}

uint8_t APISequenceAnalyzer::GetMaxSeverity() const noexcept {
    return m_impl ? m_impl->maxSeverity : 0;
}

uint32_t APISequenceAnalyzer::GetMatchCount() const noexcept {
    return m_impl ? static_cast<uint32_t>(m_impl->matches.size()) : 0;
}

std::vector<std::pair<APIId, uint32_t>> APISequenceAnalyzer::GetAPIFrequency() const noexcept {
    std::vector<std::pair<APIId, uint32_t>> result;
    if (!m_impl) return result;

    result.reserve(m_impl->frequency.size());
    for (const auto& [id, count] : m_impl->frequency)
        result.emplace_back(id, count);

    std::sort(result.begin(), result.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    return result;
}

std::vector<TransitionAnomaly> APISequenceAnalyzer::GetTopAnomalies(uint32_t n) const noexcept {
    if (!m_impl || m_impl->anomalies.empty()) return {};

    std::vector<TransitionAnomaly> sorted = m_impl->anomalies;
    std::sort(sorted.begin(), sorted.end(),
              [](const TransitionAnomaly& a, const TransitionAnomaly& b) {
                  return a.probability < b.probability;
              });

    if (sorted.size() > n)
        sorted.resize(n);
    return sorted;
}

void APISequenceAnalyzer::Reset() noexcept {
    if (m_impl) m_impl->ResetState();
}

} // namespace Phantom
