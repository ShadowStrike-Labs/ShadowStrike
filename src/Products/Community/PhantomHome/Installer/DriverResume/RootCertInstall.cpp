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

/**
 * @file RootCertInstall.cpp
 * @brief Install the ShadowStrike code-signing root certificate into the
 *        LocalMachine Root and TrustedPublisher stores.
 *
 * Security:
 *  - File size capped at 64 KB to prevent memory exhaustion on hostile input.
 *  - CertCreateCertificateContext is tried first for raw DER; CryptQueryObject
 *    is the PEM/DER autodetection fallback.
 *  - All CryptoAPI handles released through RAII guards (no leak paths).
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <wincrypt.h>

#include <cstdint>
#include <string>
#include <vector>

#include "RootCertInstall.hpp"
#include "DriverInstaller.hpp"  // HandleGuard

#pragma comment(lib, "crypt32.lib")

namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

namespace ShadowStrike::Installer {

namespace {

constexpr DWORD kMaxCerBytes = 64u * 1024u;

// RAII guard for HCERTSTORE.
struct CertStoreGuard {
    HCERTSTORE h = nullptr;
    explicit CertStoreGuard(HCERTSTORE handle = nullptr) noexcept : h(handle) {}
    ~CertStoreGuard() noexcept {
        if (h) {
            // CERT_CLOSE_STORE_FORCE_FLAG would force-free contexts; we rely
            // on caller-side CertContextGuard to release individual contexts
            // first, so use the default flag for a clean refcount close.
            CertCloseStore(h, 0);
            h = nullptr;
        }
    }
    CertStoreGuard(const CertStoreGuard&)            = delete;
    CertStoreGuard& operator=(const CertStoreGuard&) = delete;
    [[nodiscard]] bool       valid() const noexcept { return h != nullptr; }
    [[nodiscard]] HCERTSTORE get()   const noexcept { return h; }
};

// RAII guard for PCCERT_CONTEXT.
struct CertContextGuard {
    PCCERT_CONTEXT c = nullptr;
    explicit CertContextGuard(PCCERT_CONTEXT ctx = nullptr) noexcept : c(ctx) {}
    ~CertContextGuard() noexcept {
        if (c) {
            CertFreeCertificateContext(c);
            c = nullptr;
        }
    }
    CertContextGuard(const CertContextGuard&)            = delete;
    CertContextGuard& operator=(const CertContextGuard&) = delete;
    CertContextGuard(CertContextGuard&& o) noexcept : c(o.c) { o.c = nullptr; }
    CertContextGuard& operator=(CertContextGuard&& o) noexcept {
        if (this != &o) {
            if (c) CertFreeCertificateContext(c);
            c = o.c;
            o.c = nullptr;
        }
        return *this;
    }
    [[nodiscard]] bool           valid() const noexcept { return c != nullptr; }
    [[nodiscard]] PCCERT_CONTEXT get()   const noexcept { return c; }
    PCCERT_CONTEXT release() noexcept { PCCERT_CONTEXT r = c; c = nullptr; return r; }
};

// Read whole file into a bounded buffer.
[[nodiscard]] DWORD ReadCerFile(const std::wstring& path, std::vector<BYTE>& out) noexcept
{
    HandleGuard hFile(
        CreateFileW(path.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr));
    if (!hFile.valid()) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"InstallShadowStrikeRootCert: CreateFileW('%ls') failed (0x%08X).",
                  path.c_str(), err);
        return err ? err : ERROR_OPEN_FAILED;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(hFile.get(), &size)) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"InstallShadowStrikeRootCert: GetFileSizeEx('%ls') failed (0x%08X).",
                  path.c_str(), err);
        return err ? err : ERROR_FUNCTION_FAILED;
    }

    if (size.QuadPart <= 0) {
        LOG_ERROR(L"InstallShadowStrikeRootCert: '%ls' is empty.", path.c_str());
        return ERROR_INVALID_DATA;
    }

    if (size.QuadPart > static_cast<LONGLONG>(kMaxCerBytes)) {
        LOG_ERROR(L"InstallShadowStrikeRootCert: '%ls' exceeds %lu-byte cap "
                  L"(actual=%lld).",
                  path.c_str(), kMaxCerBytes,
                  static_cast<long long>(size.QuadPart));
        return ERROR_FILE_TOO_LARGE;
    }

    try {
        out.resize(static_cast<size_t>(size.QuadPart));
    } catch (const std::bad_alloc&) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    DWORD totalRead = 0;
    while (totalRead < out.size()) {
        DWORD chunk = 0;
        const DWORD remaining = static_cast<DWORD>(out.size() - totalRead);
        if (!ReadFile(hFile.get(), out.data() + totalRead, remaining, &chunk, nullptr)) {
            const DWORD err = GetLastError();
            LOG_ERROR(L"InstallShadowStrikeRootCert: ReadFile('%ls') failed "
                      L"(0x%08X) at offset %lu.", path.c_str(), err, totalRead);
            return err ? err : ERROR_READ_FAULT;
        }
        if (chunk == 0) {
            // EOF earlier than expected.
            LOG_ERROR(L"InstallShadowStrikeRootCert: short read on '%ls' "
                      L"(%lu of %zu).",
                      path.c_str(), totalRead, out.size());
            return ERROR_HANDLE_EOF;
        }
        totalRead += chunk;
    }
    return ERROR_SUCCESS;
}

// Try raw DER parse; on failure, fall back to CryptQueryObject (PEM/DER auto).
[[nodiscard]] DWORD ParseCert(const std::vector<BYTE>&  data,
                              const std::wstring&        path,
                              CertContextGuard&          out) noexcept
{
    PCCERT_CONTEXT direct = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        data.data(),
        static_cast<DWORD>(data.size()));
    if (direct != nullptr) {
        out = CertContextGuard{ direct };
        return ERROR_SUCCESS;
    }
    const DWORD directErr = GetLastError();
    LOG_INFO(L"InstallShadowStrikeRootCert: CertCreateCertificateContext "
             L"failed (0x%08X); falling back to CryptQueryObject for "
             L"PEM/DER autodetection.", directErr);

    DWORD encodingType  = 0;
    DWORD contentType   = 0;
    DWORD formatType    = 0;
    PCCERT_CONTEXT ctx  = nullptr;
    BOOL ok = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        path.c_str(),
        CERT_QUERY_CONTENT_FLAG_CERT,
        CERT_QUERY_FORMAT_FLAG_ALL,
        0,
        &encodingType,
        &contentType,
        &formatType,
        nullptr,
        nullptr,
        reinterpret_cast<const void**>(&ctx));

    if (!ok || ctx == nullptr) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"InstallShadowStrikeRootCert: CryptQueryObject failed for "
                  L"'%ls' (0x%08X).", path.c_str(), err);
        return err ? err : ERROR_INVALID_DATA;
    }
    out = CertContextGuard{ ctx };
    return ERROR_SUCCESS;
}

[[nodiscard]] DWORD AddToStore(PCCERT_CONTEXT ctx, const wchar_t* storeName) noexcept
{
    CertStoreGuard store(
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            storeName));
    if (!store.valid()) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"InstallShadowStrikeRootCert: CertOpenStore('%ls') failed "
                  L"(0x%08X).", storeName, err);
        return err ? err : ERROR_FUNCTION_FAILED;
    }

    if (!CertAddCertificateContextToStore(
            store.get(), ctx, CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
    {
        const DWORD err = GetLastError();
        LOG_ERROR(L"InstallShadowStrikeRootCert: CertAddCertificateContextToStore "
                  L"('%ls') failed (0x%08X).", storeName, err);
        return err ? err : ERROR_FUNCTION_FAILED;
    }

    LOG_INFO(L"InstallShadowStrikeRootCert: cert installed into '%ls' store.",
             storeName);
    return ERROR_SUCCESS;
}

} // anonymous namespace

DWORD InstallShadowStrikeRootCert(const std::wstring& cerFilePath) noexcept
{
    if (cerFilePath.empty()) {
        LOG_ERROR(L"InstallShadowStrikeRootCert: empty path.");
        return ERROR_INVALID_PARAMETER;
    }

    LOG_INFO(L"InstallShadowStrikeRootCert: installing '%ls'.", cerFilePath.c_str());

    std::vector<BYTE> blob;
    DWORD err = ReadCerFile(cerFilePath, blob);
    if (err != ERROR_SUCCESS) {
        return err;
    }

    CertContextGuard ctx;
    err = ParseCert(blob, cerFilePath, ctx);
    if (err != ERROR_SUCCESS) {
        return err;
    }

    err = AddToStore(ctx.get(), L"Root");
    if (err != ERROR_SUCCESS) {
        return err;
    }

    err = AddToStore(ctx.get(), L"TrustedPublisher");
    if (err != ERROR_SUCCESS) {
        return err;
    }

    LOG_INFO(L"InstallShadowStrikeRootCert: success (Root + TrustedPublisher).");
    return ERROR_SUCCESS;
}

} // namespace ShadowStrike::Installer
