/*
 * VersionInfo.rc.inc - the VERSIONINFO block, written once.
 *
 * A .rc file that wants a version resource defines its own identity and then
 * includes this file:
 *
 *     #define SS_RC_FILE_DESCRIPTION  "ShadowStrike Phantom Service"
 *     #define SS_RC_INTERNAL_NAME     "ShadowStrikePhantomService"
 *     #define SS_RC_ORIGINAL_FILENAME "ShadowStrikePhantomService.exe"
 *     #include "VersionInfo.rc.inc"
 *
 * SS_RC_FILETYPE may be set before including to override the default of VFT_APP;
 * the kernel driver sets VFT_DRV. Getting that wrong is not cosmetic - tools that
 * enumerate drivers filter on FILETYPE, so a driver declaring itself an
 * application is a driver those tools do not list.
 *
 * The three identity macros are deliberately NOT given defaults. A binary that
 * forgets one fails to compile, which is the behaviour we want: the alternative is
 * five binaries all describing themselves as "ShadowStrike" and nobody noticing,
 * which is the same shape as the file lists that matched nothing.
 */

#include "VersionInfo.h"
#include <winresrc.h>

#ifndef SS_RC_FILE_DESCRIPTION
#error "SS_RC_FILE_DESCRIPTION must be defined before including VersionInfo.rc.inc"
#endif
#ifndef SS_RC_INTERNAL_NAME
#error "SS_RC_INTERNAL_NAME must be defined before including VersionInfo.rc.inc"
#endif
#ifndef SS_RC_ORIGINAL_FILENAME
#error "SS_RC_ORIGINAL_FILENAME must be defined before including VersionInfo.rc.inc"
#endif

#ifndef SS_RC_FILETYPE
#define SS_RC_FILETYPE VFT_APP
#endif

VS_VERSION_INFO VERSIONINFO
FILEVERSION     SS_VERSION_MAJOR,SS_VERSION_MINOR,SS_VERSION_PATCH,SS_VERSION_BUILD
PRODUCTVERSION  SS_VERSION_MAJOR,SS_VERSION_MINOR,SS_VERSION_PATCH,SS_VERSION_BUILD
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
#ifdef _DEBUG
FILEFLAGS       VS_FF_DEBUG
#else
FILEFLAGS       0x0L
#endif
FILEOS          VOS_NT_WINDOWS32
FILETYPE        SS_RC_FILETYPE
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        // 040904b0 = US English, Unicode. Must match the Translation value below;
        // a mismatch makes the whole string block invisible to readers that look
        // the language up first, which is most of them.
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      SS_COMPANY_NAME
            VALUE "FileDescription",  SS_RC_FILE_DESCRIPTION
            VALUE "FileVersion",      SS_VERSION_STRING
            VALUE "InternalName",     SS_RC_INTERNAL_NAME
            VALUE "LegalCopyright",   SS_LEGAL_COPYRIGHT
            VALUE "LegalTrademarks",  SS_LEGAL_TRADEMARKS
            VALUE "OriginalFilename", SS_RC_ORIGINAL_FILENAME
            VALUE "ProductName",      SS_PRODUCT_NAME
            VALUE "ProductVersion",   SS_VERSION_STRING
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
