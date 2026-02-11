/**
 * ============================================================================
 * ShadowStrike NGAV - PATH EXCLUSION ENGINE
 * ============================================================================
 *
 * @file PathExclusion.c
 * @brief Enterprise-grade path normalization and pattern matching.
 *
 * Implements:
 * - Path normalization (uppercase, trailing separator stripping)
 * - Case-insensitive prefix matching with path boundary validation
 * - Wildcard matching (* and ? with proper backtracking)
 * - Extension extraction (zero-copy)
 * - Recursive directory matching with component boundary checks
 *
 * All matching operates on WCHAR arrays and UNICODE_STRING without
 * requiring heap allocation in the hot path (normalization is done
 * at exclusion insertion time, not at match time).
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ExclusionManager.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, ShadowStrikeNormalizePath)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PATH_SEPARATOR L'\\'

/**
 * @brief Maximum iteration count for wildcard matching.
 *
 * Bounds total work against adversarial patterns (e.g., *?*?*?*?*).
 * Set to StringLen * PatternLen cap. For a 520-char path and 520-char
 * pattern, worst case is 270400 iterations — well under 1ms on modern
 * hardware. This prevents unbounded CPU consumption without affecting
 * legitimate patterns.
 */
#define MAX_WILDCARD_ITERATIONS (SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH * \
                                 SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH)

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/**
 * @brief Compare two wide characters case-insensitively.
 *
 * Both inputs MUST already be upcased (normalization done at insertion
 * time). This function uses RtlUpcaseUnicodeChar only as a safety net
 * for callers that pass un-normalized paths. In production hot paths,
 * both sides are pre-upcased so the fast A == B path is taken.
 *
 * @irql <= APC_LEVEL (RtlUpcaseUnicodeChar accesses paged NLS tables)
 */
_IRQL_requires_max_(APC_LEVEL)
static FORCEINLINE BOOLEAN
PathpCharsEqualCaseInsensitive(
    _In_ WCHAR A,
    _In_ WCHAR B
    )
{
    if (A == B) {
        return TRUE;
    }
    return RtlUpcaseUnicodeChar(A) == RtlUpcaseUnicodeChar(B);
}

/**
 * @brief Internal wildcard matching engine with bounded iteration.
 *
 * Supports:
 * - '?' matches exactly one character (never a path separator
 *   in non-recursive mode)
 * - '*' matches zero or more characters (never crosses path separators
 *   in non-recursive mode)
 *
 * Uses the iterative star-backtracking algorithm. Total iterations are
 * bounded by MAX_WILDCARD_ITERATIONS to prevent CPU exhaustion from
 * adversarial patterns (e.g., *?*?*?*?*).
 *
 * @param String         Input string to match.
 * @param StringLen      Length of String in characters.
 * @param Pattern        Pattern to match against.
 * @param PatternLen     Length of Pattern in characters.
 * @param CaseSensitive  TRUE for exact case matching.
 * @param Recursive      TRUE to let '*' cross path separators.
 * @return TRUE if match succeeds.
 *
 * @irql <= APC_LEVEL (case-insensitive mode uses RtlUpcaseUnicodeChar)
 */
_IRQL_requires_max_(APC_LEVEL)
static
BOOLEAN
PathpWildcardMatch(
    _In_reads_(StringLen) PCWCH String,
    _In_ USHORT StringLen,
    _In_reads_(PatternLen) PCWCH Pattern,
    _In_ USHORT PatternLen,
    _In_ BOOLEAN CaseSensitive,
    _In_ BOOLEAN Recursive
    )
{
    USHORT si = 0;
    USHORT pi = 0;
    USHORT starSi = (USHORT)-1;
    USHORT starPi = (USHORT)-1;
    ULONG iterations = 0;

    //
    // Guard: reject strings at the USHORT boundary to prevent overflow
    // when starSi is incremented during backtracking.
    //
    if (StringLen == 0 || PatternLen == 0) {
        return FALSE;
    }

    while (si < StringLen) {
        //
        // Bound total work to prevent adversarial pattern abuse
        //
        if (++iterations > MAX_WILDCARD_ITERATIONS) {
            return FALSE;
        }

        if (pi < PatternLen && Pattern[pi] == L'?') {
            //
            // '?' matches any single character except path separator
            // (unless Recursive)
            //
            if (!Recursive && String[si] == PATH_SEPARATOR) {
                //
                // '?' does not cross path boundaries in non-recursive mode.
                // Check if we have a star bookmark to backtrack to.
                //
                if (starPi != (USHORT)-1) {
                    pi = starPi + 1;
                    starSi++;
                    si = starSi;
                    continue;
                }
                return FALSE;
            }
            si++;
            pi++;
        }
        else if (pi < PatternLen && Pattern[pi] == L'*') {
            //
            // '*' — record bookmark for backtracking
            //
            starPi = pi;
            starSi = si;
            pi++;
        }
        else if (pi < PatternLen &&
                 (CaseSensitive ? (String[si] == Pattern[pi])
                                : PathpCharsEqualCaseInsensitive(String[si], Pattern[pi]))) {
            //
            // Literal character match
            //
            si++;
            pi++;
        }
        else if (starPi != (USHORT)-1) {
            //
            // Backtrack to last '*' and advance string position
            //
            pi = starPi + 1;
            starSi++;

            //
            // In non-recursive mode, '*' does not cross path separators.
            // When the star expansion hits a separator, stop expanding the
            // star (clear the bookmark) and position si at the separator
            // so the main loop tries to match it as a literal against
            // Pattern[pi]. This correctly handles patterns like
            // "dir\*\subdir" where '*' should match within a single
            // path component.
            //
            if (!Recursive && starSi < StringLen && String[starSi] == PATH_SEPARATOR) {
                si = starSi;
                starPi = (USHORT)-1;
                starSi = (USHORT)-1;
                continue;
            }

            si = starSi;
        }
        else {
            return FALSE;
        }
    }

    //
    // Consume any trailing '*' in pattern
    //
    while (pi < PatternLen && Pattern[pi] == L'*') {
        pi++;
    }

    return (pi == PatternLen);
}

// ============================================================================
// PUBLIC API
// ============================================================================

_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
ShadowStrikeNormalizePath(
    _In_ PCUNICODE_STRING InputPath,
    _Out_ PUNICODE_STRING NormalizedPath
    )
{
    PWCHAR buffer;
    USHORT inputChars;
    USHORT i;
    USHORT outIndex;
    ULONG allocLen;
    WCHAR ch;
    WCHAR prevCh;

    PAGED_CODE();

    RtlZeroMemory(NormalizedPath, sizeof(UNICODE_STRING));

    if (!ShadowStrikeValidateUnicodeString(InputPath)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InputPath->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    inputChars = InputPath->Length / sizeof(WCHAR);

    //
    // Reject paths exceeding maximum length. Silent truncation is a
    // security risk — a truncated exclusion pattern could match
    // unintended paths crafted by an attacker.
    //
    if (inputChars > SHADOWSTRIKE_MAX_EXCLUSION_PATH_LENGTH) {
        return STATUS_NAME_TOO_LONG;
    }

    //
    // Allocate buffer — ULONG to prevent overflow on future constant changes.
    // Use PagedPool: this function runs at PASSIVE_LEVEL during exclusion
    // insertion, not on the hot match path. NonPagedPool is a scarce
    // kernel resource and must not be wasted for configuration operations.
    //
    allocLen = ((ULONG)inputChars + 1) * sizeof(WCHAR);

    buffer = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        allocLen,
        SHADOWSTRIKE_EXCLUSION_POOL_TAG
    );

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Copy, upcase, normalize forward slashes to backslashes,
    // and collapse consecutive separators in a single pass.
    //
    outIndex = 0;
    prevCh = L'\0';
    for (i = 0; i < inputChars; i++) {
        ch = InputPath->Buffer[i];

        //
        // Normalize forward slashes to canonical backslash
        //
        if (ch == L'/') {
            ch = PATH_SEPARATOR;
        }

        //
        // Collapse consecutive path separators (keep only the first)
        //
        if (ch == PATH_SEPARATOR && prevCh == PATH_SEPARATOR) {
            continue;
        }

        buffer[outIndex] = RtlUpcaseUnicodeChar(ch);
        prevCh = ch;
        outIndex++;
    }

    //
    // Strip trailing path separators (but keep the root "\" itself)
    //
    while (outIndex > 1 && buffer[outIndex - 1] == PATH_SEPARATOR) {
        outIndex--;
    }

    buffer[outIndex] = L'\0';

    NormalizedPath->Buffer = buffer;
    NormalizedPath->Length = outIndex * sizeof(WCHAR);
    NormalizedPath->MaximumLength = (USHORT)allocLen;

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
BOOLEAN
ShadowStrikeMatchPathPattern(
    _In_ PCUNICODE_STRING FilePath,
    _In_ PCUNICODE_STRING Pattern,
    _In_ UINT8 Flags
    )
{
    BOOLEAN caseSensitive;
    BOOLEAN recursive;
    BOOLEAN wildcard;
    USHORT patternChars;
    USHORT fileChars;

    if (!ShadowStrikeValidateUnicodeString(FilePath) ||
        !ShadowStrikeValidateUnicodeString(Pattern)) {
        return FALSE;
    }

    if (FilePath->Length == 0 || Pattern->Length == 0) {
        return FALSE;
    }

    caseSensitive = (Flags & ShadowStrikeExclusionFlagCaseSensitive) != 0;
    recursive = (Flags & ShadowStrikeExclusionFlagRecursive) != 0;
    wildcard = (Flags & ShadowStrikeExclusionFlagWildcard) != 0;

    patternChars = Pattern->Length / sizeof(WCHAR);
    fileChars = FilePath->Length / sizeof(WCHAR);

    //
    // Wildcard matching path
    //
    if (wildcard) {
        return PathpWildcardMatch(
            FilePath->Buffer,
            fileChars,
            Pattern->Buffer,
            patternChars,
            caseSensitive,
            recursive
        );
    }

    //
    // Non-wildcard: prefix matching with path boundary validation
    //

    //
    // Pattern cannot be longer than the file path for a prefix match
    //
    if (patternChars > fileChars) {
        return FALSE;
    }

    //
    // Compare prefix
    //
    if (caseSensitive) {
        if (RtlCompareMemory(FilePath->Buffer, Pattern->Buffer,
                             patternChars * sizeof(WCHAR))
            != patternChars * sizeof(WCHAR)) {
            return FALSE;
        }
    } else {
        UNICODE_STRING filePrefix;
        filePrefix.Buffer = FilePath->Buffer;
        filePrefix.Length = patternChars * sizeof(WCHAR);
        filePrefix.MaximumLength = filePrefix.Length;

        if (RtlCompareUnicodeString(&filePrefix, Pattern, TRUE) != 0) {
            return FALSE;
        }
    }

    //
    // Exact match
    //
    if (patternChars == fileChars) {
        return TRUE;
    }

    //
    // Prefix matched — check if we should match children
    //
    if (recursive) {
        //
        // Pattern ended with separator → subtree match
        //
        if (Pattern->Buffer[patternChars - 1] == PATH_SEPARATOR) {
            return TRUE;
        }

        //
        // Next character in file path is separator → proper subtree boundary
        //
        if (FilePath->Buffer[patternChars] == PATH_SEPARATOR) {
            return TRUE;
        }

        //
        // Prefix matched but not at a path component boundary
        // (e.g., pattern "C:\WIN" should not match "C:\WINDOWS\...")
        //
        return FALSE;
    }

    //
    // Non-recursive, non-exact: prefix matched but lengths differ
    //
    return FALSE;
}

_IRQL_requires_max_(APC_LEVEL)
VOID
ShadowStrikeExtractExtension(
    _In_ PCUNICODE_STRING FilePath,
    _Out_ PUNICODE_STRING Extension
    )
{
    USHORT charCount;
    USHORT i;
    USHORT lastDot = (USHORT)-1;
    USHORT lastSep = (USHORT)-1;

    RtlZeroMemory(Extension, sizeof(UNICODE_STRING));

    if (!ShadowStrikeValidateUnicodeString(FilePath) || FilePath->Length == 0) {
        return;
    }

    charCount = FilePath->Length / sizeof(WCHAR);

    //
    // Scan backwards for last dot and last separator
    // We need to find the dot after the last separator to handle
    // paths like "C:\some.dir\file" (no extension)
    //
    for (i = charCount; i > 0; i--) {
        WCHAR ch = FilePath->Buffer[i - 1];

        if (ch == L'.' && lastDot == (USHORT)-1) {
            lastDot = (USHORT)(i - 1);
        }
        else if (ch == PATH_SEPARATOR || ch == L'/') {
            lastSep = (USHORT)(i - 1);
            break;
        }
    }

    //
    // No dot found, or dot is before the last separator (part of directory name)
    //
    if (lastDot == (USHORT)-1) {
        return;
    }

    if (lastSep != (USHORT)-1 && lastDot < lastSep) {
        return;
    }

    //
    // Dot at the very end means no extension (e.g., "file.")
    //
    if (lastDot + 1 >= charCount) {
        return;
    }

    //
    // Zero-copy view: point into the original buffer past the dot
    //
    Extension->Buffer = &FilePath->Buffer[lastDot + 1];
    Extension->Length = (USHORT)((charCount - lastDot - 1) * sizeof(WCHAR));
    Extension->MaximumLength = Extension->Length;
}
