# Security Review Analysis

## Issue 1: CRITICAL - Wrong constant used for redirect policy
Line 193: `DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;`

The variable is named `redirectPolicy` but should hold a **policy value**, not the **option ID**.
According to Windows SDK headers:
- `WINHTTP_OPTION_REDIRECT_POLICY` = 88 (the option ID to pass to WinHttpSetOption)
- `WINHTTP_OPTION_REDIRECT_POLICY_NEVER` = 0 (the value for that option)
- `WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS` = 2

The code assigns `WINHTTP_OPTION_REDIRECT_POLICY_NEVER` (value 0) to `redirectPolicy`, which is **CORRECT**.

Wait, let me re-read the diff more carefully...

Looking at line 193 in the diff:
```cpp
DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
::WinHttpSetOption(requestGuard.handle, WINHTTP_OPTION_REDIRECT_POLICY,
    &redirectPolicy, sizeof(redirectPolicy));
```

This is using:
- Option ID: `WINHTTP_OPTION_REDIRECT_POLICY` (88)
- Value: `WINHTTP_OPTION_REDIRECT_POLICY_NEVER` (0)

This is CORRECT! The constant name is confusing but it's the right value (0 = never redirect).

## Issue 2: Header parsing - potential off-by-one or buffer overrun
Lines 308-330: The raw header parsing logic

The code does:
1. Query size with `rawSize` (in bytes)
2. Allocate string: `std::wstring rawHeaders(rawSize / sizeof(wchar_t), L'\0');`
3. Query again into buffer

**Potential issue**: After the second WinHttpQueryHeaders call, `rawSize` is updated to the actual bytes written. But the code then iterates using `rawHeaders.size()`, which was calculated from the original size request. If the second call writes LESS data than requested, the loop could read uninitialized wchar_t values at the end.

## Issue 3: Path traversal bypass
Lines 414-420, 490-496: Path traversal check using `find(L"..")`

This check can be bypassed on Windows using:
- Unicode normalization: `..` vs `․․` (U+2024)
- Case variations (though Windows is case-insensitive)
- URL encoding in filesystem paths
- DOS 8.3 names
- Multiple separators: `...` followed by delete
- UNC paths: `\\?\C:\path\..\..\sensitive`

However, for an EDR agent receiving paths from trusted code (not user input), this may be acceptable defense-in-depth.

## Issue 4: Symlink check race condition
Lines 498-504: Symlink check followed by file operations

Classic TOCTOU:
1. Check if path is symlink (line 500)
2. Check if file exists (line 508)
3. Open file (line 527)

An attacker with filesystem access could replace the file with a symlink between steps 2 and 3.
