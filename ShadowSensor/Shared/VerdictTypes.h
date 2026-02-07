#pragma once

typedef enum _SHADOWSTRIKE_SCAN_VERDICT {
    Verdict_Unknown = 0,
    Verdict_Clean,          // File is safe
    Verdict_Malicious,      // File is malicious
    Verdict_Suspicious,     // File is suspicious but not confirmed
    Verdict_Error,          // Scan failed
    Verdict_Timeout         // Scan timed out
} SHADOWSTRIKE_SCAN_VERDICT;
