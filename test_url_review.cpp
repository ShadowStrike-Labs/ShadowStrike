// Test program to verify overflow checks and edge cases
#include <cstdint>
#include <iostream>
#include <limits>

// Test PunycodeDecode overflow check for i += digit * w
void test_overflow_i_plus_digit_w() {
    std::cout << "Testing i += digit * w overflow check..." << std::endl;
    
    uint32_t i = UINT32_MAX - 100;
    uint32_t digit = 10;
    uint32_t w = 20;
    
    // The check is: if (digit > (UINT32_MAX - i) / w)
    // This should be: if (digit * w > UINT32_MAX - i)
    // Rearranged to avoid overflow in the check itself: if (digit > (UINT32_MAX - i) / w)
    
    bool overflow_detected = (digit > (UINT32_MAX - i) / w);
    bool actual_overflow_would_occur = (UINT32_MAX - i < digit * w);
    
    std::cout << "  i=" << i << ", digit=" << digit << ", w=" << w << std::endl;
    std::cout << "  Check result: " << overflow_detected << std::endl;
    std::cout << "  Actual overflow: " << actual_overflow_would_occur << std::endl;
    std::cout << "  (UINT32_MAX - i) / w = " << ((UINT32_MAX - i) / w) << std::endl;
    std::cout << "  Match: " << (overflow_detected == actual_overflow_would_occur) << std::endl;
    
    // Edge case: when w is 0 (should never happen in actual code, but let's check)
    w = 0;
    if (w > 0) {
        overflow_detected = (digit > (UINT32_MAX - i) / w);
        std::cout << "  w=0 case would cause division by zero!" << std::endl;
    }
}

// Test PunycodeDecode overflow check for w *= factor
void test_overflow_w_times_factor() {
    std::cout << "\nTesting w *= factor overflow check..." << std::endl;
    
    uint32_t w = UINT32_MAX / 2;
    uint32_t factor = 3;
    
    // The check is: if (w > UINT32_MAX / factor)
    bool overflow_detected = (w > UINT32_MAX / factor);
    bool actual_overflow = (w > UINT32_MAX / factor);
    
    std::cout << "  w=" << w << ", factor=" << factor << std::endl;
    std::cout << "  Check result: " << overflow_detected << std::endl;
    std::cout << "  UINT32_MAX / factor = " << (UINT32_MAX / factor) << std::endl;
    std::cout << "  Match: " << (overflow_detected == actual_overflow) << std::endl;
}

// Test PunycodeEncode overflow check for delta computation
void test_overflow_delta_computation() {
    std::cout << "\nTesting delta computation overflow check..." << std::endl;
    
    uint32_t m = 0x10FFFF;
    uint32_t n = 0x80;
    uint32_t delta = UINT32_MAX - 1000;
    size_t handledCount = 10;
    
    // The check is: if (m - n > (UINT32_MAX - delta) / (handledCount + 1))
    // This should detect: delta += (m - n) * (handledCount + 1) overflowing
    
    bool overflow_detected = ((m - n) > (UINT32_MAX - delta) / (handledCount + 1));
    
    std::cout << "  m=" << m << ", n=" << n << ", delta=" << delta << ", handledCount=" << handledCount << std::endl;
    std::cout << "  (m - n) = " << (m - n) << std::endl;
    std::cout << "  (UINT32_MAX - delta) / (handledCount + 1) = " << ((UINT32_MAX - delta) / (handledCount + 1)) << std::endl;
    std::cout << "  Check result: " << overflow_detected << std::endl;
}

// Test surrogate pair handling bounds
void test_surrogate_pairs() {
    std::cout << "\nTesting surrogate pair bounds..." << std::endl;
    
    // High surrogate range: 0xD800 - 0xDBFF
    // Low surrogate range: 0xDC00 - 0xDFFF
    
    uint32_t high = 0xD800;
    uint32_t low = 0xDC00;
    
    std::cout << "  High surrogate: 0x" << std::hex << high << std::endl;
    std::cout << "  Low surrogate: 0x" << std::hex << low << std::endl;
    
    // Check the condition in UrlDecode line 343
    bool is_high_surrogate = (high >= 0xD800 && high <= 0xDBFF);
    std::cout << "  Is high surrogate (0xD800): " << is_high_surrogate << std::endl;
    
    // Edge cases
    high = 0xDBFF;
    is_high_surrogate = (high >= 0xD800 && high <= 0xDBFF);
    std::cout << "  Is high surrogate (0xDBFF): " << is_high_surrogate << std::endl;
    
    high = 0xDC00; // This is actually a low surrogate
    is_high_surrogate = (high >= 0xD800 && high <= 0xDBFF);
    std::cout << "  Is high surrogate (0xDC00, should be false): " << is_high_surrogate << std::endl;
    
    // The next character check in line 343: && i + 1 < str.length()
    // What if the low surrogate check fails? The code doesn't validate the low surrogate!
    std::cout << "\n  WARNING: Code at line 343 checks high surrogate but doesn't validate" << std::endl;
    std::cout << "  that the next character is actually a LOW surrogate (0xDC00-0xDFFF)!" << std::endl;
}

// Test IsValidDomain with boundary characters
void test_domain_validation() {
    std::cout << "\nTesting domain validation..." << std::endl;
    
    // The condition on line 432: if (c > 127) continue;
    // This accepts ANY character > 127, including control characters
    
    wchar_t test_chars[] = {
        128,    // First non-ASCII
        0x80,   // Same as 128
        0x9F,   // C1 control character
        0x00A0, // Non-breaking space
        0x200B, // Zero-width space
        0xFFFE, // Invalid Unicode
        0xFFFF, // Invalid Unicode
        0xD800, // High surrogate (invalid in UTF-16 as standalone)
    };
    
    std::cout << "  Characters that would be accepted by 'if (c > 127) continue;':" << std::endl;
    for (wchar_t c : test_chars) {
        if (c > 127) {
            std::cout << "    0x" << std::hex << static_cast<int>(c) << std::dec;
            if (c >= 0xD800 && c <= 0xDFFF) {
                std::cout << " (SURROGATE - invalid standalone)";
            } else if (c == 0xFFFE || c == 0xFFFF) {
                std::cout << " (INVALID Unicode)";
            } else if ((c >= 0x80 && c <= 0x9F) || c == 0x00A0 || c == 0x200B) {
                std::cout << " (CONTROL/SPECIAL)";
            }
            std::cout << std::endl;
        }
    }
}

// Test fragment parsing edge cases
void test_fragment_parsing() {
    std::cout << "\nTesting fragment parsing from ExtraInfo..." << std::endl;
    
    // WinHttpCrackUrl puts query+fragment in lpszExtraInfo
    // Format can be:
    // "?query"
    // "?query#fragment"
    // "#fragment"
    // ""
    
    std::wstring test_cases[] = {
        L"?key=value#section",
        L"?key=value",
        L"#section",
        L"",
        L"?#",
        L"?key=value#",
        L"?#fragment"
    };
    
    std::cout << "  Testing various extraInfo formats:" << std::endl;
    for (const auto& extra : test_cases) {
        size_t hashPos = extra.find(L'#');
        std::wstring query, fragment;
        
        if (hashPos != std::wstring::npos) {
            query = extra.substr(0, hashPos);
            fragment = extra.substr(hashPos + 1);
        } else {
            query = extra;
        }
        
        std::wcout << L"    extraInfo=\"" << extra << L"\" -> query=\"" << query << L"\", fragment=\"" << fragment << L"\"" << std::endl;
    }
}

int main() {
    test_overflow_i_plus_digit_w();
    test_overflow_w_times_factor();
    test_overflow_delta_computation();
    test_surrogate_pairs();
    test_domain_validation();
    test_fragment_parsing();
    
    return 0;
}
