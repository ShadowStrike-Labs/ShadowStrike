#include <iostream>
#include <string>
#include <algorithm>

void testHostnameExtraction(const std::wstring& url) {
    std::wstring hostname;
    size_t schemeEnd = url.find(L"://");
    size_t hostStart = (schemeEnd != std::wstring::npos) ? schemeEnd + 3 : 0;
    size_t hostEnd = url.find_first_of(L":/?", hostStart);
    if (hostEnd == std::wstring::npos) hostEnd = url.size();
    hostname = url.substr(hostStart, hostEnd - hostStart);
    std::transform(hostname.begin(), hostname.end(), hostname.begin(), ::towlower);
    
    std::wcout << L"URL: " << url << L" -> Hostname: " << hostname << std::endl;
}

int main() {
    // Test cases
    testHostnameExtraction(L"http://example.com/path");
    testHostnameExtraction(L"https://example.com:8080/path");
    testHostnameExtraction(L"http://[::1]/path");
    testHostnameExtraction(L"http://[2001:db8::1]:8080/path");
    testHostnameExtraction(L"example.com");
    testHostnameExtraction(L"localhost");
    testHostnameExtraction(L"http://user@host.com/path");
    testHostnameExtraction(L"http://user:pass@host.com/path");
    testHostnameExtraction(L"");
    testHostnameExtraction(L"://noscheme");
    return 0;
}
