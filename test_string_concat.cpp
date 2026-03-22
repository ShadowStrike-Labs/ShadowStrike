#include <string>
#include <iostream>

// Simulating the problematic code
void TestFunction() noexcept {
    std::wstring msg1 = L"Error 1";
    std::wstring msg2 = L"Error 2";
    
    // This can throw std::bad_alloc, violating noexcept
    std::wstring combined = L"Combined: " + msg1 + L"; " + msg2;
    
    std::wcout << combined << std::endl;
}

int main() {
    TestFunction();
    return 0;
}
