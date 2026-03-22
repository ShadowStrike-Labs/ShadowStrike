#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

int main() {
    printf("WINHTTP_OPTION_REDIRECT_POLICY = %d\n", WINHTTP_OPTION_REDIRECT_POLICY);
    printf("WINHTTP_OPTION_REDIRECT_POLICY_NEVER = %d\n", WINHTTP_OPTION_REDIRECT_POLICY_NEVER);
    
    return 0;
}
