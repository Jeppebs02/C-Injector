#include "injector.h"
#include <stdio.h>


int main(void)
{
    DWORD pid = 28244;                    // put the real PID here
    LPCWSTR dll = L"C:\\Users\\lain\\Documents\\Oracle-Server\\Dll2.dll";

    if (InjectDll(pid, dll))
        printf(L"[*] Injection succeeded.\n");
    else
        printf(L"[!] Injection failed.\n");
    return 0;
}