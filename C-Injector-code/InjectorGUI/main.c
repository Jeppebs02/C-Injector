#include "injector.h"


int main(void)
{
    DWORD pid = 28244;                    // put the real PID here
    LPCWSTR dll = L"C:\\Users\\lain\\Documents\\Oracle-Server\\Dll2.dll";

    if (InjectDll(pid, dll))
        wprintf(L"[*] Injection succeeded.\n");
    else
        wprintf(L"[!] Injection failed.\n");
    return 0;
}