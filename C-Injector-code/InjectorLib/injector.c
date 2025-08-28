//injector.c
#include "injector.h"
#include "ntdll_ext.h"


static NtOpenProcess_t NtOpenProcess;
static NtCreateSection_t NtCreateSection;
static NtMapViewOfSection_t NtMapViewOfSection;
static NtCreateThreadEx_t NtCreateThreadEx;

static BOOL InitNtdll(void)
{
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) return FALSE;

    NtOpenProcess = (NtOpenProcess_t)GetProcAddress(hNtDll, "NtOpenProcess");
    NtCreateSection = (NtCreateSection_t)GetProcAddress(hNtDll, "NtCreateSection");
    NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtDll, "NtMapViewOfSection");
    NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtDll, "NtCreateThreadEx");
    return NtOpenProcess && NtCreateSection && NtMapViewOfSection && NtCreateThreadEx;
}


BOOL InjectDll(IN DWORD pid, IN LPWSTR DllName) {

    if (!InitNtdll()) {
        return FALSE;
    }

    /* 1. Open target process */
    HANDLE hTarget = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    CLIENT_ID cid = { .UniqueProcess = (HANDLE)(ULONG_PTR)pid, .UniqueThread = NULL };
    if (NtOpenProcess(&hTarget, PROCESS_ALL_ACCESS, &objAttr, &cid) != STATUS_SUCCESS)
        return FALSE;


}

