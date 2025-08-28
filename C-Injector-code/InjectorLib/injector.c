//injector.c
#include "injector.h"
#include "ntdll_ext.h"
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")

static NtOpenProcess_t NtOpenProcess = NULL;
static NtCreateSection_t NtCreateSection = NULL;
static NtMapViewOfSection_t NtMapViewOfSection = NULL;
static NtCreateThreadEx_t NtCreateThreadEx = NULL;


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



/*  Helpers for walking the target PEB to find the base address of   */

static NTSTATUS GetRemoteModuleBase(HANDLE hProcess, LPCWSTR moduleName, PVOID* pBase)
{
    /* 1.  Get the PEB address */
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), NULL);
    if (status != STATUS_SUCCESS) return status;

    /* 2.  Read the PEB */

    PEB peb = { 0 };
    SIZE_T bytesRead = 0;
    status = NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb,
        sizeof(peb), &bytesRead);
    if (status != STATUS_SUCCESS) return status;

    /* 3.  Walk InMemoryOrderModuleList */
    LIST_ENTRY* list = &peb.Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = list->Flink;

    while (current != list) {
        /* read the entry */
        typedef struct _LDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            /* many other members omitted. add more later  */
        } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

        LDR_DATA_TABLE_ENTRY entry = { 0 };
        status = NtReadVirtualMemory(hProcess,
            CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
            &entry,
            sizeof(entry),
            &bytesRead);
        if (status != STATUS_SUCCESS) return status;

        /* compare BaseDllName with the requested module name */
        if (entry.BaseDllName.Buffer) {
            WCHAR buf[260] = { 0 };
            ULONG copyLen = (entry.BaseDllName.Length / sizeof(WCHAR));
            if (copyLen > 259) copyLen = 259;
            memcpy(buf, entry.BaseDllName.Buffer, copyLen * sizeof(WCHAR));
            if (_wcsicmp(buf, moduleName) == 0) {
                *pBase = entry.DllBase;
                return STATUS_SUCCESS;
            }
        }

        current = current->Flink;
    }
    return STATUS_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/*  Resolve the address of LoadLibraryW in the target process.        */
static PVOID GetRemoteLoadLibraryW(HANDLE hProcess)
{
    /* 1.  Find the remote kernel32 base */
    PVOID remoteK32 = NULL;
    NTSTATUS status = GetRemoteModuleBase(hProcess, L"kernel32.dll", &remoteK32);
    if (status != STATUS_SUCCESS) return NULL;

    /* 2.  Compute offset of LoadLibraryW in local kernel32 */
    PVOID localK32 = GetModuleHandleW(L"kernel32.dll");
    PVOID localLoad = GetProcAddress(localK32, "LoadLibraryW");
    ULONG_PTR offset = (ULONG_PTR)localLoad - (ULONG_PTR)localK32;

    /* 3.  Return the remote address */
    return (PVOID)((ULONG_PTR)remoteK32 + offset);
}


BOOL InjectDll(DWORD pid, LPCWSTR dllPath)
{
    if (!InitNtdll()) return FALSE;

    // Open target
    HANDLE hTarget = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    CLIENT_ID cid = { .UniqueProcess = (HANDLE)(ULONG_PTR)pid, .UniqueThread = NULL };

    NTSTATUS status = NtOpenProcess(&hTarget, PROCESS_ALL_ACCESS,
        &objAttr, &cid);
    if (status != STATUS_SUCCESS) return FALSE;

    /* ---------------------------------------------------------------- */
    /* 2.  Resolve remote address of LoadLibraryW */
    PVOID remoteLoadLibraryW = GetRemoteLoadLibraryW(hTarget);
    if (!remoteLoadLibraryW) {
        CloseHandle(hTarget);
        return FALSE;
    }

    /* ---------------------------------------------------------------- */
    /* 3.  Allocate memory in the target for the DLL path string */
    SIZE_T dwSize = (wcslen(dllPath) + 1) * sizeof(WCHAR);
    PVOID remoteAddr = NULL;
    status = NtAllocateVirtualMemory(hTarget, &remoteAddr, 0, &dwSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) {
        CloseHandle(hTarget);
        return FALSE;
    }

    /* ---------------------------------------------------------------- */
    /* 4.  Write the DLL path into the allocated space */
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hTarget, remoteAddr,
        (PVOID)dllPath, dwSize,
        &bytesWritten);
    if (status != STATUS_SUCCESS || bytesWritten != dwSize) {
        NtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
        CloseHandle(hTarget);
        return FALSE;
    }

    /* ---------------------------------------------------------------- */
    /* 5.  Create the remote thread that calls LoadLibraryW(remoteAddr) */
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
        hTarget, remoteLoadLibraryW,
        remoteAddr, FALSE,
        0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        NtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
        CloseHandle(hTarget);
        return FALSE;
    }

    /* ---------------------------------------------------------------- */
    /* 6.  Optional: wait for the thread to finish (or detach) */
    WaitForSingleObject(hThread, INFINITE);

    /* ---------------------------------------------------------------- */
    /* 7.  Clean up */
    CloseHandle(hThread);
    NtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
    CloseHandle(hTarget);

    return TRUE;
}
