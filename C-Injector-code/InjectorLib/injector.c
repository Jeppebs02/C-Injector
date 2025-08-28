//injector.c
#include "injector.h"
#include "ntdll_ext.h"
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")

static NtOpenProcess_t               fnNtOpenProcess = NULL;
static NtCreateThreadEx_t            fnNtCreateThreadEx = NULL;
static NtQueryInformationProcess_t   fnNtQueryInformationProcess = NULL;
static NtReadVirtualMemory_t         fnNtReadVirtualMemory = NULL;
static NtAllocateVirtualMemory_t     fnNtAllocateVirtualMemory = NULL;
static NtWriteVirtualMemory_t        fnNtWriteVirtualMemory = NULL;
static NtFreeVirtualMemory_t         fnNtFreeVirtualMemory = NULL;


static BOOL InitNtdll(void)
{
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) {
        return FALSE;
    }

    fnNtOpenProcess = (NtOpenProcess_t)GetProcAddress(hNtDll, "NtOpenProcess");
    fnNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtDll, "NtCreateThreadEx");
    fnNtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    fnNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtDll, "NtReadVirtualMemory");
    fnNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
    fnNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
    fnNtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetProcAddress(hNtDll, "NtFreeVirtualMemory");

    // Check if any of them failed to load
    return fnNtOpenProcess && fnNtCreateThreadEx && fnNtQueryInformationProcess &&
        fnNtReadVirtualMemory && fnNtAllocateVirtualMemory && fnNtWriteVirtualMemory &&
        fnNtFreeVirtualMemory;
}

//Helpers for walking the target PEB to find the base address of

static NTSTATUS GetRemoteModuleBase(HANDLE hProcess, LPCWSTR moduleName, PVOID* pBase)
{
    PROCESS_BASIC_INFORMATION pbi = { 0 };

    NTSTATUS status = fnNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status != STATUS_SUCCESS) return status;

    PEB peb = { 0 };
    SIZE_T bytesRead = 0;

    status = fnNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead);
    if (status != STATUS_SUCCESS) return status;

    PEB_LDR_DATA ldrData = { 0 };

    status = fnNtReadVirtualMemory(hProcess, peb.Ldr, &ldrData, sizeof(ldrData), &bytesRead);
    if (status != STATUS_SUCCESS) return status;

    LIST_ENTRY* pLdrListHead = &ldrData.InMemoryOrderModuleList;
    LIST_ENTRY* pCurrentEntry = ldrData.InMemoryOrderModuleList.Flink;
    WCHAR buf[260];

    while (pCurrentEntry != pLdrListHead)
    {

        LDR_DATA_TABLE_ENTRY entry = { 0 };
        
        status = fnNtReadVirtualMemory(hProcess, CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(entry), &bytesRead);
        if (status != STATUS_SUCCESS) return status;

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            status = fnNtReadVirtualMemory(hProcess, entry.BaseDllName.Buffer, buf, entry.BaseDllName.Length, &bytesRead);
            if (status == STATUS_SUCCESS) {
                buf[bytesRead / sizeof(WCHAR)] = L'\0';
                if (_wcsicmp(buf, moduleName) == 0) {
                    *pBase = entry.DllBase;
                    return STATUS_SUCCESS;
                }
            }
        }
        pCurrentEntry = entry.InMemoryOrderLinks.Flink;
    }
    return STATUS_NOT_FOUND;
}


// Resolve the address of LoadLibraryW in the target process.
// This is not necessary because kernel32.dll is almost always loaded at the same base address in all processes.
// But its nice for backward compatibility and in case of some weird edge cases.
static PVOID GetRemoteLoadLibraryW(HANDLE hProcess)
{
	// Find the remote kernel32 base, usually the same as local since its a system DLL
    PVOID remoteK32 = NULL;
    NTSTATUS status = GetRemoteModuleBase(hProcess, L"kernel32.dll", &remoteK32);
    if (status != STATUS_SUCCESS) return NULL;

    // Compute offset of LoadLibraryW in local kernel32
    PVOID localK32 = GetModuleHandleW(L"kernel32.dll");
    PVOID localLoad = GetProcAddress(localK32, "LoadLibraryW");
    ULONG_PTR offset = (ULONG_PTR)localLoad - (ULONG_PTR)localK32;

    
    return (PVOID)((ULONG_PTR)remoteK32 + offset);
}

BOOL InjectDll(DWORD pid, LPCWSTR dllPath)
{
    if (!InitNtdll()) return FALSE;

    HANDLE hTarget = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    CLIENT_ID cid = { .UniqueProcess = (HANDLE)(ULONG_PTR)pid, .UniqueThread = NULL };

	// get a handle to the target process with all access
    if (fnNtOpenProcess(&hTarget, PROCESS_ALL_ACCESS, &objAttr, &cid) != STATUS_SUCCESS){
        return FALSE;
    }

    PVOID remoteLoadLibraryW = GetRemoteLoadLibraryW(hTarget);
    if (!remoteLoadLibraryW) {
        CloseHandle(hTarget);
        return FALSE;
    }

	// Get the size of the DLL path string including null terminator
    SIZE_T dwSize = (wcslen(dllPath) + 1) * sizeof(WCHAR);
    PVOID remoteAddr = NULL;
	// Allocate memory in the target process for the DLL path
    if (fnNtAllocateVirtualMemory(hTarget, &remoteAddr, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != STATUS_SUCCESS) {
        CloseHandle(hTarget);
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
	// write the DLL path into the allocated memory
    NTSTATUS status = fnNtWriteVirtualMemory(hTarget, remoteAddr, (PVOID)dllPath, dwSize, &bytesWritten);
    if (status != STATUS_SUCCESS || bytesWritten != dwSize) {
        fnNtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
        CloseHandle(hTarget);
        return FALSE;
    }

    HANDLE hThread = NULL;
	// create a remote thread that calls LoadLibraryW with the DLL path as argument
    status = fnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hTarget, remoteLoadLibraryW, remoteAddr, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        fnNtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
        CloseHandle(hTarget);
        return FALSE;
    }

	// Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    fnNtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
    CloseHandle(hTarget);

    return TRUE;
}