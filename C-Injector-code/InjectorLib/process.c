// process.c
#include "process.h"
#include <windows.h>
#include <tlhelp32.h>

BOOL EnumerateProcesses(OUT PROCESSENTRY32* pe32Array, OUT DWORD* count)
{
	if (!pe32Array || !count) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	const DWORD cap = *count;
	*count = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	DWORD i = 0;
	DWORD total = 0;
	BOOL more = Process32First(hSnap, &pe);

	while (more) {
		total++;
		if (i < cap) {
			pe32Array[i] = pe;
			i++;
		}
		pe.dwSize = sizeof(pe);
		more = Process32Next(hSnap, &pe);
	}

	*count = i;
	CloseHandle(hSnap);

	if (total > cap) {
		SetLastError(ERROR_MORE_DATA);
	}

	return TRUE;
}
