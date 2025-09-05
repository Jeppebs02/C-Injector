// process.c
#include <windows.h>
#include <tlhelp32.h>

BOOL EnumerateProcesses(OUT PROCESSENTRY32* pe32Array, OUT DWORD* count)
{
	// Validate parameters
	if (!pe32Array || !count) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	// Store the capacity and reset count
	const DWORD cap = *count;
	*count = 0;

	// Create a snapshot of all processes
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}


	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(pe); // dwSize member must always set before calling Process32First/Next functions
	
	DWORD i = 0; // base index

	// Get the first process of the snapshot
	BOOL more = Process32First(hSnap, &pe);

	// Walk the process list
	while (more) {
		// If we still have room, copy this process entry into caller's array
		if (i < cap) {
			// assign then increment
			pe32Array[i] = pe;
			i++;
		}
		pe.dwSize = sizeof(pe);
		more = Process32Next(hSnap, &pe);
	}

	*count = i;
	CloseHandle(hSnap);
	return TRUE;
}
