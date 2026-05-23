// process.h
#pragma once

#include <windows.h>
#include <tlhelp32.h>

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * EnumerateProcesses
	 *
	 * Enumerates running processes and copies up to *count entries into the caller's array.
	 *
	 * @param pe32Array [OUT]  Pointer to an array of PROCESSENTRY32 structures.
	 * @param count     [IN/OUT] On input: capacity of pe32Array (number of elements).
	 *                          On output: number of entries actually written.
	 *
	 * @return TRUE on success. If the array was too small to hold all processes,
	 *         GetLastError() returns ERROR_MORE_DATA.
	 */
	BOOL EnumerateProcesses(OUT PROCESSENTRY32* pe32Array, OUT DWORD* count);

#ifdef __cplusplus
}
#endif
