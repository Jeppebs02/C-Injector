
/*  injector.h public API of the library */
#pragma once
#include <windows.h>


BOOL InjectDll(DWORD pid, LPCWSTR dllPath);