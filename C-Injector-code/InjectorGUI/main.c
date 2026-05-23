#include <windows.h>
#include <commctrl.h>
#include "injector.h"
#include "process.h"
#include "ntdll_ext.h"
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Comctl32.lib")

#define CTL_LISTVIEW   101
#define CTL_SELECT_DLL 1
#define CTL_INJECT     2
#define CTL_DLL_LABEL  3

HWND hProcessListView = NULL;
HWND hInjectButton = NULL;
HWND hDllPathLabel = NULL;
WCHAR szDllPath[MAX_PATH] = { 0 };

void PopulateProcessList(HWND hListView);
void HandleInjectClick(HWND hWnd);

static BOOL IsRunningElevated(void)
{
	BOOL isElevated = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
			isElevated = elevation.TokenIsElevated;
		}
		CloseHandle(hToken);
	}
	return isElevated;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:
	{
		hProcessListView = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"",
			WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
			10, 10, 460, 280, hWnd, (HMENU)CTL_LISTVIEW, NULL, NULL);

		LV_COLUMN lvc;
		lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
		lvc.cx = 280; lvc.pszText = L"Process Name";
		ListView_InsertColumn(hProcessListView, 0, &lvc);
		lvc.cx = 120; lvc.pszText = L"PID";
		ListView_InsertColumn(hProcessListView, 1, &lvc);

		PopulateProcessList(hProcessListView);

		hDllPathLabel = CreateWindowW(L"Static", L"No DLL selected.",
			WS_VISIBLE | WS_CHILD,
			10, 300, 440, 20, hWnd, (HMENU)CTL_DLL_LABEL, NULL, NULL);

		CreateWindowW(L"Button", L"Select DLL...", WS_VISIBLE | WS_CHILD,
			10, 330, 120, 30, hWnd, (HMENU)CTL_SELECT_DLL, NULL, NULL);
		hInjectButton = CreateWindowW(L"Button", L"Inject", WS_VISIBLE | WS_CHILD,
			140, 330, 120, 30, hWnd, (HMENU)CTL_INJECT, NULL, NULL);

		if (!IsRunningElevated()) {
			MessageBoxW(hWnd, L"Not running as Administrator.\n"
				L"Injection into system or protected processes will likely fail.",
				L"Warning", MB_ICONWARNING);
		}

		break;
	}

	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case CTL_SELECT_DLL:
		{
			OPENFILENAMEW ofn = { 0 };
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hWnd;
			ofn.lpstrFile = szDllPath;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			if (GetOpenFileNameW(&ofn)) {
				WCHAR labelText[MAX_PATH + 20];
				swprintf(labelText, MAX_PATH + 20, L"DLL: %s", szDllPath);
				SetWindowTextW(hDllPathLabel, labelText);
			}
			break;
		}
		case CTL_INJECT:
		{
			HandleInjectClick(hWnd);
			break;
		}
		}
		break;
	}

	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break;
	}

	default:
		return DefWindowProcW(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_LISTVIEW_CLASSES;
	InitCommonControlsEx(&icex);

	WNDCLASSW wc = { 0 };
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc.lpszClassName = L"InjectorWindowClass";
	RegisterClassW(&wc);

	HWND hWnd = CreateWindowW(L"InjectorWindowClass", L"DLL Injector",
		WS_OVERLAPPEDWINDOW | WS_VISIBLE,
		CW_USEDEFAULT, CW_USEDEFAULT, 500, 430,
		NULL, NULL, hInstance, NULL);

	MSG msg = { 0 };
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}

void PopulateProcessList(HWND hListView)
{
	ListView_DeleteAllItems(hListView);

	PROCESSENTRY32 pe32[1024];
	DWORD count = 1024;

	if (EnumerateProcesses(pe32, &count))
	{
		for (DWORD i = 0; i < count; i++)
		{
			LVITEMW lvi = { 0 };
			lvi.mask = LVIF_TEXT;
			lvi.iItem = i;
			lvi.pszText = pe32[i].szExeFile;
			ListView_InsertItem(hListView, &lvi);

			WCHAR pidText[16];
			swprintf(pidText, 16, L"%d", pe32[i].th32ProcessID);
			ListView_SetItemText(hListView, i, 1, pidText);
		}
	}
}

void HandleInjectClick(HWND hWnd)
{
	int selectedIndex = ListView_GetNextItem(hProcessListView, -1, LVNI_SELECTED);
	if (selectedIndex == -1) {
		MessageBoxW(hWnd, L"Please select a process from the list.", L"Error", MB_ICONERROR);
		return;
	}

	if (szDllPath[0] == L'\0') {
		MessageBoxW(hWnd, L"Please select a DLL file to inject.", L"Error", MB_ICONERROR);
		return;
	}

	WCHAR pidText[16];
	ListView_GetItemText(hProcessListView, selectedIndex, 1, pidText, 16);
	DWORD pid = _wtoi(pidText);

	INJECT_STATUS result = InjectDll(pid, szDllPath);

	switch (result) {
	case INJECT_OK:
		MessageBoxW(hWnd, L"Injection succeeded!", L"Success", MB_ICONINFORMATION);
		break;
	case INJECT_ERR_NTDLL_INIT:
		MessageBoxW(hWnd, L"Failed to initialise NTDLL functions.", L"Error", MB_ICONERROR);
		break;
	case INJECT_ERR_OPEN_PROCESS:
		MessageBoxW(hWnd, L"Failed to open process.\nMake sure the PID is valid and you have sufficient privileges.", L"Error", MB_ICONERROR);
		break;
	case INJECT_ERR_RESOLVE_LOADLIBRARY:
		MessageBoxW(hWnd, L"Failed to resolve LoadLibraryW in the target process.", L"Error", MB_ICONERROR);
		break;
	case INJECT_ERR_ALLOC:
		MessageBoxW(hWnd, L"Failed to allocate memory in the target process.", L"Error", MB_ICONERROR);
		break;
	case INJECT_ERR_WRITE:
		MessageBoxW(hWnd, L"Failed to write DLL path into the target process.", L"Error", MB_ICONERROR);
		break;
	case INJECT_ERR_CREATE_THREAD:
		MessageBoxW(hWnd, L"Failed to create remote thread.", L"Error", MB_ICONERROR);
		break;
	case INJECT_ERR_THREAD_TIMEOUT:
		MessageBoxW(hWnd, L"Remote thread timed out.\nThe loaded DLL may have hung in DllMain.", L"Error", MB_ICONERROR);
		break;
	default:
		MessageBoxW(hWnd, L"Injection failed for an unknown reason.", L"Error", MB_ICONERROR);
		break;
	}
}
