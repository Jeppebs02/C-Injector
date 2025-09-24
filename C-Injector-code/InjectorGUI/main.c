#include <windows.h>
#include <commctrl.h>
#include "injector.h" // injection library header
#include "process.h" // process enumeration header
#include "ntdll_ext.h"
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Comctl32.lib") // Link  the Common Controls library

// Global handles to UI elements so we can access them from anywhere
HWND hProcessListView = NULL;
HWND hInjectButton = NULL;
WCHAR szDllPath[MAX_PATH] = { 0 }; // Global variable to store the selected DLL path

// Forward declarations of functions. TODO: Add more as needed.
void PopulateProcessList(HWND hListView);
void HandleInjectClick(HWND hWnd);




// The Window Procedure: Handles all events for the main window.
// check https://learn.microsoft.com/en-us/windows/win32/api/winuser/nc-winuser-wndproc
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {

        // Create the ListView to show processes
        hProcessListView = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"",
            WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL,
            10, 10, 460, 300, hWnd, (HMENU)101, NULL, NULL);

        // Add columns to the ListView
        LV_COLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        lvc.cx = 280; lvc.pszText = L"Process Name";
        ListView_InsertColumn(hProcessListView, 0, &lvc);
        lvc.cx = 120; lvc.pszText = L"PID";
        ListView_InsertColumn(hProcessListView, 1, &lvc);

		// Add processes to the ListView
        PopulateProcessList(hProcessListView);

        // Create the buttons
        CreateWindowW(L"Button", L"Select DLL...", WS_VISIBLE | WS_CHILD, 10, 320, 120, 30, hWnd, (HMENU)1, NULL, NULL);
        hInjectButton = CreateWindowW(L"Button", L"Inject", WS_VISIBLE | WS_CHILD, 140, 320, 120, 30, hWnd, (HMENU)2, NULL, NULL);

        break;
    }

    case WM_COMMAND:
    {
        // This runs when a button is clicked or a menu item is selected.
        // LOWORD(wParam) contains the ID of the control that sent the message.
        switch (LOWORD(wParam))
        {
        case 1: // "Select DLL..." button
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
                // The user selected a file, szDllPath is now populated.
				// TODO: Update UI to show selected DLL name/path.
            }
            break;
        }
        case 2: // "Inject" button
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
    // Initialize controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    // Register window class
    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"InjectorWindowClass";
    RegisterClassW(&wc);

    // Create the window
    HWND hWnd = CreateWindowW(L"InjectorWindowClass", L"Simple DLL Injector",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 410,
        NULL, NULL, hInstance, NULL);

    // Main message loop
    MSG msg = { 0 };
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}


// Logic Functions

void PopulateProcessList(HWND hListView)
{
    ListView_DeleteAllItems(hListView); // Clear the list first :)

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
    // Get the selected process from the ListView
    int selectedIndex = ListView_GetNextItem(hProcessListView, -1, LVNI_SELECTED);
    if (selectedIndex == -1) {
        MessageBoxW(hWnd, L"Please select a process from the list.", L"Error", MB_ICONERROR);
        return;
    }

    // Check if a DLL has been selected
    if (szDllPath[0] == L'\0') {
        MessageBoxW(hWnd, L"Please select a DLL file to inject.", L"Error", MB_ICONERROR);
        return;
    }

    // Get the PID from the ListView's sub-item
    WCHAR pidText[16];
    ListView_GetItemText(hProcessListView, selectedIndex, 1, pidText, 16);
    DWORD pid = _wtoi(pidText);

    // inject
    if (InjectDll(pid, szDllPath)) {
        MessageBoxW(hWnd, L"Injection Succeeded!", L"Success", MB_ICONINFORMATION);
    }
    else {
        MessageBoxW(hWnd, L"Injection Failed.", L"Failure", MB_ICONERROR);
    }
}