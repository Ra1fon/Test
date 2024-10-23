#include "Protect.h"
#include <Wbemidl.h>
#include <comdef.h>
#include <string>
#include <intrin.h>
#pragma comment(lib, "wbemuuid.lib")

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    BYTE Reserved4[104];
    PVOID Reserved5[52];
    PVOID PostProcessInitRoutine;
    BYTE Reserved6[128];
    PVOID Reserved7[1];
    ULONG SessionId;
} PEB;

void XorString(char* str, char key) {
    while (*str) {
        *str ^= key;
        str++;
    }
}


FARPROC GetDynamicAPI(HMODULE hModule, const char* funcName) {
    char obfFuncName[64];
    strcpy_s(obfFuncName, funcName);
    XorString(obfFuncName, 0x5A);
    return GetProcAddress(hModule, obfFuncName);
}


bool LoadComAPI(ComAPI* api) {
    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (!hOle32) return false;

    api->CoInitializeEx = (tCoInitializeEx)GetDynamicAPI(hOle32, "CoInitializeEx");
    api->CoInitializeSecurity = (tCoInitializeSecurity)GetDynamicAPI(hOle32, "CoInitializeSecurity");
    api->CoCreateInstance = (tCoCreateInstance)GetDynamicAPI(hOle32, "CoCreateInstance");
    api->CoSetProxyBlanket = (tCoSetProxyBlanket)GetDynamicAPI(hOle32, "CoSetProxyBlanket");
    api->CoUninitialize = (tCoUninitialize)GetDynamicAPI(hOle32, "CoUninitialize");

    return (api->CoInitializeEx && api->CoInitializeSecurity && api->CoCreateInstance &&
        api->CoSetProxyBlanket && api->CoUninitialize);
}


PEB* GetPEB() {
#ifdef _M_X64
    return (PEB*)__readgsqword(0x60);
#else
    return (PEB*)__readfsdword(0x30);
#endif
}


bool BeingDebuggedPEBCheck() {
    PEB* peb = GetPEB();
    return peb->BeingDebugged;
}


bool NtGlobalFlagCheck() {
    PEB* peb = GetPEB();
    return (peb->Reserved2[0] & 0x70) != 0;
}


bool IsDebuggerPresentCheck() {
    return IsDebuggerPresent();
}

bool CheckRemoteDebuggerPresentCheck() {
    BOOL isDebuggerPresent = FALSE;
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    FARPROC pCheckRemoteDebuggerPresent = GetDynamicAPI(hKernel32, "CheckRemoteDebuggerPresent");

    if (pCheckRemoteDebuggerPresent) {
        typedef BOOL(WINAPI* tCheckRemoteDebuggerPresent)(HANDLE, PBOOL);
        tCheckRemoteDebuggerPresent CheckRemoteDebuggerPresent = (tCheckRemoteDebuggerPresent)pCheckRemoteDebuggerPresent;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    }

    return isDebuggerPresent;
}

bool HardwareBreakpointCheck() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return true;
        }
    }
    return false;
}

void AntiDebug() {
    if (IsDebuggerPresentCheck() || CheckRemoteDebuggerPresentCheck() ||
        NtGlobalFlagCheck() || BeingDebuggedPEBCheck() || HardwareBreakpointCheck()) {
        ExitProcess(0);
    }
}

// Получение информации через WMI
std::string GetWmiInfo(const char* className, const char* propertyName, ComAPI* api) {
    char classBuf[64];
    char propBuf[64];

    strcpy_s(classBuf, className);
    strcpy_s(propBuf, propertyName);
    XorString(classBuf, 0x5A);
    XorString(propBuf, 0x5A);

    HRESULT hres;
    std::string result = "";

    hres = api->CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return result;

    hres = api->CoInitializeSecurity(
        NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL
    );
    if (FAILED(hres)) {
        api->CoUninitialize();
        return result;
    }

    IWbemLocator* pLoc = NULL;
    hres = api->CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        api->CoUninitialize();
        return result;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        api->CoUninitialize();
        return result;
    }

    hres = api->CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        api->CoUninitialize();
        return result;
    }

    std::string query = "SELECT ";
    query += propBuf;
    query += " FROM ";
    query += classBuf;

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        api->CoUninitialize();
        return result;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtProp;
        hr = pclsObj->Get(_bstr_t(propBuf), 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            result = _bstr_t(vtProp.bstrVal);
            VariantClear(&vtProp);
        }
        pclsObj->Release();
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    api->CoUninitialize();

    return result;
}

// Проверка на Вм по биос нейму 
bool IsVirtualMachine(ComAPI* api) {
    char memoryClass[] = "Win32_PhysicalMemory";
    char memoryProp[] = "Speed";
    char biosClass[] = "Win32_BIOS";
    char biosProp[] = "Version";
    const char* virtualBioses[] = { "BOCHS", "VMware", "VirtualBox", "Xen", "Hyper-V", "virtual", "qemu", "oracle", "google" };

    XorString(memoryClass, 0x5A);
    XorString(memoryProp, 0x5A);
    XorString(biosClass, 0x5A);
    XorString(biosProp, 0x5A);

    std::string memorySpeed = GetWmiInfo(memoryClass, memoryProp, api);
    if (memorySpeed.empty() || std::stoi(memorySpeed) < 10) {
        return true;
    }

    std::string biosVersion = GetWmiInfo(biosClass, biosProp, api);
    for (const char* vbios : virtualBioses) {
        if (biosVersion.find(vbios) != std::string::npos) {
            return true;
        }
    }

    return false;
}


void AntiVMs() {
    ComAPI api;
    if (LoadComAPI(&api)) {
        if (IsVirtualMachine(&api)) {
            ExitProcess(0);
        }
    }
}

void Protect() {
    AntiDebug();
    AntiVMs(); 
}
