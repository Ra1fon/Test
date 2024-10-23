#ifndef PROTECT_H
#define PROTECT_H

#include <Windows.h>
#include <string>

typedef HRESULT(WINAPI* tCoInitializeEx)(LPVOID, DWORD);
typedef HRESULT(WINAPI* tCoInitializeSecurity)(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*, void*, DWORD, DWORD, void*, DWORD, void*);
typedef HRESULT(WINAPI* tCoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef HRESULT(WINAPI* tCoSetProxyBlanket)(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
typedef void(WINAPI* tCoUninitialize)();

struct ComAPI {
    tCoInitializeEx CoInitializeEx;
    tCoInitializeSecurity CoInitializeSecurity;
    tCoCreateInstance CoCreateInstance;
    tCoSetProxyBlanket CoSetProxyBlanket;
    tCoUninitialize CoUninitialize;
};

void Protect(); 
bool LoadComAPI(ComAPI* api);
void AntiDebug();
void AntiAnalysis();
void AntiVMs();
bool EmulationCheck();
bool IsDebuggerPresentCheck();
bool CheckRemoteDebuggerPresentCheck();
bool NtGlobalFlagCheck();
bool BeingDebuggedPEBCheck();
bool HardwareBreakpointCheck();
std::string GetWmiInfo(const char* className, const char* propertyName, ComAPI* api);
bool IsVirtualMachine(ComAPI* api);
void XorString(char* str, char key);
#endif
