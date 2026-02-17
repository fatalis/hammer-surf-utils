#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define DLLEXPORT __declspec(dllexport)

static HMODULE real_dll;

void wrapper(void)
{
    if (real_dll)
        return;

    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    lstrcatA(path, "\\version.dll");
    real_dll = LoadLibraryA(path);
}

DLLEXPORT BOOL WINAPI GetFileVersionInfoA(
    LPCSTR a, DWORD b, DWORD c, LPVOID d)
{
    wrapper();
    return ((BOOL (WINAPI *)(LPCSTR, DWORD, DWORD, LPVOID))
        GetProcAddress(real_dll, "GetFileVersionInfoA"))(a, b, c, d);
}

DLLEXPORT BOOL WINAPI GetFileVersionInfoW(
    LPCWSTR a, DWORD b, DWORD c, LPVOID d)
{
    wrapper();
    return ((BOOL (WINAPI *)(LPCWSTR, DWORD, DWORD, LPVOID))
        GetProcAddress(real_dll, "GetFileVersionInfoW"))(a, b, c, d);
}

DLLEXPORT DWORD WINAPI GetFileVersionInfoSizeA(
    LPCSTR a, LPDWORD b)
{
    wrapper();
    return ((DWORD (WINAPI *)(LPCSTR, LPDWORD))
        GetProcAddress(real_dll, "GetFileVersionInfoSizeA"))(a, b);
}

DLLEXPORT DWORD WINAPI GetFileVersionInfoSizeW(
    LPCWSTR a, LPDWORD b)
{
    wrapper();
    return ((DWORD (WINAPI *)(LPCWSTR, LPDWORD))
        GetProcAddress(real_dll, "GetFileVersionInfoSizeW"))(a, b);
}
