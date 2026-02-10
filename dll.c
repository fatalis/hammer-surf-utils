#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#define SBI_SIZE 3
#define SURF_NORMAL 0.7

// an arbitrary cutoff for a very steep ramp that you can somewhat stay on
#define UNSURF_NORMAL 0.28

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

#define HOOK_DEBUG 1

#if HOOK_DEBUG
static void log_msg(const char *fmt, ...)
{
    FILE *f = fopen("hook.log", "a");
    if (!f)
        return;

    va_list va;
    va_start(va, fmt);
    vfprintf(f, fmt, va);
    va_end(va);

    fclose(f);
}
#else
#define log_msg(...) ((void)0)
#endif

typedef int (__thiscall *SetPaneText_t)(void *this_, int nIndex, char *lpszNewText, int bUpdate);
static SetPaneText_t orig_SetPaneText = NULL;

int __thiscall hook_SetPaneText(void *this_, int nIndex, char *lpszNewText, int bUpdate)
{
    /* log_msg("[SetPaneText] %p %d \"%s\" %d\n", this_, nIndex, lpszNewText, bUpdate); */

    if (nIndex == SBI_SIZE) {
        int w = -1, l = -1, h = -1;

        if (sscanf(lpszNewText, " %dw %dl %dh", &w, &l, &h) != 3)
            goto out;

        // lpszNewText buffer size is now confirmed to be MAX_PATH(260)

        int width = (w < l) ? w : l;
        int height = h;

        double angle = atan((double)height / (double)width) * (180.0 / M_PI);
        double angle_rad = atan2(height, width);
        double normal_rad = angle_rad + M_PI / 2.0;
        double normal = sin(normal_rad);

        if (normal < SURF_NORMAL && normal >= UNSURF_NORMAL) {
            int steep_score = (int)fmin(floor((SURF_NORMAL - normal) * 100.0), 10);
            log_msg("%d %d angle %f rad %f normal %f score %d\n", height, width, angle, angle_rad, normal, steep_score);

            char buf[MAX_PATH];

            snprintf(
               buf,
               sizeof(buf),
               "S%d %.2f\xB0%s",
               steep_score,
               angle,
               lpszNewText
            );

            strncpy(lpszNewText, buf, MAX_PATH-1);
            lpszNewText[MAX_PATH-1] = '\0';
        }
    }

out:
    return orig_SetPaneText(this_, nIndex, lpszNewText, bUpdate);
}

static void *find_pattern(uint8_t *base, size_t size,
                          const uint8_t *pat, const char *mask)
{
    size_t len = strlen(mask);

    for (size_t i = 0; i <= size - len; i++) {
        size_t j = 0;
        for (; j < len; j++) {
            if (mask[j] == 'x' && base[i + j] != pat[j])
                break;
        }
        if (j == len)
            return base + i;
    }
    return NULL;
}

static void install_hook(void *target, void *hook, void **orig, size_t extra_bytes)
{
    DWORD old;
    uint8_t *src = (uint8_t *)target;
    size_t stolen = 12 + extra_bytes;

    *orig = VirtualAlloc(NULL, 64,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_EXECUTE_READWRITE);

    // Copy stolen bytes (include any extra bytes so that we keep
    // instructions intact if the 12-byte window would split one).
    memcpy(*orig, src, stolen);

    // Jump back to original + stolen
    uint8_t *tramp = (uint8_t *)(*orig) + stolen;
    tramp[0] = 0x48; tramp[1] = 0xB8;
    *(void **)(tramp + 2) = src + stolen;
    tramp[10] = 0xFF; tramp[11] = 0xE0;

    VirtualProtect(src, stolen, PAGE_EXECUTE_READWRITE, &old);

    // Overwrite target with jump to hook
    src[0] = 0x48; src[1] = 0xB8;
    *(void **)(src + 2) = hook;
    src[10] = 0xFF; src[11] = 0xE0;

    // If we stole more than 12 bytes, pad the remainder with NOPs
    // so we don't execute partial instructions.
    for (size_t i = 12; i < stolen; i++) {
        src[i] = 0x90;
    }

    VirtualProtect(src, stolen, old, &old);
}

// dll wrapper

#define DLLEXPORT __declspec(dllexport)

static HMODULE real_dll;

static void load_real_dll(void)
{
    if (real_dll)
        return;

    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    lstrcatA(path, "\\version.dll");
    real_dll = LoadLibraryA(path);
}

/* exports */

DLLEXPORT BOOL WINAPI GetFileVersionInfoA(
    LPCSTR a, DWORD b, DWORD c, LPVOID d)
{
    load_real_dll();
    return ((BOOL (WINAPI *)(LPCSTR, DWORD, DWORD, LPVOID))
        GetProcAddress(real_dll, "GetFileVersionInfoA"))(a, b, c, d);
}

DLLEXPORT BOOL WINAPI GetFileVersionInfoW(
    LPCWSTR a, DWORD b, DWORD c, LPVOID d)
{
    load_real_dll();
    return ((BOOL (WINAPI *)(LPCWSTR, DWORD, DWORD, LPVOID))
        GetProcAddress(real_dll, "GetFileVersionInfoW"))(a, b, c, d);
}

DLLEXPORT DWORD WINAPI GetFileVersionInfoSizeA(
    LPCSTR a, LPDWORD b)
{
    load_real_dll();
    return ((DWORD (WINAPI *)(LPCSTR, LPDWORD))
        GetProcAddress(real_dll, "GetFileVersionInfoSizeA"))(a, b);
}

DLLEXPORT DWORD WINAPI GetFileVersionInfoSizeW(
    LPCWSTR a, LPDWORD b)
{
    load_real_dll();
    return ((DWORD (WINAPI *)(LPCWSTR, LPDWORD))
        GetProcAddress(real_dll, "GetFileVersionInfoSizeW"))(a, b);
}
static DWORD WINAPI hook_init_thread(LPVOID param)
{
    /* HINSTANCE hinst = (HINSTANCE)param; */

    log_msg("[hook] DLL loaded\n");

    load_real_dll();

    HMODULE mod;
    while (!(mod = GetModuleHandleA("hammerplusplus_dll.dll")))
        Sleep(100);

    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

    // CStatusBar::SetPaneText -- TODO: refine signature
    uint8_t sig[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18,
        0x57,
        0x41, 0x54,
        0x41, 0x55,
        0x41, 0x56,
        0x41, 0x57,
        0x48, 0x83, 0xEC, 0x40,
    };

    const char *mask = "xxxxxxxxxxxxxxxxxxxxxxx";

    void *addr = find_pattern(
        (uint8_t *)mi.lpBaseOfDll,
        mi.SizeOfImage,
        sig,
        mask
    );

    if (!addr) {
        log_msg("[hook] SetPaneText not found\n");
        return 0;
    }

    orig_SetPaneText = (SetPaneText_t)addr;

    log_msg("[hook] SetPaneText found @ %p\n", addr);

    install_hook(addr,
                 hook_SetPaneText,
                 (void **)&orig_SetPaneText,
                 1);

    log_msg("[hook] hook installed successfully\n");

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE thread;

        DisableThreadLibraryCalls(hinst);

        thread = CreateThread(NULL,
                              0,
                              hook_init_thread,
                              hinst,
                              0,
                              NULL);

        if (thread) {
            CloseHandle(thread);
        } else {
            log_msg("[hook] failed to create init thread (err=%lu)\n",
                    GetLastError());
        }
    }

    return TRUE;
}
