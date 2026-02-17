#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>

#include <MinHook.h>

#include "wrapper.h"
#include "common.h"
#include "tier0.h"

// status bar ids
#define SBI_SIZE 3

#define SURF_NORMAL 0.7
// an arbitrary cutoff for a very steep ramp that you can somewhat stay on
#define UNSURF_NORMAL 0.28

#define OFFSET_CMAPDOC_MPWORLD 0x166 * 8

#define CMAPATOM_VTABLE_DOTRANSFORM 17

/* CMapEntity / FindEntity offsets */
#define OFFSET_ENT_POS               0x50
#define OFFSET_ENT_CLASSNAME         0x1C8

static SetPaneText_t orig_SetPaneText = NULL;
static EnumChildren_t EnumChildren = NULL;
static SetActiveMapDoc_t orig_SetActiveMapDoc = NULL;
static SetModifiedFlag_t SetModifiedFlag = NULL;
static CMapDoc_UpdateAllViews_t CMapDoc_UpdateAllViews = NULL;

static void *active_map_doc = NULL;
static char *CMapEntityType = NULL;

static void *find_pattern(uint8_t *base, size_t size, const uint8_t *pat, const char *mask) {
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

int find_ent_by_pos(uint8_t *ent, void *param) {
    struct FindEntity_t *find = (struct FindEntity_t *)param;
    float *pos = (float *)(ent + OFFSET_ENT_POS);

    int rx = round(pos[0]);
    int ry = round(pos[1]);
    int rz = round(pos[2]);

    /* log_msg("[hook] ent @ %p %d %d %d\n", ent, rx, ry, rz); */

    /* char *className = "?"; */
    if (rx == find->pos[0] && ry == find->pos[1] && rz == find->pos[2]) {
        find->ent = ent;
        /* char *className = (char *)(ent + OFFSET_ENT_CLASSNAME); */
        /* log_msg("[hook] FOUND %s @ %p %d %d %d\n", className, ent, rx, ry, rz); */
        return FALSE;
        /* return TRUE; */
    }
    return TRUE;
}

void hook_SetActiveMapDoc(void *doc) {
    log_msg("[hook] SetActiveMapDoc %p\n", doc);
    orig_SetActiveMapDoc(doc);
    active_map_doc = doc;
}

int hook_SetPaneText(void *this_, int nIndex, char *lpszNewText, int bUpdate) {
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

static BOOL find_cmapentity_type(uint8_t *base, size_t size) {
    const char *sig = "CMapEntity"; // CMapSolid instead?
    const char *mask = "xxxxxxxxxxx";

    void *addr = find_pattern(
        base,
        size,
        (uint8_t*)sig,
        mask
    );

    if (!addr) {
        log_msg("[hook] CMapEntity type not found\n");
        return FALSE;
    }

    log_msg("[hook] CMapEntity type found @ %p\n", addr);
    CMapEntityType = addr;
    return TRUE;
}

static BOOL find_enumchildren(uint8_t *base, size_t size) {
    uint8_t sig[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,
        0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18,
        0x57,
        0x41, 0x56,
        0x41, 0x57,
        0x48, 0x83, 0xEC, 0x20,
        0x33, 0xDB,
        0x49, 0x8B, 0xE9,
        0x4D, 0x8B, 0xF0,
    };

    const char *mask = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    void *addr = find_pattern(
        base,
        size,
        sig,
        mask
    );

    if (!addr) {
        log_msg("[hook] EnumChildren not found\n");
        return FALSE;
    }

    log_msg("[hook] EnumChildren found @ %p\n", addr);
    EnumChildren = addr;
    return TRUE;
}

static BOOL find_updateallviews(uint8_t *base, size_t size) {
    uint8_t sig[] = {
        0x48, 0x89, 0x5C, 0x24, 0x18,
        0x57,
        0x48, 0x83, 0xEC, 0x30,
        0x48, 0x8B, 0xD9,
        0x8B, 0xFA
    };

    const char *mask = "xxxxxxxxxxxxxxx";

    void *addr = find_pattern(
        base,
        size,
        sig,
        mask
    );

    if (!addr) {
        log_msg("[hook] UpdateAllViews not found\n");
        return FALSE;
    }

    log_msg("[hook] UpdateAllViews found @ %p\n", addr);
    CMapDoc_UpdateAllViews = addr;
    return TRUE;
}

static BOOL find_setmodifiedflag(uint8_t *base, size_t size) {
    uint8_t sig[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08,     // mov    qword ptr [rsp+0x08], rbx
        0x57,                             // push   rdi
        0x48, 0x83, 0xEC, 0x20,           // sub    rsp, 0x20
        0x8B, 0xFA,                       // mov    edi, edx
        0x48, 0x8B, 0xD9,                 // mov    rbx, rcx
        0x85, 0xD2,                       // test   edx, edx
        0x74, 0x6B                        // je     +0x6B
    };

    const char *mask = "xxxxxxxxxxxxxxxxxxx";

    void *addr = find_pattern(
        base,
        size,
        sig,
        mask
    );

    if (!addr) {
        log_msg("[hook] SetModifiedFlag not found\n");
        return FALSE;
    }

    log_msg("[hook] SetModifiedFlag found @ %p\n", addr);
    SetModifiedFlag = addr;
    return TRUE;
}

static BOOL hook_set_pane_text(uint8_t *base, size_t size) {
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
        base,
        size,
        sig,
        mask
    );

    if (!addr) {
        log_msg("[hook] SetPaneText not found\n");
        return FALSE;
    }

    orig_SetPaneText = (SetPaneText_t)addr;
    log_msg("[hook] SetPaneText found @ %p\n", addr);

    if (MH_CreateHook(addr, (LPVOID)hook_SetPaneText, (LPVOID *)&orig_SetPaneText) != MH_OK) {
        log_msg("[hook] SetPaneText MH_CreateHook failed\n");
        return FALSE;
    }

    return TRUE;
}

static BOOL hook_set_active_map_doc(uint8_t *base, size_t size) {
    uint8_t sig[] = {
        0x40, 0x53,
        0x41, 0x56,
        0x48, 0x83, 0xEC, 0x48,
        0x48, 0x8B, 0x1D, 0x39, 0x1D, 0xB7, 0x00,
        0x4C, 0x8B, 0xF1,
    };

    // ISSUE: .text:00000001800D3B78 48 8B 1D 39 1D B7 00                    mov     rbx, cs:qword_180C458B8

    const char *mask = "xxxxxxxxx???xxxx";

    void *addr = find_pattern(
        base,
        size,
        sig,
        mask
    );

    if (!addr) {
        log_msg("[hook] SetActiveMapDoc not found\n");
        return FALSE;
    }

    log_msg("[hook] SetActiveMapDoc found @ %p\n", addr);

    orig_SetActiveMapDoc = (SetActiveMapDoc_t)addr;
    log_msg("[hook] SetActiveMapDoc found @ %p\n", addr);

    if (MH_CreateHook(addr, (LPVOID)hook_SetActiveMapDoc, (LPVOID *)&orig_SetActiveMapDoc) != MH_OK) {
        log_msg("[hook] SetActiveMapDoc MH_CreateHook failed\n");
        return FALSE;
    }

    return TRUE;
}

static void *get_doc_world() {
    if (!active_map_doc) {
        return NULL;
    }

    return *(void**)(active_map_doc + OFFSET_CMAPDOC_MPWORLD);
}

static void move_brush(int *start, int *end) {
    void *world = get_doc_world();
    if (!world || !active_map_doc) {
        return;
    }

    /* const char *CMapSolid = (char*)0x180993858; */
    /* const char *CMapEntity = ADDR_CMAPENTITY_TYPE; */
    struct FindEntity_t find;
    find.pos[0] = start[0];
    find.pos[1] = start[1];
    find.pos[2] = start[2];
    find.ent = NULL;

    EnumChildren(world, find_ent_by_pos, &find, CMapEntityType);
    /* log_msg("[hook] FindEnt = %p\n", find.ent); */

    if (find.ent) {
        void **vtable = *(void***)find.ent;
        CMapEntity_DoTransform_t do_transform = vtable[CMAPATOM_VTABLE_DOTRANSFORM];

        float delta[3];
        mat4 mtx;
        delta[0] = end[0] - start[0];
        delta[1] = end[1] - start[1];
        delta[2] = end[2] - start[2];
        MatrixSetIdentity(&mtx);
        SetTranslation(&mtx, delta);
        /* CMapEntity_DoTransform(find.ent, &mtx); */
        do_transform(find.ent, &mtx);
        log_msg("[hook] moved %p with delta %.1f %.1f %.1f\n", find.ent, delta[0], delta[1], delta[2]);
        SetModifiedFlag(active_map_doc, TRUE);
        // TODO: fix shaderapi crash
        CMapDoc_UpdateAllViews(active_map_doc, MAPVIEW_UPDATE_OBJECTS | MAPVIEW_RENDER_NOW, NULL);
    } else {
        log_msg("[hook] failed to find ent at %d %d %d\n", find.pos[0], find.pos[1], find.pos[2]);
    }
}

static int follow_console_log() {
    // fopen/crt version doesnt work, raw win32 apis work though?
    const char * path = "..\\..\\cstrike\\console.log";
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        log_msg("error opening console.log\n");
        return 1;
    }

    LARGE_INTEGER pos;
    pos.QuadPart = 0;
    SetFilePointerEx(hFile, pos, NULL, FILE_END);
    log_msg("tailing win32\n");
    /* ConLog(mwStatus, "tailing win32\n"); */

    char buffer[1024];
    DWORD bytesRead;

    while (1) {
        if (ReadFile(hFile, buffer, sizeof(buffer)-1, &bytesRead, NULL)) {
            if (bytesRead > 0) {
                buffer[bytesRead] = 0;

                char *line = buffer;
                char *bufend = buffer + bytesRead;

                while (line < bufend) {
                    char *next = strchr(line, '\n');
                    if (next) {
                        *next = '\0';
                    }

                    /* strip trailing carriage return if present */
                    size_t len = strlen(line);
                    if (len > 0 && line[len-1] == '\r') {
                        line[len-1] = '\0';
                    }

                    int x1, y1, z1, x2, y2, z2;
                    if (sscanf(line, "[fatalis-movebrushes] move %d %d %d to %d %d %d",
                           &x1, &y1, &z1, &x2, &y2, &z2) == 6) {

                        int start[3];
                        start[0] = x1;
                        start[1] = y1;
                        start[2] = z1;

                        int end[3];
                        end[0] = x2;
                        end[1] = y2;
                        end[2] = z2;

                        /* log_msg("[hook]-----------------\n[hook] log: %s\n", line); */
                        move_brush(start, end);
                    }

                    if (!next) {
                        break;
                    }
                    line = next + 1;
                }
                /* log_msg("[hook] log2: %s\n", buffer); */
            }
        }

        /* Msg("[hook] tail sleep\n"); */
        /* ConLog(mwStatus, "hook.dll loaded1\n"); */
        /* ConLog(mwError, "hook.dll loaded3\n"); */
        /* ConLog(mwWarning, "hook.dll loaded4\n"); */
        /* Log("hook.dll loaded2\n"); */
        Sleep(100);
    }

    CloseHandle(hFile);
}

static const init_step_t init_steps[] = {
    find_cmapentity_type,
    find_enumchildren,
    find_updateallviews,
    find_setmodifiedflag,

    hook_set_pane_text,
    hook_set_active_map_doc,
};

static DWORD WINAPI hook_init_thread(LPVOID param) {
    log_msg("[hook] DLL loaded\n");

    wrapper();

    HMODULE mod;
    while (!(mod = GetModuleHandleA("hammerplusplus_dll.dll")))
        Sleep(100);

    if (init_tier0()) {
        return 1;
    }

    if (MH_Initialize() != MH_OK) {
        log_msg("[hook] MH_Initialize failed\n");
        return 1;
    }

    MODULEINFO mi;
    GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

    uint8_t *base = (uint8_t *)mi.lpBaseOfDll;
    size_t size = mi.SizeOfImage;

    for (size_t i = 0; i < ARRAY_LEN(init_steps); ++i) {
        if (!init_steps[i](base, size)) {
            return 1;
        }
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        log_msg("[hook] MH_EnableHook failed\n");
        return 0;
    }

    log_msg("[hook] setup successfully\n");

    follow_console_log();

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
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
