#define HOOK_DEBUG 1

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

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

#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

#define MAPVIEW_UPDATE_OBJECTS 0x001
#define MAPVIEW_RENDER_NOW 0x800

typedef BOOL (*init_step_t)(uint8_t *base, size_t size);

typedef float mat4[4][4];
typedef int (*SetPaneText_t)(void *this_, int nIndex, char *lpszNewText, int bUpdate);
typedef int (*EnumChildrenCallback)(uint8_t *ent, void *param);
typedef int (*EnumChildren_t)(void *this_, EnumChildrenCallback cb, void *param, const char *type);
typedef void (*SetActiveMapDoc_t)(void *doc);
typedef void (*SetModifiedFlag_t)(void *this_, BOOL bModified);
typedef void (*CMapEntity_DoTransform_t)(void *this_, mat4 *mtx);
typedef void (*CMapDoc_UpdateAllViews_t)(void *this_, int nFlags, void *ub);

struct FindEntity_t {
    int pos[3];
    void *ent;
};

inline void MatrixSetIdentity(mat4* dst) {
    (*dst)[0][0] = 1.0f; (*dst)[0][1] = 0.0f; (*dst)[0][2] = 0.0f; (*dst)[0][3] = 0.0f;
    (*dst)[1][0] = 0.0f; (*dst)[1][1] = 1.0f; (*dst)[1][2] = 0.0f; (*dst)[1][3] = 0.0f;
    (*dst)[2][0] = 0.0f; (*dst)[2][1] = 0.0f; (*dst)[2][2] = 1.0f; (*dst)[2][3] = 0.0f;
    (*dst)[3][0] = 0.0f; (*dst)[3][1] = 0.0f; (*dst)[3][2] = 0.0f; (*dst)[3][3] = 1.0f;
}

inline void SetTranslation(mat4* mat, const float* trans) {
    (*mat)[0][3] = trans[0];
    (*mat)[1][3] = trans[1];
    (*mat)[2][3] = trans[2];
}
