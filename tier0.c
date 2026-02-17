#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "tier0.h"
#include "common.h"

Msg_t Msg = NULL;
ConLog_t ConLog = NULL;
Error_t Error = NULL;
Log_t Log = NULL;

int init_tier0(void)
{
    HMODULE tier0 = GetModuleHandleA("tier0.dll");
    if (!tier0) {
        log_msg("[hook] tier0.dll not loaded?\n");
        return 1;
    }

    Msg = (Msg_t)GetProcAddress(tier0, "Msg");
    if (!Msg) {
        log_msg("[hook] Msg not found in tier0?\n");
        return 1;
    }

    ConLog = (ConLog_t)GetProcAddress(tier0, "ConLog");
    if (!ConLog) {
        log_msg("[hook] ConLog not found in tier0?\n");
        return 1;
    }

    Error = (Error_t)GetProcAddress(tier0, "Error");
    if (!Error) {
        log_msg("[hook] Error not found in tier0?\n");
        return 1;
    }

    Log = (Log_t)GetProcAddress(tier0, "Log");
    if (!Log) {
        log_msg("[hook] Log not found in tier0?\n");
        return 1;
    }

    return 0;
}
