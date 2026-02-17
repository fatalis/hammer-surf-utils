#ifndef TIER0_H
#define TIER0_H

enum MWMSGTYPE {
    mwStatus,
    mwError,
    mwWarning
};

typedef void (*Msg_t)(const char* fmt, ...);
typedef void (*ConLog_t)(int type, const char* fmt, ...);
typedef void (*Error_t)(const char* fmt, ...);
typedef void (*Log_t)(const char* fmt, ...);

extern Msg_t Msg;
extern ConLog_t ConLog;
extern Error_t Error;
extern Log_t Log;

/* Returns 0 on success, 1 on failure. */
int init_tier0(void);

#endif
