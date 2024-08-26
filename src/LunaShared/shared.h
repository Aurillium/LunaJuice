// It is highly recommended to change these values in production, or make them dynamic
#define SHARED_SESSION_NAME "LunaShared"
#define SHARED_GLOBAL_NAME "Global\\LunaShared"

// All variants should come under the same flag
typedef enum _HookFlags {
    Enable_NtReadFile = 1,
    Enable_NtWriteFile = 2,
    Enable_ReadConsole = 4,
    Enable_RtlAdjustPrivilege = 8,
    Enable_OpenProcess = 16,
    Enable_CreateRemoteThread = 32,
    Enable_WriteProcessMemory = 64,
    Enable_ReadProcessMemory = 128,
    Enable_CreateProcess = 256,
    Enable_NtCreateUserProcess = 512
} HookFlags;
typedef enum _MitigationFlags {
    Enable_
} MitigationFlags;

// Used to find the config function
typedef struct _LunaShared {
    DWORD dwOffset = 0;
    HMODULE hModule = NULL;
    LPDWORD lpInit = NULL;
} LunaShared;
// Gets passed from loader to lib for initialisation
typedef struct _LunaStart {
    CHAR id[25];
    HookFlags hooks;
    MitigationFlags mitigations;
} LunaStart;

// General helpers
#define NOT_WHITESPACE(expr) (expr != ' ' && expr != '\t' && expr != '\n' && expr != '\r')
#define IS_WHITESPACE(expr) (expr == ' ' || expr == '\t' || expr == '\n' || expr == '\r')