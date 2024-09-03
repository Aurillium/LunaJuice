#pragma once
#include "framework.h"
#include <Windows.h>

// It is highly recommended to change these values in production, or make them dynamic
#define SHARED_SESSION_NAME "LunaShared"
#define SHARED_GLOBAL_NAME "Global\\LunaShared"

#define LUNA_ID_CHARACTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
#define LUNA_MAX_ID_LENGTH 24

namespace LunaAPI {
    // All variants should come under the same flag
    typedef enum _HookFlags {
        Hook_None = 0,
        Hook_NtReadFile = 1,
        Hook_NtWriteFile = 2,
        Hook_ReadConsole = 4,
        Hook_RtlAdjustPrivilege = 8,
        Hook_OpenProcess = 16,
        Hook_CreateRemoteThread = 32,
        Hook_CreateRemoteThreadEx = 32,
        Hook_WriteProcessMemory = 64,
        Hook_ReadProcessMemory = 128,
        Hook_CreateProcess = 256,
        Hook_NtCreateUserProcess = 512,
        Hook_CoCreateInstance = 1024,
        Hook_All = 0xFFFFFFFF
    } HookFlags;
    typedef enum _MitigationFlags {
        Mitigate_None = 0,
        Mitigate_BlockEsc = 1,
        Mitigate_BlanketFakeSuccess = 2,
        Mitigate_BlanketNoPerms = 4,
        Mitigate_All = 0xFFFFFFFF
    } MitigationFlags;
    typedef enum _LogFlags {
        Log_None = 0,
        Log_Signature = 1,
        Log_Stdin = 2,
        Log_Stdout = 4,
        Log_Stderr = 8,
        Log_Stdio = 14,  // All stdio
        Log_PrivilegeAdjust = 16,
        Log_SpawnProcess = 32,
        Log_SpoofPPID = 64,
        Log_All = 0xFFFFFFFF
    } LogFlags;
    typedef enum _SecuritySettings {
        // 2 bits
        BlockSimilar = 1,   // Block similar DLLs to LunaLib from loading
        BlockUnsigned = 2,  // Block all unsigned DLLs (and signed LunaLib) from loading
        BlockAll = 3        // Block all DLL loading
    } SecuritySettings;

    inline HookFlags operator|(const HookFlags a, const HookFlags b) {
        return (HookFlags)((int)a | (int)b);
    }
    inline MitigationFlags operator|(const MitigationFlags a, const MitigationFlags b) {
        return (MitigationFlags)((int)a | (int)b);
    }

    // Used to find the config function
    typedef struct LunaShared {
        DWORD dwOffset = 0;
        HMODULE hModule = NULL;
        LPDWORD lpInit = NULL;
    } LunaShared;
    // Gets passed from loader to lib for initialisation
    typedef struct LUNA_API LunaStart {
        CHAR id[LUNA_MAX_ID_LENGTH + 1];
        HookFlags hooks;
        MitigationFlags mitigations;
        LogFlags logs;

        LunaStart();
        LunaStart(LPCSTR id);
        BOOL SetID(LPCSTR id);
    } LunaStart;

    // Settings object to send to change hook settings
    typedef struct HooksConfig {
        HookFlags hooks;
        MitigationFlags mitigations;
        LogFlags logs;
    };
    typedef struct HooksEnabled {
        HookFlags hooks;
        bool enabled;
    };

    // Defaults
    const HookFlags DEFAULT_HOOKS =
        Hook_NtReadFile |
        Hook_ReadConsole |
        Hook_RtlAdjustPrivilege |
        Hook_NtCreateUserProcess |
        Hook_CoCreateInstance
        ;
    const MitigationFlags DEFAULT_MITIGATIONS = Mitigate_None;
    const LogFlags DEFAULT_LOGS = Log_All;
}