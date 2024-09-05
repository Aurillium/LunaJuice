#pragma once
#include "framework.h"
#include <map>
#include <string>
#include <Windows.h>

// It is highly recommended to change these values in production, or make them dynamic
#define SHARED_SESSION_NAME "LunaShared"
#define SHARED_GLOBAL_NAME "Global\\LunaShared"

#define LUNA_ID_CHARACTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
#define LUNA_MAX_ID_LENGTH 24

namespace LunaAPI {
    // Registry for fast addressing
    typedef unsigned int HookID;
    const HookID MAX_HOOKID = ((HookID)~((HookID)0));

    typedef std::map<std::string, HookID> HookRegistry;
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
        MitigationFlags mitigations;
        LogFlags logs;

        LunaStart();
        LunaStart(LPCSTR id);
        BOOL SetID(LPCSTR id);
    } LunaStart;

    // Settings object to send to change hook settings
    typedef struct _HookConfig {
        HookID hook;
        MitigationFlags mitigations;
        LogFlags logs;
    } HookConfig;

    const MitigationFlags DEFAULT_MITIGATIONS = Mitigate_None;
    const LogFlags DEFAULT_LOGS = Log_All;
}