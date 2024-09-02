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
        NoHooks = 0,
        Enable_NtReadFile = 1,
        Enable_NtWriteFile = 2,
        Enable_ReadConsole = 4,
        Enable_RtlAdjustPrivilege = 8,
        Enable_OpenProcess = 16,
        Enable_CreateRemoteThread = 32,
        Enable_WriteProcessMemory = 64,
        Enable_ReadProcessMemory = 128,
        Enable_CreateProcess = 256,
        Enable_NtCreateUserProcess = 512,
        Enable_CoCreateInstance = 1024
    } HookFlags;
    typedef enum _MitigationFlags {
        NoMitigations = 0,
        Enable_BlockEsc = 1,
        Enable_BlanketFakeSuccess = 2,
        Enable_BlanketNoPerms = 4
    } MitigationFlags;

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

        LunaStart();
        LunaStart(LPCSTR id);
        BOOL SetID(LPCSTR id);
    } LunaStart;

    // Defaults
    const HookFlags DEFAULT_HOOKS =
        Enable_NtReadFile |
        Enable_ReadConsole |
        Enable_RtlAdjustPrivilege |
        Enable_NtCreateUserProcess |
        Enable_CoCreateInstance
        ;
}