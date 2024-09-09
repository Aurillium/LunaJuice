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
    // If these get over 32 bits, change the operators
    typedef enum _MitigationFlags {
        Mitigate_None = 0,
        Mitigate_BlockEsc = 1 << 0,
        Mitigate_BlanketFakeSuccess = 1 << 1,
        Mitigate_BlanketNoPerms = 1 << 2,
        Mitigate_All = 0xFFFFFFFF
    } MitigationFlags;
    typedef enum _LogFlags {
        Log_None = 0,
        Log_Signature = 1 << 0,
        Log_Stdin = 1 << 1,
        Log_Stdout = 1 << 2,
        Log_Stderr = 1 << 3,
        Log_Stdio = 14,  // All stdio
        Log_PrivilegeAdjust = 1 << 4,
        Log_SpawnProcess = 1 << 5,
        Log_SpoofPPID = 1 << 6,
        Log_All = 0xFFFFFFFF
    } LogFlags;
    typedef enum _SecuritySettings {
        // 2 bits
        Sec_BlockSimilar = 1,   // Block similar DLLs to LunaLib from loading (hash, name)
        Sec_BlockUnsigned = 2,  // Block all unsigned DLLs (and signed LunaLib) from loading
        Sec_BlockAll = 3        // Block all DLL loading
    } SecuritySettings;

    // OR and AND operations for flags
    inline MitigationFlags operator|(const MitigationFlags a, const MitigationFlags b) {
        return (MitigationFlags)((unsigned int)a | (unsigned int)b);
    }
    inline LogFlags operator|(const LogFlags a, const LogFlags b) {
        return (LogFlags)((unsigned int)a | (unsigned int)b);
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

    typedef struct _Policy {
        MitigationFlags mitigations;
        LogFlags logs;
        SecuritySettings security;
    } Policy;

    const MitigationFlags DEFAULT_MITIGATIONS = Mitigate_None;
    const LogFlags DEFAULT_LOGS = Log_All;
    const SecuritySettings DEFAULT_SECURITY = Sec_BlockSimilar;

    // This is technically a destructor, but this is also technically an int
    // Choose your technicality
    inline MitigationFlags operator~(const MitigationFlags a) {
        return (MitigationFlags)(~(unsigned int)a);
    }
    inline LogFlags operator~(const LogFlags a) {
        return (LogFlags)(~(unsigned int)a);
    }
    inline MitigationFlags operator&(const MitigationFlags a, const MitigationFlags b) {
        return (MitigationFlags)((unsigned int)a & (unsigned int)b);
    }
    inline LogFlags operator&(const LogFlags a, const LogFlags b) {
        return (LogFlags)((unsigned int)a & (unsigned int)b);
    }
    inline MitigationFlags operator^(const MitigationFlags a, const MitigationFlags b) {
        return (MitigationFlags)((unsigned int)a ^ (unsigned int)b);
    }
    inline LogFlags operator^(const LogFlags a, const LogFlags b) {
        return (LogFlags)((unsigned int)a ^ (unsigned int)b);
    }

    static MitigationFlags& operator |=(MitigationFlags& a, MitigationFlags b) {
        a = a | b;
        return a;
    }
    static LogFlags& operator |=(LogFlags& a, LogFlags b) {
        a = a | b;
        return a;
    }
    static MitigationFlags& operator &=(MitigationFlags& a, MitigationFlags b) {
        a = a & b;
        return a;
    }
    static LogFlags& operator &=(LogFlags& a, LogFlags b) {
        a = a & b;
        return a;
    }
}