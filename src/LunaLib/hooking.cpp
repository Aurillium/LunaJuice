#include "pch.h" 
#include <any>
#include <list>
#include <map>
#include <mutex>
#include <tuple>
#include <string>
#include <Windows.h>

#include "debug.h"
#include "hooking.h"
#include "util.h"

#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

std::mutex HOOKS_MUTEX;
std::mutex REGISTRY_MUTEX;
std::mutex NATIVE_HOOKS_MUTEX;

std::vector<LunaHook<AnyFunction>*> NATIVE_HOOKS = std::vector<LunaHook<AnyFunction>*>();

// Store hook instances
std::vector<std::pair<HookType, void*>> HOOK_STORAGE = std::vector<std::pair<HookType, void*>>();
LunaAPI::HookRegistry REGISTRY = LunaAPI::HookRegistry();
// Register: add hook, return ID, send back to client, client records in own registry to address with later

// Create a global map for hook function locations
std::map<std::string, void*> HOOK_LOCATIONS = std::map<std::string, void*>();
LunaAPI::MitigationFlags DEFAULT_MITIGATIONS = LunaAPI::Mitigate_None;
LunaAPI::LogFlags DEFAULT_LOGS = LunaAPI::Log_All;


void* GetFunctionAddress(IN LPCSTR moduleName, IN LPCSTR functionName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL) {
        WRITELINE_DEBUG("Failed to get module handle to " << moduleName << ".");
        return NULL;
    }

    FARPROC originalAddress = GetProcAddress(hModule, functionName);
    if (originalAddress == NULL) {
        WRITELINE_DEBUG("Failed to find function " << functionName << " in " << moduleName << ".");
        return NULL;
    }

    return originalAddress;
}

// Mitigations
template<typename Ret> BOOL Mitigate(LunaAPI::MitigationFlags flags, Ret* ret) {
    if (flags & LunaAPI::Mitigate_BlanketNoPerms) {
        SetLastError(5);
    }
    return FALSE;
}
// Void pointers, hopefully works as a fallback for pointers but probably not
template<> BOOL Mitigate<void*>(LunaAPI::MitigationFlags flags, void** ret) {
    if (flags & LunaAPI::Mitigate_BlanketFakeSuccess) {
        *ret = NULL;
        return TRUE;
    }
    if (flags & LunaAPI::Mitigate_BlanketNoPerms) {
        SetLastError(5); // Permission denied
        *ret = NULL;
        return TRUE;
    }
    return FALSE;
}
template<> BOOL Mitigate<BOOL>(LunaAPI::MitigationFlags flags, BOOL *ret) {
    if (flags & LunaAPI::Mitigate_BlanketFakeSuccess) {
        *ret = TRUE;
        return TRUE;
    }
    if (flags & LunaAPI::Mitigate_BlanketNoPerms) {
        SetLastError(5); // Permission denied
        *ret = FALSE;
        return TRUE;
    }
    return FALSE;
}
template<> BOOL Mitigate<NTSTATUS>(LunaAPI::MitigationFlags flags, NTSTATUS *ret) {
    if (flags & LunaAPI::Mitigate_BlanketFakeSuccess) {
        *ret = 0;
        return TRUE;
    }
    if (flags & LunaAPI::Mitigate_BlanketNoPerms) {
        SetLastError(5); // Permission denied
        // Return STATUS_PRIVILEGE_NOT_HELD (not a defined header but found at https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
        *ret = 0xC0000061;
        return TRUE;
    }
    return FALSE;
}

void SetDefaultMitigations(LunaAPI::MitigationFlags mitigations) {
    DEFAULT_MITIGATIONS = mitigations;
}
void SetDefaultLogs(LunaAPI::LogFlags logEvents) {
    DEFAULT_LOGS = logEvents;
}
LunaAPI::MitigationFlags GetDefaultMitigations() {
    return DEFAULT_MITIGATIONS;
}
LunaAPI::LogFlags GetDefaultLogs() {
    return DEFAULT_LOGS;
}

void AddHookedFunction(std::string key, void* location) {
    HOOK_LOCATIONS[key] = location;
}

BOOL HookInstalled(LPCSTR key) {
    return REGISTRY.find(key) != REGISTRY.end();
}
// Gets the location of the real function, whether hooked or not
void* GetRealFunction(LPCSTR key) {
    // If the key is not in the registry
    if (!HookInstalled(key)) {
        size_t length = strlen(key) + sizeof(CHAR);
        LPSTR target = (LPSTR)calloc(length, sizeof(CHAR));
        if (target == NULL) {
            WRITELINE_DEBUG("Could not allocate memory to store target function name.");
            return NULL;
        }
        memcpy_s(target, length, key, length);
        DWORD i = 0;
        while (target[i] != 0) {
            if (target[i] == '!') {
                // Terminate module name here
                target[i] = 0;
                i++; // This becomes the beginning of the function name
                break;
            }
            i++;
        }
        if (i == 0) {
            WRITELINE_DEBUG("Could not find '!' in key.");
            free(target);
            return NULL;
        }
        LPSTR moduleName = target;
        LPSTR functionName = &target[i]; // Get from after the '!'
        void* address = GetFunctionAddress(moduleName, functionName);
        free(target);
        return address;
    }
    else {
        // Get the trampoline location from registry
        std::pair<HookType, void*> pair = HOOK_STORAGE[REGISTRY[key]];
        if (pair.first != Type_Native) {
            return NULL;
        }
        LunaHook<AnyFunction>* hook = (LunaHook<AnyFunction>*)pair.second;
        return hook->trampoline;
    }
}
void* GetHookFunction(std::string key) {
    if (HOOK_LOCATIONS.find(key) == HOOK_LOCATIONS.end()) {
        WRITELINE_DEBUG("Could not find '" << key << "'.");
        return NULL;
    }
    return HOOK_LOCATIONS[key];
}
