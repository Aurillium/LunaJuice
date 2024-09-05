#include "pch.h" 
#include <any>
#include <list>
#include <map>
#include <Windows.h>

#include "debug.h"
#include "hooking.h"
#include "util.h"

#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

// Store hook instances
std::vector<LunaHook<std::any(*)(std::any)>*> HOOK_STORAGE = std::vector<LunaHook<std::any(*)(std::any)>*>();
LunaAPI::HookRegistry REGISTRY = LunaAPI::HookRegistry();
// Register: add hook, return ID, send back to client, client records in own registry to address with later

// Create a global map for hook function locations
std::map<LPCSTR, void*> HOOK_LOCATIONS = std::map<LPCSTR, void*>();
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

// Run callbacks
template<typename Ret, typename... Args> Ret LunaHook<Ret(*)(Args...)>::Callbacks(Args... args) {
    Ret mitigationReturn;
    // If mitigations returned a value, return it without running the hook.
    if (Mitigate(this->mitigations, &mitigationReturn)) {
        return mitigationReturn;
    }
    
    // Call the hook
    return this->hookAddr(args...);
}

template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>::LunaHook(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log, LPCSTR sig) {
    registerSuccess = FALSE;
    signature = sig;

    void* originalAddress = GetFunctionAddress(moduleName, functionName);
    if (originalAddress == NULL) {
        WRITELINE_DEBUG("Could not find " << moduleName << "!" << functionName << ", will not be able to hook.");
        return;
    }
    hook = new PLH::NatDetour((uint64_t)originalAddress, (uint64_t)hookAddress, &(uint64_t)this->trampoline);
    if (hook == NULL) {
        WRITELINE_DEBUG("Could not create LunaHook for " << moduleName << "!" << functionName << ".");
        return;
    }
    mitigations = mitigate;
    logEvents = log;

    hook->hook();

    registerSuccess = TRUE;
    WRITELINE_DEBUG("Successfully hooked '" << functionName << " of " << moduleName << "'!");
}
template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>::~LunaHook() {
    // Clean up
    delete hook;
}
template<typename Ret, typename... Args> BOOL LunaHook<Ret(*)(Args...)>::GetStatus() {
    return hook->isHooked();
}
template<typename Ret, typename... Args> BOOL LunaHook<Ret(*)(Args...)>::Enable() {
    return hook->hook();
}
template<typename Ret, typename... Args> BOOL LunaHook<Ret(*)(Args...)>::Disable() {
    return hook->unHook();
}

template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>* GetGlobalHook(LPCSTR key) {
    return HOOK_STORAGE[REGISTRY[key]];
}
template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>* GetGlobalHook(LunaAPI::HookID key) {
    return HOOK_STORAGE[key];
}

template<typename Ret, typename... Args> LunaAPI::HookID LunaHook<Ret(*)(Args...)>::Register(LPCSTR identifier, void* hookAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log, LunaHook* hook) {
    size_t length = strlen(identifier) + sizeof(CHAR);
    LPSTR target = (LPSTR)malloc(length);
    if (target == NULL) {
        WRITELINE_DEBUG("Could not allocate memory to store target function name.");
        return NULL;
    }
    memcpy_s(target, length, identifier, length);
    DWORD i = 0;
    while (target[i] == 0) {
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
    
    LunaHook newHook = LunaHook(moduleName, functionName, hookAddress, mitigate, log);
    free(target); // module and function names have been used now
    if (!newHook->registerSuccess) {
        // Clean up and exit on fail
        delete newHook;
        // This should be a maximum int, as HookID is unsigned
        return -1;
    }
    if (hook != NULL) {
        *hook = newHook;
    }
    LunaAPI::HookID id = HOOK_STORAGE.size();
    HOOK_STORAGE.push_back(newHook);

    // Add to registry
    REGISTRY[identifier] = id;

    return id;
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

void AddHookedFunction(LPCSTR key, void* location) {
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
        LPSTR target = (LPSTR)malloc(length);
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
        LunaHook<std::any(*)(std::any)>* hook = HOOK_STORAGE[REGISTRY[key]];
        return hook->trampoline;
    }
}
void* GetHookFunction(LPCSTR key) {
    if (HOOK_LOCATIONS.find(key) == HOOK_LOCATIONS.end()) {
        return NULL;
    }
    return HOOK_LOCATIONS[key];
}