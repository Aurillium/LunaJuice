#include "pch.h"
#include <map>
#include <Windows.h>

#include "debug.h"
#include "hooking.h"

#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

// Create a global map for hooks
std::map<LPCSTR, LunaHook*> GLOBAL_HOOKS = std::map<LPCSTR, LunaHook*>();
LunaAPI::MitigationFlags DEFAULT_MITIGATIONS = LunaAPI::Mitigate_None;
LunaAPI::LogFlags DEFAULT_LOGS = LunaAPI::Log_All;

PLH::NatDetour* InstallPolyHook(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL) {
        WRITE_DEBUG("Failed to get module handle, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return NULL;
    }

    FARPROC originalAddress = GetProcAddress(hModule, functionName);
    if (originalAddress == NULL) {
        WRITE_DEBUG("Could not find target function, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return NULL;
    }

    PLH::NatDetour* detour = new PLH::NatDetour((uint64_t)originalAddress, (uint64_t)hookFunction, (uint64_t*)originalFunction);
    return detour;
}

LunaHook::LunaHook(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, void** trampolineAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log) {
    hook = InstallPolyHook(moduleName, functionName, hookAddress, trampolineAddress);
    if (hook == NULL) {
        WRITELINE_DEBUG("Could not create LunaHook for " << functionName << " of " << moduleName << ".");
    }
    mitigations = mitigate;
    logEvents = log;

    // Try add this function to global hooks
    size_t modLength = strlen(moduleName);
    size_t funcLength = strlen(functionName);
    size_t bufferSize = modLength + funcLength + 2 + 10;
    LPSTR key = (LPSTR)calloc(bufferSize, sizeof(CHAR));
    if (key == NULL) {
        WRITELINE_DEBUG("Could not allocate memory for key in hooks hashmap.");
        return;
    }
    memcpy_s(key, bufferSize * sizeof(CHAR), moduleName, modLength * sizeof(CHAR));
    key[modLength] = '!';
    memcpy_s(key + (modLength + 1) * sizeof(CHAR), bufferSize * sizeof(CHAR), functionName, funcLength * sizeof(CHAR));
    // Add to global hooks map
    GLOBAL_HOOKS[key] = this;

    hook->hook();

    registerSuccess = TRUE;
    WRITELINE_DEBUG("Successfully hooked '" << key << "'!");
}
LunaHook::~LunaHook() {
    // Clean up
    delete hook;
}
BOOL LunaHook::GetStatus() {
    return hook->isHooked();
}
BOOL LunaHook::Enable() {
    return hook->hook();
}
BOOL LunaHook::Disable() {
    return hook->unHook();
}

LunaHook* GetGlobalHook(LPCSTR key) {
    return GLOBAL_HOOKS[key];
}
BOOL LunaHook::Register(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, void** trampolineAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log) {
    // Try create and register a hook
    LunaHook* hook = new LunaHook(moduleName, functionName, hookAddress, trampolineAddress, mitigate, log);
    if (hook->registerSuccess) {
        return TRUE;
    }
    // If it fails, clean up
    delete hook;
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