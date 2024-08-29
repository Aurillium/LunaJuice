#include "pch.h"
#include <Windows.h>

#include "debug.h"

#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

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
