#include "pch.h"
#include <dbghelp.h>
#include <Windows.h>

#include "debug.h"
#include "hooking.h"

// This may need improvement, unsure on stability
BOOL InstallHookV2(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction) {
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL) {
        WRITELINE_DEBUG("Failed to get module handle");
        return false;
    }

    // Get a handle on program imports
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    // We need this to access DLL info
    if (importDesc == NULL) {
        WRITELINE_DEBUG("Failed to get import descriptor");
        return false;
    }

    // Loop through each import
    while (importDesc->Name) {
        // Construct the module name
        const char* modName = (const char*)((BYTE*)hModule + importDesc->Name);
        // Check if we have the library we want to hook into
        // This is case insensitive
        if (_stricmp(modName, moduleName) == 0) {
            // ?????????
            // https://stackoverflow.com/questions/2641489/what-is-a-thunk
            // This is where the magic happens
            // Unfortunately, I do not fully understand the magic yet
            // Here is where we find our function though
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            while (thunk->u1.Function) {
                FARPROC* pfn = (FARPROC*)&thunk->u1.Function;
                FARPROC fn = (FARPROC)GetProcAddress(GetModuleHandleA(moduleName), functionName);

                // Is this our function?
                if (fn == (FARPROC)*pfn) {
                    // Now we hook

                    // Unprotect the memory containing the function address and save the old protection
                    DWORD oldProtect;
                    VirtualProtect(pfn, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect);

                    // Save original
                    *originalFunction = *pfn;
                    // Set function address to our function
                    *pfn = (FARPROC)hookFunction;
                    // Reapply page protection
                    VirtualProtect(pfn, sizeof(FARPROC), oldProtect, &oldProtect);

                    // Let the user know we succeeded
                    WRITE_DEBUG("Successfully hooked ");
                    WRITELINE_DEBUG(functionName);
                    return true;
                }
                thunk++;
            }
        }
        importDesc++;
    }

    // :(
    WRITE_DEBUG("Failed to hook ");
    WRITELINE_DEBUG(functionName);
    return false;
}