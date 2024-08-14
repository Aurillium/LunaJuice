// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
// Kernel and advapi32
#include <Windows.h>
#include <securitybaseapi.h>
// Others
#include <iostream>

#include <dbghelp.h>

#include "hooks.h"
#include "debug.h"
#include "events.h"

#include "include/capstone/capstone.h"

EXTERN_HOOK(NtReadFile);

// Debug logs
void LogLine(const char* message) {
#if _DEBUG
    std::cerr << message << std::endl;
#endif
}
void Log(const char* message) {
#if _DEBUG
    std::cerr << message;
#endif
}

// This may need improvement, unsure on stability
bool InstallHookV2(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction) {
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL) {
        LogLine("Failed to get module handle");
        return false;
    }

    // Get a handle on program imports
    ULONG size;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    // We need this to access DLL info
    if (importDesc == NULL) {
        LogLine("Failed to get import descriptor");
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
                    Log("Successfully hooked ");
                    LogLine(functionName);
                    return true;
                }
                thunk++;
            }
        }
        importDesc++;
    }

    // :(
    Log("Failed to hook ");
    LogLine(functionName);
    return false;
}


// Function to determine the prologue length
size_t GetFunctionPrologueLength(IN void* functionAddress) {
    csh handle;
    cs_insn* insn;
    size_t count;
    size_t prologueLength = 0;
    const size_t MAX_INSTRUCTIONS = 14; // Limit to prevent excessive disassembly
    const size_t MIN_BYTES = 14;

    // Initialize Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return 0;
        // TODO: Error handling
    }

    // Disassemble the function
    count = cs_disasm(handle, (const uint8_t*)functionAddress, 64, (uint64_t)functionAddress, MAX_INSTRUCTIONS, &insn);
    if (count > 0) {
        // Determine the prologue length (commonly includes setup instructions like PUSH, MOV, etc.)
        // Example condition: terminate on a specific instruction or byte pattern
        for (size_t i = 0; i < count; i++) {
            prologueLength += insn[i].size;
            // Exit early if we have enough bytes to create trampoline
            if (prologueLength >= MIN_BYTES) {
                break;
            }
        }
        cs_free(insn, count);
    }
    cs_close(&handle);

    return prologueLength;
}

// Trampoline hooking
// More advanced than IAT but more stable (in theory)
bool InstallHookV3(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction) {
    // Get the DLL the function is from
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL) {
        Log("Failed to get module handle, failed to hook ");
        LogLine(functionName);
        return false;
    }

    // Get target function address
    void* targetFunctionAddress = GetProcAddress(hModule, functionName);
    if (targetFunctionAddress == NULL) {
        Log("Could not find target function, failed to hook ");
        LogLine(functionName);
        return false;
    }

    // Set up trampoline
    size_t prologueLength = GetFunctionPrologueLength(targetFunctionAddress);
    void* trampoline = VirtualAlloc(NULL, prologueLength + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (trampoline == NULL) {
        Log("Could not allocate trampoline, failed to hook ");
        LogLine(functionName);
        return false;
    }
    // Copy first 14 bytes of function into beginning of trampoline
    memcpy(trampoline, targetFunctionAddress, prologueLength);

    // Address of after the first 14 bytes (these are in trampoline)
    uintptr_t trampolineJmpBackAddr = (uintptr_t)targetFunctionAddress + 14;
    // Add the jump after original first 14 bytes
    *(BYTE*)((BYTE*)trampoline + prologueLength) = 0xFF;            // jmp setup
    *(BYTE*)((BYTE*)trampoline + prologueLength + 1) = 0x25;
    *(DWORD*)((BYTE*)trampoline + prologueLength + 2) = 0x00000000;     // end jmp setup
    *(uintptr_t*)((BYTE*)trampoline + prologueLength + 6) = trampolineJmpBackAddr;

    // Overwrite memory protection so we can write jump to hook
    DWORD oldProtect;
    if (!VirtualProtect(targetFunctionAddress, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("Could change memory protection, failed to hook ");
        LogLine(functionName);
        return false;
    }

    // Get address of hook
    uintptr_t hookFuncAddr = (uintptr_t)hookFunction;
    // Write the jump towards hook function where the first 14 bytes used to be
    *(BYTE*)targetFunctionAddress = 0x48;                 // mov rax, hookfunc
    *(BYTE*)((BYTE*)targetFunctionAddress + 1) = 0xB8;
    *(uintptr_t*)((BYTE*)targetFunctionAddress + 2) = hookFuncAddr;
    *(BYTE*)((BYTE*)targetFunctionAddress + 10) = 0xFF;   // jmp rax
    *(BYTE*)((BYTE*)targetFunctionAddress + 11) = 0xE0;

    // Rewrite old protections
    if (!VirtualProtect(targetFunctionAddress, 14, oldProtect, &oldProtect)) {
        Log("Could restore memory protection, failed to hook ");
        LogLine(functionName);
        return false;
    }

    // Send trampoline back as the original function
    *originalFunction = trampoline;

#if _DEBUG
    // Debug info
    // NtReadFile is an example and function of interest
    std::cout << "----------------------" << std::endl;
    std::cout << "Function:             " << functionName << std::endl;
    std::cout << "Hook function:        " << hookFunction << std::endl;
    std::cout << "Original function:    " << *originalFunction << std::endl;
    std::cout << "Trampoline address:   " << trampoline << std::endl;
    std::cout << "Real NtReadFile:      " << (void*)Real_NtReadFile << std::endl;
    std::cout << "Trampoline[20...]:    " << (void*)*(uintptr_t*)((BYTE*)trampoline + 20) << std::endl;
    std::cout << "Target function addr: " << targetFunctionAddress << std::endl;
    std::cout << "First jmp to:         " << (void*)*(uintptr_t*)((BYTE*)targetFunctionAddress + 2) << std::endl;
    std::cout << "----------------------" << std::endl;
#endif

    // Real equals the target address, should equal trampoline -- this is because global variable is not changed (why?)

    Log("Successfully hooked ");
    LogLine(functionName);
}



// Install the hooks
void InstallHooks() {
#if _DEBUG
    EXTERN_HOOK(MessageBoxA);
    QUICK_HOOK("user32.dll", MessageBoxA);
#endif
    // Testing for now
    EXTERN_HOOK(RtlAdjustPrivilege);
    //EXTERN_HOOK(NtReadFile);
    QUICK_HOOK("ntdll.dll", RtlAdjustPrivilege);

    //EXTERN_HOOK(NtWriteFile);
    QUICK_HOOK_V3("ntdll.dll", NtReadFile);
    //QUICK_HOOK_V3("ntdll.dll", NtWriteFile);

    // Privilege adjust
    EXTERN_HOOK(AdjustTokenPrivileges);
    EXTERN_HOOK(ZwAdjustPrivilegesToken);
    EXTERN_HOOK(NtAdjustPrivilegesToken);
    QUICK_HOOK("kernelbase.dll", AdjustTokenPrivileges);
    QUICK_HOOK("ntdll.dll", ZwAdjustPrivilegesToken);
    QUICK_HOOK("ntdll.dll", NtAdjustPrivilegesToken);

    // Remote processes
    EXTERN_HOOK(OpenProcess);
    EXTERN_HOOK(CreateRemoteThread);
    EXTERN_HOOK(CreateRemoteThreadEx);
    EXTERN_HOOK(WriteProcessMemory);
    EXTERN_HOOK(ReadProcessMemory);
    QUICK_HOOK("kernel32.dll", OpenProcess);
    QUICK_HOOK("kernel32.dll", CreateRemoteThread);
    QUICK_HOOK("kernel32.dll", CreateRemoteThreadEx);
    QUICK_HOOK("kernel32.dll", WriteProcessMemory);
    QUICK_HOOK("kernel32.dll", ReadProcessMemory);

    // Process start
    EXTERN_HOOK(CreateProcessW);
    EXTERN_HOOK(CreateProcessA);
    QUICK_HOOK("kernel32.dll", CreateProcessW);
    QUICK_HOOK("kernel32.dll", CreateProcessA);

    //QUICK_HOOK("msvcrt.dll", fgets);
    //QUICK_HOOK("msvcrt.dll", fgetws);
    //QUICK_HOOK("msvcrt.dll", _read);

    std::cout << (void*)Real_NtReadFile << std::endl;
}

// This code is run on injection
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LogLine("Attached to process");
        OpenLogger();
        LogLine("Started logger!");
        InstallHooks();
        LogLine("Installed hooks!");
        break;
    case DLL_THREAD_ATTACH:
        // These logs are quite verbose, so commented out even for testing by default
        //LogLine("Attached to thread");
        break;
    case DLL_THREAD_DETACH:
        //LogLine("Detached from thread");
        break;
    case DLL_PROCESS_DETACH:
        LogLine("Detaching from process");
        CloseLogger();
        LogLine("Closed logger!");
        break;
    }
    return TRUE;
}
