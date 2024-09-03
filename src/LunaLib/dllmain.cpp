// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
// Kernel and advapi32
#include <Windows.h>
#include <securitybaseapi.h>
// Others
#include <iostream>

#include "debug.h"
#include "events.h"
#include "hooks.h"
#include "mitigations.h"
#include "server.h"
#include "util.h"

#include "shared_util.h"

#include "Config.h"

#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

static HANDLE hMapFile;
static LPVOID lpMemFile;

EXTERN_HOOK(NtReadFile);
EXTERN_HOOK(NtWriteFile);
EXTERN_HOOK(ReadConsoleA);
EXTERN_HOOK(ReadConsoleW);
EXTERN_HOOK(RtlAdjustPrivilege);
EXTERN_HOOK(OpenProcess);
EXTERN_HOOK(CreateRemoteThread);
EXTERN_HOOK(CreateRemoteThreadEx);
EXTERN_HOOK(WriteProcessMemory);
EXTERN_HOOK(ReadProcessMemory);
EXTERN_HOOK(CreateProcessW);
EXTERN_HOOK(CreateProcessA);
EXTERN_HOOK(NtCreateUserProcess);
EXTERN_HOOK(CoCreateInstance);

// Install the hooks
void InstallHooks(LunaAPI::HookFlags flags) {
#if _DEBUG
    EXTERN_HOOK(MessageBoxA);
    QUICK_HOOK("user32.dll", MessageBoxA);
#endif

    // File read/write
    if (flags & LunaAPI::Enable_NtReadFile) {
        QUICK_HOOK("ntdll.dll", NtReadFile);
    }
    if (flags & LunaAPI::Enable_NtWriteFile) {
        QUICK_HOOK("ntdll.dll", NtWriteFile);
    }
    // Console read
    if (flags & LunaAPI::Enable_ReadConsole) {
        QUICK_HOOK("kernel32.dll", ReadConsoleA);
        QUICK_HOOK("kernel32.dll", ReadConsoleW);
    }
    
    if (flags & LunaAPI::Enable_RtlAdjustPrivilege) {
        QUICK_HOOK("ntdll.dll", RtlAdjustPrivilege);
    }

    // Remote processes
    if (flags & LunaAPI::Enable_OpenProcess) {
        QUICK_HOOK("kernel32.dll", OpenProcess);
    }
    if (flags & LunaAPI::Enable_CreateRemoteThread) {
        QUICK_HOOK("kernel32.dll", CreateRemoteThread);
        QUICK_HOOK("kernel32.dll", CreateRemoteThreadEx);
    }
    if (flags & LunaAPI::Enable_WriteProcessMemory) {
        QUICK_HOOK("kernel32.dll", WriteProcessMemory);
    }
    if (flags & LunaAPI::Enable_ReadProcessMemory) {
        QUICK_HOOK("kernel32.dll", ReadProcessMemory);
    }
    
    // Process start
    if (flags & LunaAPI::Enable_CreateProcess) {
        QUICK_HOOK("kernel32.dll", CreateProcessW);
        QUICK_HOOK("kernel32.dll", CreateProcessA);
    }
    if (flags & LunaAPI::Enable_NtCreateUserProcess) {
        QUICK_HOOK("ntdll.dll", NtCreateUserProcess);
    }

    if (flags & LunaAPI::Enable_CoCreateInstance) {
        QUICK_HOOK("ole32.dll", CoCreateInstance);
    }
}

BOOL CloseShare() {
    if (hMapFile != NULL) {
        UnmapViewOfFile(lpMemFile);
        CloseHandle(hMapFile);
        return TRUE;
    }
    return FALSE;
}



#include "include/v8/v8.h"
#include <polyhook2/IHook.hpp>
#include <polyhook2/Detour/NatDetour.hpp>

#include "events.h"

typedef v8::MaybeLocal<v8::Value>(*V8CALL)(v8::Local<v8::Context>, v8::Local<v8::Value>, int, v8::Local<v8::Value>[]);
V8CALL Real_HookedCall = NULL;

v8::MaybeLocal<v8::Value> HookedCall(v8::Local<v8::Context> context,
    v8::Local<v8::Value> recv, int argc,
    v8::Local<v8::Value> argv[]) {

    LogFunctionCall("V8 Function Call");
    WRITELINE_DEBUG("We are in a V8 function call.");
    MessageBoxA(NULL, "Hello", "yay woo", 0);

    return Real_HookedCall(context, recv, argc, argv);
}

// Waits for a function call, then uses hooks to inject JavaScript code
// TODO: target subprocesses that import chrome_100_percent.pak?
//       Is v8_context_snapshot.bin a sign?
//       - Not in some subprocesses
//         - These still die on injection
// - Discord runs without sandbox, meaning the buffer overruns aren't from that
// - ASARs and plain JS not included as modules
//   - When .node modules included, JavaScript is probably used (potential indicator)
// - Injection succeeds but sends no events on .node processes (is this the JavaScript executor?)
//   - Potentially the other processes with chrome_.00_percent\.pak are renderers, which means can't import libraries
// - Process containing Cookies and some data does not send messageboxes to desktop (probably hidden somewhere)
BOOL JavaScriptHook() {
    WRITELINE_DEBUG("JS Hook start");

    //public: class v8::MaybeLocal<class v8::Value> __cdecl v8::Function::Call(class v8::Local<class v8::Context>, class v8::Local<class v8::Value>, int, class v8::Local<class v8::Value> *__ptr64 const) __ptr64

    // According to Edge, a buffer overrun contributes to the injection problem
    // But no code from the DLL is being run due to this

    // Gives us the module
    HANDLE hProcess = GetCurrentProcess();
    if (hProcess == NULL) {
        WRITELINE_DEBUG("Could not open self.");
        return FALSE;
    }

    // Get main module, if this is an Electron app it will export addresses of important functions
    HMODULE hModule = GetMainModuleHandle(hProcess);
    if (hModule == NULL) {
        WRITELINE_DEBUG("Could not get main module: " << GetLastError());
        return FALSE;
    }

    // Find the function that runs on JS function calls
    FARPROC originalAddress = GetProcAddress(hModule, "?Call@Function@v8@@QEAA?AV?$MaybeLocal@VValue@v8@@@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@HQEAV52@@Z");
    if (originalAddress == NULL) {
        WRITELINE_DEBUG("Could not get function address: " << GetLastError());
        return FALSE;
    }

    WRITELINE_DEBUG(originalAddress);
    WRITELINE_DEBUG("Attempting to hook...");

    PLH::NatDetour* detour = new PLH::NatDetour((uint64_t)originalAddress, (uint64_t)HookedCall, (uint64_t*)&Real_HookedCall);
    WRITELINE_DEBUG("Prepared, doing it...");
    //detour->hook();
    WRITELINE_DEBUG("Done!");

    MessageBoxA(NULL, "Hello", "Survided", 0);

    WRITELINE_DEBUG("JS Hook end");
    return FALSE;
}

BOOL LoadConfig(LunaAPI::LunaStart config) {
    // Connect to named mutex for further communication

    WRITELINE_DEBUG("Hello, my name is " << config.id << "!");

    // Initialise hooks
    InstallHooks(config.hooks);
    SetMitigations(config.mitigations);
    WRITELINE_DEBUG("Installed hooks!");

    JavaScriptHook();

    CloseShare();
    
    // Start the RPC server
    HANDLE hThread = CreateThread(
        NULL,                               // Default security attributes
        0,                                  // Default stack size
        (LPTHREAD_START_ROUTINE)BeginPipe,  // Thread function
        &config.id,                         // Thread function arguments
        0,                                  // Default creation flags
        NULL);                              // No thread identifier needed

    if (hThread == NULL) {
        WRITELINE_DEBUG("Could not create thread.");
        return FALSE;
    }

    CloseHandle(hThread);

    return TRUE;
}


// Set up and populate shared memory for init
BOOL InitShare(HMODULE hModule) {
    LunaAPI::LunaShared shared;

    // Get a handle to our file map
    hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_GLOBAL_NAME);
    if (hMapFile == NULL) {
        WRITELINE_DEBUG("Could not open global file mapping.");

        // Try open session mapping if there's no global one
        hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHARED_SESSION_NAME);
        if (hMapFile == NULL) {
            // Fail if neither work
            WRITELINE_DEBUG("Could not open session file mapping.");
            return FALSE;
        }
    }

    // Get our shared memory pointer
    lpMemFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == NULL) {
        WRITELINE_DEBUG("Could not map shared memory.");
        return FALSE;
    }

    // Set shared memory to hold what our remote process needs
    memset(lpMemFile, 0, sizeof(LunaAPI::LunaShared));
    shared.hModule = hModule;
    shared.lpInit = (LPDWORD)LoadConfig;
    shared.dwOffset = (DWORD)shared.lpInit - (DWORD)shared.hModule;
    memcpy(lpMemFile, &shared, sizeof(LunaAPI::LunaShared));

    return TRUE;
}

// This code is run on injection
__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        WRITELINE_DEBUG("Attached to process...");
        if (!InitShare(hModule)) {
            WRITELINE_DEBUG("Could not set up shared memory.");
        }
        WRITELINE_DEBUG("Initialised share memory...");

        if (!OpenLogger()) {
            WRITELINE_DEBUG("Could not open logger.");
        }
        WRITELINE_DEBUG("Started logger!");

        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        WRITELINE_DEBUG("Detaching from process");
        if (CloseShare()) {
            WRITELINE_DEBUG("Closed shared memory, was it used?");
        } else {
            WRITELINE_DEBUG("Shared memory was already closed!");
        }
        CloseLogger();
        WRITELINE_DEBUG("Closed logger and we are out!");
        break;
    }

    return TRUE;
}
