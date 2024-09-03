// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Loader.h"

using namespace LunaAPI;

#ifdef _DEBUG
#define VERBOSE_DEFAULT TRUE
#else
#define VERBOSE_DEFAULT FALSE
#endif

// Will be false if uninitialised
BOOL verboseEnabled = FALSE;

void InitialiseLuna(BOOL verbose = VERBOSE_DEFAULT) {
    verboseEnabled = verbose;
}

#ifdef LUNA_API_STATIC
// Code specific to static linking
#else
// Code for dynamic linking
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
#endif