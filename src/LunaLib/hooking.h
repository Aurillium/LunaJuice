#pragma once
//#include "hookingv2.h"
//#include "hookingv3.h"
//#include "hookingv4.h"

#include <polyhook2/Detour/NatDetour.hpp>
#include "Config.h"

// Macro to make hooking easier
// Make sure you follow the naming format though!
// Hooked_{name}, Real_{name}
#define QUICK_HOOK(dll, name) (InstallPolyHook(dll, #name, (void*)Hooked_##name, (void**)&Real_##name)->hook())
#define REGISTER_HOOK(dll, name, mitigations, logs) LunaHook::Register(dll, #name, (void*)Hooked_##name, (void**)&Real_##name, mitigations, logs)
#define EXTERN_HOOK(name) extern name##_t Real_##name;

#define CONDITIONAL_REGISTER_HOOK(flags, dll, name, mitigations, logs) if (flags & LunaAPI::Hook_##name) { if (!REGISTER_HOOK(dll, name, mitigations, logs)) WRITELINE_DEBUG("Could not register hook '" #name "' of '" #dll "'."); }
#define CONDITIONAL_REGISTER_AW_HOOK(flags, dll, name, mitigations, logs) if (flags & LunaAPI::Hook_##name) { \
	if (!REGISTER_HOOK(dll, name##A, mitigations, logs)) WRITELINE_DEBUG("Could not register hook '" #name "A' of '" #dll "'."); \
	if (!REGISTER_HOOK(dll, name##W, mitigations, logs)) WRITELINE_DEBUG("Could not register hook '" #name "W' of '" #dll "'."); \
}

// Quickly define hooks
// Example:
// typedef BOOL(WINAPI* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
// BOOL WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
//
// Becomes:
// HOOKDEF(MessageBoxA, BOOL, WINAPI, (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType));
#define HOOKHEAD(name, calltype, ret, sig) \
typedef ret(calltype* name##_t)sig; \
ret calltype Hooked_##name##sig;

#define HOOKDEF(name, calltype, ret, sig) \
name##_t Real_##name; \
LPCSTR String_##name = #ret " " #calltype " " #name #sig; \
NOINLINE ret calltype Hooked_##name##sig

#define HOOKSTUB(name, calltype, ret, sig) \
name##_t Real_##name; \
LPCSTR String_##name = #ret " " #calltype " " #name #sig; \
NOINLINE ret calltype Hooked_##name##sig { \
	LPCSTR __MYNAME = #name; \
	name##_t __REAL = Real_##name; \
	LunaHook* __LUNA = GetGlobalHook(__MYNAME);

#define ENDHOOK }

class LunaHook {
private:
	PLH::NatDetour* hook;
	BOOL status = FALSE;
	BOOL registerSuccess = FALSE;

	LunaHook(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, void** trampolineAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log);

public:
	LunaAPI::MitigationFlags mitigations;
	LunaAPI::LogFlags logEvents;

	~LunaHook();
	BOOL Enable();
	BOOL Disable();
	BOOL GetStatus();
	static BOOL Register(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, void** trampolineAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log);
};
LunaHook* GetGlobalHook(LPCSTR key);
void SetDefaultMitigations(LunaAPI::MitigationFlags mitigations);
void SetDefaultLogs(LunaAPI::LogFlags logEvents);
LunaAPI::MitigationFlags GetDefaultMitigations();
LunaAPI::LogFlags GetDefaultLogs();

PLH::NatDetour* InstallPolyHook(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction);

// These variables cannot be static, no matter what Visual Studio says:
// https://stackoverflow.com/questions/1358400/what-is-external-linkage-and-internal-linkage
// https://stackoverflow.com/questions/6469849/one-or-more-multiply-defined-symbols-found