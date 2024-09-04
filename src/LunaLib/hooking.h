#pragma once
#include <polyhook2/Detour/NatDetour.hpp>
#include "Config.h"

// Should be run at the start of the program to ensure hooks can be located when needed
#define PREPARE_HOOK(dll, name) (AddHookedFunction(dll##"!"##name, (void*)Hooked_##name))

#define GET_REAL(dll, name) static name##_t Real_##name = GetRealFunction<name##_t>(dll "!" #name)
#define GET_LUNA(dll, name) static LunaHook<name##_t>* LUNA = GetGlobalHook<name##_t>(dll "!" #name)

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
LPCSTR String_##name = #ret " " #calltype " " #name #sig; \
NOINLINE ret calltype Hooked_##name##sig

template<typename Ret, typename... Args> class LunaHook {
private:
	PLH::NatDetour* hook;
	BOOL status = FALSE;
	BOOL registerSuccess = FALSE;

	LPCSTR signature;
	LunaHook(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log, LPCSTR signature=NULL);

public:
	LunaAPI::MitigationFlags mitigations;
	LunaAPI::LogFlags logEvents;

	Ret Callbacks(Args...);

	~LunaHook();
	BOOL Enable();
	BOOL Disable();
	BOOL GetStatus();
	static LunaAPI::HookID Register(LPCSTR identifier, void* hookAddress, LunaAPI::MitigationFlags mitigate=DEFAULT_MITIGATIONS, LunaAPI::LogFlags log=DEFAULT_LOGS, LunaHook* hook=NULL);
};
template<typename Ret, typename... Args> class LunaHook<Ret(*)(Args...)> {
public:
	Ret(*trampoline)(Args...);
	Ret(*hookFunction)(Args...);
};

template<typename Ret, typename... Args> LunaHook<Ret, Args...>* GetGlobalHook(LPCSTR key);
template<typename Ret, typename... Args> LunaHook<Ret, Args...>* GetGlobalHook(LunaAPI::HookID key);

void SetDefaultMitigations(LunaAPI::MitigationFlags mitigations);
void SetDefaultLogs(LunaAPI::LogFlags logEvents);
LunaAPI::MitigationFlags GetDefaultMitigations();
LunaAPI::LogFlags GetDefaultLogs();

void AddHookedFunction(LPCSTR key, void* location);
BOOL HookInstalled(LPCSTR key);
template<typename Func> Func GetRealFunction(LPCSTR key);
template<typename Func> Func GetHookFunction(LPCSTR key);
