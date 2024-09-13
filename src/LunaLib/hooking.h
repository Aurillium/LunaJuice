#pragma once
#include <any>

#include <polyhook2/Detour/NatDetour.hpp>

#include "Config.h"

#include "debug.h"

// Should be run at the start of the program to ensure hooks can be located when needed
#define PREPARE_HOOK(dll, name) (AddHookedFunction(dll "!" #name, (void*)Hooked_##name))

#define GET_REAL(dll, name) static name##_t Real_##name = (name##_t)GetRealFunction(dll "!" #name)
#define GET_LUNA(dll, name) static LunaHook<name##_t>* LUNA = LunaHook<name##_t>::GetGlobalHook(dll "!" #name)

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

using AnyFunction = std::any(*)(std::any);

enum HookType {
    Type_Native,
    Type_Python
};

template<class> class LunaHook;
template<typename Ret, typename... Args> class LunaHook<Ret(*)(Args...)> {
private:
	PLH::NatDetour* hook;
	BOOL status = FALSE;
	BOOL registerSuccess = FALSE;

	LPCSTR signature;

	LunaHook(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log, LPCSTR signature = NULL);
public:
	LunaAPI::MitigationFlags mitigations;
	LunaAPI::LogFlags logEvents;
	Ret(*trampoline)(Args...);
	Ret(*hookFunction)(Args...);

	Ret Callbacks(Args...) const;

	~LunaHook();
	BOOL Enable() const;
	BOOL Disable() const;
	BOOL GetStatus() const;
	static LunaAPI::HookID Register(LPCSTR identifier, void* hookAddress, LunaAPI::MitigationFlags mitigate = DEFAULT_MITIGATIONS, LunaAPI::LogFlags log = DEFAULT_LOGS, LunaHook** hook = NULL);
    static LunaHook<Ret(*)(Args...)>* GetGlobalHook(LPCSTR identifier);
    static LunaHook<Ret(*)(Args...)>* GetGlobalHook(LunaAPI::HookID key);
};

void SetDefaultMitigations(LunaAPI::MitigationFlags mitigations);
void SetDefaultLogs(LunaAPI::LogFlags logEvents);
LunaAPI::MitigationFlags GetDefaultMitigations();
LunaAPI::LogFlags GetDefaultLogs();

void AddHookedFunction(std::string key, void* location);
BOOL HookInstalled(LPCSTR key);
void* GetRealFunction(LPCSTR key);
void* GetHookFunction(std::string key);
void* GetFunctionAddress(IN LPCSTR moduleName, IN LPCSTR functionName);

// Template definitions

extern std::vector<std::pair<HookType, void*>> HOOK_STORAGE;
extern LunaAPI::HookRegistry REGISTRY;
extern std::map<std::string, void*> HOOK_LOCATIONS;

extern std::mutex HOOKS_MUTEX;
extern std::mutex REGISTRY_MUTEX;
extern std::mutex NATIVE_HOOKS_MUTEX;

// Run callbacks
template<typename Ret, typename... Args> Ret LunaHook<Ret(*)(Args...)>::Callbacks(Args... args) const {
    Ret mitigationReturn;
    // If mitigations returned a value, return it without running the hook.
    if (Mitigate(this->mitigations, &mitigationReturn)) {
        return mitigationReturn;
    }

    // Call the hook
    return this->hookAddr(args...);
}

template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>::LunaHook(LPCSTR moduleName, LPCSTR functionName, void* hookAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log, LPCSTR sig) {
    this->registerSuccess = FALSE;
    this->signature = sig;

    void* originalAddress = GetFunctionAddress(moduleName, functionName);
    if (originalAddress == NULL) {
        WRITELINE_DEBUG("Could not find " << moduleName << "!" << functionName << ", will not be able to hook.");
        return;
    }
    this->hook = new PLH::NatDetour((uint64_t)originalAddress, (uint64_t)hookAddress, (uint64_t*)&this->trampoline);
    if (this->hook == NULL) {
        WRITELINE_DEBUG("Could not create LunaHook for " << moduleName << "!" << functionName << ".");
        return;
    }
    this->mitigations = mitigate;
    this->logEvents = log;

    this->hook->hook();

    this->registerSuccess = TRUE;
    WRITELINE_DEBUG("Successfully hooked '" << functionName << "' of '" << moduleName << "'!");
}
template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>::~LunaHook() {
    // Clean up
    delete hook;
}
template<typename Ret, typename... Args> BOOL LunaHook<Ret(*)(Args...)>::GetStatus() const {
    return hook->isHooked();
}
template<typename Ret, typename... Args> BOOL LunaHook<Ret(*)(Args...)>::Enable() const {
    if (!this->hook->isHooked()) {
        WRITELINE_DEBUG("Hooking...");
        return hook->hook();
    }
    WRITELINE_DEBUG("Already hooked!");
    return TRUE;
}
template<typename Ret, typename... Args> BOOL LunaHook<Ret(*)(Args...)>::Disable() const {
    if (this->hook->isHooked()) {
        WRITELINE_DEBUG("Unhooking...");
        return hook->unHook();
    }
    WRITELINE_DEBUG("Already hooked!");
    return TRUE;
}

// Should these functions check for errors?
template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>* LunaHook<Ret(*)(Args...)>::GetGlobalHook(LPCSTR identifier) {
    return (LunaHook<Ret(*)(Args...)>*)HOOK_STORAGE[REGISTRY[identifier]].second;
}
template<typename Ret, typename... Args> LunaHook<Ret(*)(Args...)>* LunaHook<Ret(*)(Args...)>::GetGlobalHook(LunaAPI::HookID key) {
    return (LunaHook<Ret(*)(Args...)>*)HOOK_STORAGE[key].second;
}

template<typename Ret, typename... Args> LunaAPI::HookID LunaHook<Ret(*)(Args...)>::Register(LPCSTR identifier, void* hookAddress, LunaAPI::MitigationFlags mitigate, LunaAPI::LogFlags log, LunaHook** hook) {
    size_t length = strlen(identifier) + 1;
    LPSTR target = (LPSTR)calloc(length, sizeof(CHAR));
    if (target == NULL) {
        WRITELINE_DEBUG("Could not allocate memory to store target function name.");
        return LunaAPI::MAX_HOOKID;
    }
    memcpy_s(target, length, identifier, length);
    // Null terminate last position
    target[length - 1] = 0;
    DWORD i = 0;
    // What is this warning for?
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
        return LunaAPI::MAX_HOOKID;
    }
    LPSTR moduleName = target;
    LPSTR functionName = &target[i]; // Get from after the '!'

    LunaHook<AnyFunction>* newHook = new LunaHook(moduleName, functionName, hookAddress, mitigate, log);
    free(target); // module and function names have been used now
    if (!newHook->registerSuccess) {
        // Clean up and exit
        delete newHook;
        // This should be a maximum int, as HookID is unsigned
        return LunaAPI::MAX_HOOKID;
    }
    if (hook != NULL) {
        *hook = newHook;
    }
    LunaAPI::HookID id = HOOK_STORAGE.size();
    HOOK_STORAGE.push_back(std::pair(Type_Native, newHook));

    // Add to registry
    REGISTRY[identifier] = id;

    WRITELINE_DEBUG("New hook registered! " << identifier << " = " << id << ", miti: " << newHook->mitigations << ", log: " << newHook->logEvents);

    return id;
}