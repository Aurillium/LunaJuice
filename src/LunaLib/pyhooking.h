#pragma once
#include <Windows.h>

#include "Config.h"

#include "include/python/Python.h"

// Just for CPython functions
#include "hooking.h"

typedef struct _PyHookSetupData {
    BOOL success;
    const char* target_expr;
    const char* hook_name;
    const char* hook_code;
    PyFunctionObject* hook;
    PyFunctionObject* target;
    // Include info to notify other thread this is done
    HANDLE event;
} PyHookSetupData;

typedef struct _PyHookData {
    BOOL success;
    PyFunctionObject* hook;
    PyFunctionObject* target;
    // Include info to notify other thread this is done
    HANDLE event;
} PyUnhookData, PyReHookData;

class LunaPyHook {
private:
	BOOL status = FALSE;
    BOOL registerSuccess = FALSE;
	PyFunctionObject* hook;
	PyFunctionObject* target;
    LunaPyHook(const char* code, const char* name, const char* target, LunaAPI::LogFlags log);
public:
	LunaAPI::LogFlags logEvents;
	~LunaPyHook();
	BOOL Enable();
	BOOL Disable();
	BOOL GetStatus();
    PyFunctionObject* GetOriginal();
    PyFunctionObject* GetHook();
	static LunaAPI::HookID Register(const char* code, const char* name, const char* target, LunaAPI::LogFlags log, LunaPyHook** hook = NULL);
};

BOOL PySetupHook(const char* code, const char* name, const char* target, PyFunctionObject** hook_func, PyFunctionObject** target_func);
BOOL PyToggleHook(PyFunctionObject* hook, PyFunctionObject* target);


typedef enum _CPythonState {
    NoInit,
    InitFailed,
    PythonNoInit,   // Py_IsInitialized() == false
    InitSuccess,
} CPythonState;

AnyFunction GetCPythonFunction(LPCSTR name);
BOOL InitialiseCPython();
BOOL AddCPythonFunction(HMODULE hPython, LPCSTR name);