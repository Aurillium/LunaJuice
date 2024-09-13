#include "pch.h"
#include <mutex>
#include <vector>
#include <Windows.h>

#include "include/python/Python.h"

#include "debug.h"
#include "pyfunctions.h"
#include "pyhooking.h"

#include <map>

#include "hooking.h"

std::mutex PYTHON_HOOKS_MUTEX;
std::vector<LunaPyHook*> PYTHON_HOOKS = std::vector<LunaPyHook*>();

typedef int (*PyDict_SetItemString_t)(PyObject* dp, const char* key, PyObject* item);
typedef PyObject* (*PyDict_GetItemString_t)(PyObject* dp, const char* key);
typedef PyObject* (*PyImport_AddModule_t)(const char* name);
typedef PyObject* (*PyModule_GetDict_t)(PyObject*);
typedef PyObject* (*PyDict_New_t)(void);
typedef int (*PyObject_HasAttrString_t)(PyObject* o, const char* attr_name);
typedef PyObject* (*PyRun_StringFlags_t)(const char*, int, PyObject*, PyObject*, PyCompilerFlags*);
typedef PyTypeObject* (*Py_TYPE_t)(PyObject*);
typedef void (*Py_DecRef_t)(PyObject*);
typedef void (*Py_IncRef_t)(PyObject*);
typedef PyObject* (*PyObject_GetAttrString_t)(PyObject* o, const char* attr_name);
typedef int (*PyObject_SetAttrString_t)(PyObject* o, const char* attr_name, PyObject* v);
typedef PyObject* (*PyFunction_GetGlobals_t)(PyObject* op);

typedef int (*PyObject_Print_t)(PyObject*, FILE*, int);

typedef PyGILState_STATE (*PyGILState_Ensure_t)(void);
typedef void (*PyGILState_Release_t)(PyGILState_STATE);
typedef int (*Py_AddPendingCall_t)(int (*func)(void*), void* arg);
typedef int (*Py_IsInitialized_t)(void);

std::map<std::string, AnyFunction> pyFunctions = std::map<std::string, AnyFunction>();

CPythonState CPYTHON_STATE = NoInit;
CPythonState GetCPythonState() {
    return CPYTHON_STATE;
}
LPCSTR COMPATIBLE_VERSIONS[] = {
    "python27.dll",
    "python30.dll",
    "python31.dll",
    "python32.dll",
    "python33.dll",
    "python34.dll",
    "python35.dll",
    "python36.dll",
    "python37.dll",
    "python38.dll",
    "python39.dll",
    "python310.dll",
    "python311.dll",
    "python312.dll"
};
LPCSTR REQUIRED_FUNCTIONS[] = {
    "PyDict_SetItemString",     // Stable ABI                       https://docs.python.org/3/c-api/dict.html#c.PyDict_SetItemString
    "PyDict_GetItemString",     // Stable ABI (borrowed ref TODO)   https://docs.python.org/3/c-api/dict.html#c.PyDict_GetItemString
    "PyImport_AddModule",       // Stable ABI (borrowed ref)        https://docs.python.org/3/c-api/import.html#c.PyImport_AddModuleObject
    "PyModule_GetDict",         // Stable ABI (borrowed ref)        https://docs.python.org/3/c-api/module.html#c.PyModule_GetDict
    "PyDict_New",               // Stable ABI (new ref)             https://docs.python.org/3/c-api/dict.html#c.PyDict_New      
    "PyObject_HasAttrString",   // Stable ABI                       https://docs.python.org/3/c-api/object.html#c.PyObject_HasAttrString
    "PyRun_StringFlags",        // Stable (new ref)                 https://docs.python.org/3/c-api/veryhigh.html#c.PyRun_StringFlags
    "Py_DecRef",                // Stable ABI                       https://docs.python.org/3/c-api/refcounting.html#c.Py_DecRef
    "Py_IncRef",                // Stable ABI                       https://docs.python.org/3/c-api/refcounting.html#c.Py_IncRef
    "PyGILState_Ensure",        // Stable ABI                       https://docs.python.org/3/c-api/init.html#c.PyGILState_Ensure
    "PyGILState_Release",       // Stable ABI                       https://docs.python.org/3/c-api/init.html#c.PyGILState_Release
    "Py_AddPendingCall",        // Stable ABI                       https://docs.python.org/3/c-api/init.html#c.Py_AddPendingCall
    "Py_IsInitialized",         // Stable ABI                       https://docs.python.org/3/c-api/init.html#c.Py_IsInitialized
    "PyObject_Print",           // Stable                           https://docs.python.org/3/c-api/object.html#c.PyObject_Print
    "PyObject_GetAttrString",   // Stable ABI                       https://docs.python.org/3/c-api/object.html#c.PyObject_GetAttrString
    "PyObject_SetAttrString",   // Stable ABI                       https://docs.python.org/3/c-api/object.html#c.PyObject_SetAttrString
    "PyFunction_GetGlobals",    // Stable ABI (borrowed ref)        https://docs.python.org/3/c-api/function.html#PyFunction_GetGlobals
    "Py_GetVersion",            // Stable ABI (static ptr)          https://docs.python.org/3/c-api/init.html#c.Py_GetVersion
};
AnyFunction GetCPythonFunction(LPCSTR name) {
    return pyFunctions[name];
}

BOOL AddCPythonFunction(HMODULE hPython, LPCSTR name) {
    FARPROC func = GetProcAddress(hPython, name);
    if (func == NULL) {
        return FALSE;
    }
    pyFunctions[name] = (AnyFunction)func;
}
BOOL InitialiseCPython() {
    HMODULE hPython = NULL;
    for (size_t i = 0; i < sizeof(COMPATIBLE_VERSIONS) / sizeof(LPCSTR); i++) {
        hPython = GetModuleHandleA(COMPATIBLE_VERSIONS[i]);
        if (hPython != NULL) {
            break;
        }
    }
    if (hPython == NULL) {
        WRITELINE_DEBUG("Could not find a compatible version of Python.");
        CPYTHON_STATE = InitFailed;
        return FALSE;
    }
    for (size_t i = 0; i < sizeof(REQUIRED_FUNCTIONS) / sizeof(LPCSTR); i++) {
        if (!AddCPythonFunction(hPython, REQUIRED_FUNCTIONS[i])) {
            WRITELINE_DEBUG("Failed to add '" << REQUIRED_FUNCTIONS[i] << "'.");
        }
    }
    
    // This has to be below the above loop
    REQUIRE_FUNC(Py_IsInitialized);

    if (Py_IsInitialized()) {
        CPYTHON_STATE = InitSuccess;
        return TRUE;
    }
    else {
        CPYTHON_STATE = PythonNoInit;
        return FALSE;
    }
}


void PySwizzleGIL_obselete(PyFunctionObject* target_func, PyFunctionObject* hook_func) {
    // Swizzle (this does not appear to be supported in the API)
    PyObject* old_code = target_func->func_code;
    PyObject* old_globals = target_func->func_globals;
    PyObject* old_builtins = target_func->func_builtins;
    PyObject* old_defaults = target_func->func_defaults;
    PyObject* old_kwdefaults = target_func->func_kwdefaults;

    PyObject* new_code = hook_func->func_code;
    PyObject* new_globals = hook_func->func_globals;
    PyObject* new_builtins = hook_func->func_builtins;
    PyObject* new_defaults = hook_func->func_defaults;
    PyObject* new_kwdefaults = hook_func->func_kwdefaults;

    hook_func->func_code = old_code;
    hook_func->func_globals = old_globals;
    hook_func->func_builtins = old_builtins;
    hook_func->func_defaults = old_defaults;
    hook_func->func_kwdefaults = old_kwdefaults;

    target_func->func_code = new_code;
    target_func->func_globals = new_globals;
    target_func->func_builtins = new_builtins;
    target_func->func_defaults = new_defaults;
    target_func->func_kwdefaults = new_kwdefaults;
    // Swizzle success!
}

// Swizzle two Python functions, but add a global variable to reference the original function
BOOL PyHookGIL(PyObject* target, PyObject* hook) {
    REQUIRE_FUNC(PyObject_HasAttrString);
    REQUIRE_FUNC(PyDict_SetItemString);
    REQUIRE_FUNC(PyFunction_GetGlobals);
    REQUIRE_FUNC(PyObject_SetAttrString);
    REQUIRE_FUNC(PyObject_GetAttrString);
    REQUIRE_FUNC(PyDict_GetItemString);
    REQUIRE_FUNC(PyRun_StringFlags);
    REQUIRE_FUNC(PyImport_AddModule);
    REQUIRE_FUNC(PyModule_GetDict);
    REQUIRE_FUNC(PyDict_New);

    WRITELINE_DEBUG("Pre-call check" << hook);
    if (!PyObject_HasAttrString(hook, "__call__")) {
        WRITE_DEBUG("Hook object was invalid.");
        return FALSE;
    }
    WRITELINE_DEBUG("After first call");
    if (!PyObject_HasAttrString(target, "__call__")) {
        WRITE_DEBUG("Target object was invalid.");
        return FALSE;
    }

    // Hook will be the original, target will be the hook
    // Inside of target (hook), let's add hook (original) as
    // a global so we can call it with `original(...)`

    // As the hook will have the code of the original
    // TODO: this modifies the globals for everyone, not just this function
    //       we need another method (perhaps patch builtins?)

    // Here we need to set up fake globals
    PyObject* main_module = PyImport_AddModule("__main__");
    PyObject* main_globals = PyModule_GetDict(main_module);
    PyObject* main_builtins = PyObject_GetAttrString(main_module, "__builtins__");
    PyObject* custom_namespace = PyDict_New();

    // NEW PLAN OF ATTACK
    // Just shove main globals into _globals in hook space, builtins should be set to main builtins

    PyObject* hook_globals = PyFunction_GetGlobals(hook);
    // Do error checking
    PyDict_SetItemString(hook_globals, "globals", main_module);
    PyDict_SetItemString(hook_globals, "builtins", main_builtins);

    if (PyDict_SetItemString(hook_globals, "original", hook)) {
        WRITELINE_DEBUG("Could not set `original` function key in hook globals");
        return FALSE;
    }
    // Now we can do the disruptive operations safely
    // Everything we could need to revert has been reverted

    PySwizzleGIL2((PyFunctionObject*)target, (PyFunctionObject*)hook);
    return TRUE;
}

PyObject* PyEvalGlobalGIL(const char* expr) {
    REQUIRE_FUNC(PyImport_AddModule);
    REQUIRE_FUNC(PyModule_GetDict);
    REQUIRE_FUNC(PyRun_StringFlags);

    // Resolve target from __main__
    PyObject* main_module = PyImport_AddModule("__main__");
    // TODO: If hidden function creation fails, this line causes a crash
    PyObject* globals = PyModule_GetDict(main_module);
    WRITELINE_DEBUG("About to run string...");
    return PyRun_StringFlags(expr, Py_eval_input, globals, globals, NULL);
}
// TODO: Get name by reading string from 'def ' to '(', etc.
PyObject* PyHiddenFunctionGIL(const char* name, const char* code) {
    REQUIRE_FUNC(PyDict_New);
    REQUIRE_FUNC(PyImport_AddModule);
    REQUIRE_FUNC(PyModule_GetDict);
    REQUIRE_FUNC(Py_DecRef);
    REQUIRE_FUNC(Py_IncRef);
    REQUIRE_FUNC(PyRun_StringFlags);
    REQUIRE_FUNC(PyDict_GetItemString);
    REQUIRE_FUNC(PyObject_HasAttrString);
    REQUIRE_FUNC(PyObject_SetAttrString);

    // We can't use any builtins/globals in the definition, but
    // we will have them accessible at call-time
    PyObject* custom_namespace = PyDict_New(); // Check refs

    PyRun_StringFlags(code, Py_file_input, custom_namespace, custom_namespace, NULL);
    PyObject* func = PyDict_GetItemString(custom_namespace, name);
    // Take ownership so it doesn't get deleted
    Py_IncRef(func);

    Py_DecRef(custom_namespace);
    if (func) {
        if (PyObject_HasAttrString(func, "__call__")) {
            return func;
        }
        else {
            WRITELINE_DEBUG("Hidden function was not valid.");
            Py_DecRef(func);
        }
    }
    WRITELINE_DEBUG("Could not create hidden function.");
    return NULL;
}

int PySetupHookThread(void* param) {
    REQUIRE_FUNC(PyGILState_Ensure);
    REQUIRE_FUNC(PyGILState_Release);

    WRITELINE_DEBUG("In hook thread.");
    // Get parameters
    PyHookSetupData* setup = (PyHookSetupData*)param;
    setup->success = FALSE;

    // Acquire the GIL before making any Python C API calls
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    WRITELINE_DEBUG("Got GIL.");

    PyObject* hook = PyHiddenFunctionGIL(setup->hook_name, setup->hook_code);
    PyObject* target = PyEvalGlobalGIL(setup->target_expr);
    WRITELINE_DEBUG("Eval'd function.");
    if (hook == NULL) {
        WRITE_DEBUG("Could not create hook function.");
        goto cleanup;
    }
    if (target == NULL) {
        WRITE_DEBUG("Could not find target function.");
        goto cleanup;
    }
    if (!PyHookGIL(target, hook)) {
        WRITELINE_DEBUG("Could not hook functions.");
        goto cleanup;
    }

    setup->success = TRUE;
cleanup:
    // Release the GIL
    PyGILState_Release(gstate);
    WRITELINE_DEBUG("Released GIL.");
    WRITELINE_DEBUG("Passing back to main...");
    SetEvent(setup->event);
    return 0; // Py_AddPendingCall requires the return value to be 0
}
int PyToggleHookThread(void* param) {
    REQUIRE_FUNC(PyGILState_Ensure);
    REQUIRE_FUNC(PyGILState_Release);

    WRITELINE_DEBUG("In hook thread.");
    // Get parameters
    PyHookSetupData* setup = (PyHookSetupData*)param;
    setup->success = FALSE;

    // Acquire the GIL before making any Python C API calls
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    WRITELINE_DEBUG("Got GIL.");

    PySwizzleGIL2(setup->target, setup->hook);

    setup->success = TRUE;
cleanup:
    // Release the GIL
    PyGILState_Release(gstate);
    WRITELINE_DEBUG("Released GIL.");
    WRITELINE_DEBUG("Passing back to main...");
    SetEvent(setup->event);
    return 0; // Py_AddPendingCall requires the return value to be 0
}

BOOL PySetupHook(const char* code, const char* name, const char* target, PyFunctionObject** hook_func, PyFunctionObject** target_func) {
    REQUIRE_FUNC(Py_AddPendingCall);

    PyHookSetupData setup = PyHookSetupData();
    setup.event = CreateEventA(NULL, FALSE, FALSE, NULL);
    setup.hook_code = code;
    setup.hook_name = name;
    setup.target_expr = target;
    if (setup.event == NULL) {
        WRITELINE_DEBUG("Could not create event to wait for.");
        return FALSE;
    }
    if (Py_AddPendingCall(PySetupHookThread, &setup) != 0) {
        WRITELINE_DEBUG("Python execution failed.");
    }
    // Wait for swizzle to finish
    WaitForSingleObject(setup.event, INFINITE);
    CloseHandle(setup.event);
    return setup.success;
}
BOOL PyToggleHook(PyFunctionObject* hook, PyFunctionObject* target) {
    REQUIRE_FUNC(Py_AddPendingCall);

    PyUnhookData setup = PyUnhookData();
    setup.event = CreateEventA(NULL, FALSE, FALSE, NULL);
    setup.hook = hook;
    setup.target = target;
    if (setup.event == NULL) {
        WRITELINE_DEBUG("Could not create event to wait for.");
        return FALSE;
    }
    if (Py_AddPendingCall(PyToggleHookThread, &setup) != 0) {
        WRITELINE_DEBUG("Python execution failed.");
    }
    // Wait for swizzle to finish
    WaitForSingleObject(setup.event, INFINITE);
    CloseHandle(setup.event);
    return setup.success;
}


LunaPyHook::LunaPyHook(const char* code, const char* name, const char* target, LunaAPI::LogFlags log) {
    this->logEvents = log;
    this->registerSuccess = PySetupHook(code, name, target, &this->hook, &this->target);
}

// idname is there so we don't have to address by the expression in the registry
LunaAPI::HookID LunaPyHook::Register(const char* code, const char* name, const char* target, const char* idname, LunaAPI::LogFlags log, LunaPyHook** hook) {
    LunaPyHook* newHook = new LunaPyHook(code, name, target, log);
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
    HOOK_STORAGE.push_back(std::pair(Type_Python, newHook));

    // TODO: finish me
    REGISTRY[idname] = id;

    WRITELINE_DEBUG("New hook registered! " << identifier << " = " << id << ", miti: " << newHook->mitigations << ", log: " << newHook->logEvents);

    return id;
}

BOOL LunaPyHook::GetStatus() {
    return this->status;
}
BOOL LunaPyHook::Enable() {
    if (this->status) {
        return FALSE;
    }
    return PyToggleHook(this->hook, this->target);
}
BOOL LunaPyHook::Disable() {
    if (!this->status) {
        return FALSE;
    }
    return PyToggleHook(this->hook, this->target);
}

// These are not threadsafe, a mutex should be added
PyFunctionObject* LunaPyHook::GetHook() {
    return this->status ? this->hook : this->target;
}
PyFunctionObject* LunaPyHook::GetOriginal() {
    return this->status ? this->target : this->hook;
}

LunaPyHook::~LunaPyHook() {
    REQUIRE_FUNC(Py_DecRef);

    this->Disable();
    Py_DecRef((PyObject*)this->hook);
    Py_DecRef((PyObject*)this->target);
}