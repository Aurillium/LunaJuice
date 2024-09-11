#include "pch.h"
#include <Windows.h>

#include "debug.h"
#include "pyhooking.h"

#include "include/python/Python.h"

void PySwizzleGIL(PyFunctionObject* target_func, PyFunctionObject* hook_func) {
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
    if (!PyFunction_Check(hook)) {
        WRITE_DEBUG("Hook object was invalid.");
        return FALSE;
    }
    if (!PyFunction_Check(target)) {
        WRITE_DEBUG("Target object was invalid.");
        return FALSE;
    }
    PyFunctionObject* target_func = ((PyFunctionObject*)target);
    PyFunctionObject* hook_func = ((PyFunctionObject*)hook);

    // Hook is will be the original, target will be the hook
    // Inside of target (hook), let's add hook (original) as
    // a global so we can call it with `original(...)`
    if (!PyDict_Check(hook_func->func_globals)) {
        WRITELINE_DEBUG("The globals of the hook seem to be corrupted.");
        return FALSE;
    }
    // As the hook will have the code of the original
    if (PyDict_SetItemString(hook_func->func_globals, "original_function", hook)) {
        WRITELINE_DEBUG("Could not set original_function key in hook globals");
        return FALSE;
    }
    // Now we can do the disruptive operations safely
    // Everything we could need to revert has been reverted

    PySwizzleGIL(target_func, hook_func);
    return TRUE;
}
// Do the same thing, but don't modify globals
BOOL PyUnhookGIL(PyObject* target, PyObject* hook) {
    if (!PyFunction_Check(hook)) {
        WRITE_DEBUG("Hook object was invalid.");
        return FALSE;
    }
    if (!PyFunction_Check(target)) {
        WRITE_DEBUG("Target object was invalid.");
        return FALSE;
    }

    PySwizzleGIL((PyFunctionObject*)target, (PyFunctionObject*)hook);
    return TRUE;
}
PyObject* PyEvalGlobalGIL(const char* expr) {
    // Resolve target from __main__
    PyObject* main_module = PyImport_AddModule("__main__");
    PyObject* globals = PyModule_GetDict(main_module);
    WRITELINE_DEBUG("About to run string...");
    return PyRun_String("test_function", Py_eval_input, globals, globals);
}
// TODO: Get name by reading string from 'def ' to '(', etc.
PyObject* PyHiddenFunctionGIL(const char* name, const char* code) {
    PyObject* custom_namespace = PyDict_New();
    PyObject* main_module = PyImport_AddModule("__main__");
    PyObject* globals = PyModule_GetDict(main_module);

    PyRun_String(code, Py_file_input, globals, custom_namespace);
    Py_DECREF(custom_namespace);
    PyObject* func = PyDict_GetItemString(custom_namespace, name);
    if (func) {
        if (PyCallable_Check(func)) {
            return func;
        }
        else {
            WRITELINE_DEBUG("Hidden function was not valid.");
            Py_DECREF(func);
        }
    }
    WRITELINE_DEBUG("Could not create hidden function.");
    return NULL;
}

int PySetupHookThread(void* param) {
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

BOOL PySetupHook(const char* code, const char* name, const char* target, PyFunctionObject** hook_func, PyFunctionObject** target_func) {
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