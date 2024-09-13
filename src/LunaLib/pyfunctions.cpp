#include "pch.h"

#include "debug.h"
#include "pyfunctions.h"
#include "pyhooking.h"

// In versions before globals are separate to builtins, testing is needed to check if original function can be used without
// interfering with the global space

typedef const char* (*Py_GetVersion_t)(void);
// This function puts a lot of trust in Python formatting the
// string consistently, so there isn't much error checking
PyVersion GetPythonVersion() {
    REQUIRE_FUNC(Py_GetVersion);

    PyVersion version = PyVersion();
    const char* str_version = Py_GetVersion();

    int i = 0;
    int phase = 0;
    while (str_version[i] != 0) {
        int current = str_version[i] - 0x30;
        if (current <= 0 || current >= 9) {
            phase++;
            if (phase == 3) {
                break;
            }
            i++;
            continue;
        }
        int* part;
        if (phase == 0) part = &version.major;
        else if (phase == 1) part = &version.minor;
        else part = &version.micro;
        *part = *part * 10 + current;
        i++;
    }
    return version;
}

template<> bool PySwizzleGIL2<PyFunctionObject20*>(PyFunctionObject20* func1, PyFunctionObject20* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_defaults = func1->func_defaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject22*>(PyFunctionObject22* func1, PyFunctionObject22* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_defaults = func1->func_defaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_defaults = func2->func_defaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_defaults = old_defaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject23*>(PyFunctionObject23* func1, PyFunctionObject23* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_defaults = func1->func_defaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_defaults = func2->func_defaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_defaults = old_defaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject30*>(PyFunctionObject30* func1, PyFunctionObject30* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_defaults = func1->func_defaults;
    PyObject* old_kwdefaults = func1->func_kwdefaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_defaults = func2->func_defaults;
    func1->func_kwdefaults = func2->func_kwdefaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_defaults = old_defaults;
    func2->func_kwdefaults = old_kwdefaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject33*>(PyFunctionObject33* func1, PyFunctionObject33* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_defaults = func1->func_defaults;
    PyObject* old_kwdefaults = func1->func_kwdefaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_defaults = func2->func_defaults;
    func1->func_kwdefaults = func2->func_kwdefaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_defaults = old_defaults;
    func2->func_kwdefaults = old_kwdefaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject38*>(PyFunctionObject38* func1, PyFunctionObject38* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_defaults = func1->func_defaults;
    PyObject* old_kwdefaults = func1->func_kwdefaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_defaults = func2->func_defaults;
    func1->func_kwdefaults = func2->func_kwdefaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_defaults = old_defaults;
    func2->func_kwdefaults = old_kwdefaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject310*>(PyFunctionObject310* func1, PyFunctionObject310* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_builtins = func1->func_builtins;
    PyObject* old_defaults = func1->func_defaults;
    PyObject* old_kwdefaults = func1->func_kwdefaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_builtins = func2->func_builtins;
    func1->func_defaults = func2->func_defaults;
    func1->func_kwdefaults = func2->func_kwdefaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_builtins = old_builtins;
    func2->func_defaults = old_defaults;
    func2->func_kwdefaults = old_kwdefaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject311*>(PyFunctionObject311* func1, PyFunctionObject311* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_builtins = func1->func_builtins;
    PyObject* old_defaults = func1->func_defaults;
    PyObject* old_kwdefaults = func1->func_kwdefaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_builtins = func2->func_builtins;
    func1->func_defaults = func2->func_defaults;
    func1->func_kwdefaults = func2->func_kwdefaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_builtins = old_builtins;
    func2->func_defaults = old_defaults;
    func2->func_kwdefaults = old_kwdefaults;

    return true;
}
template<> bool PySwizzleGIL2<PyFunctionObject312*>(PyFunctionObject312* func1, PyFunctionObject312* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_builtins = func1->func_builtins;
    PyObject* old_defaults = func1->func_defaults;
    PyObject* old_kwdefaults = func1->func_kwdefaults;

    func1->func_code = func2->func_code;
    func1->func_globals = func2->func_globals;
    func1->func_builtins = func2->func_builtins;
    func1->func_defaults = func2->func_defaults;
    func1->func_kwdefaults = func2->func_kwdefaults;

    func2->func_code = old_code;
    func2->func_globals = old_globals;
    func2->func_builtins = old_builtins;
    func2->func_defaults = old_defaults;
    func2->func_kwdefaults = old_kwdefaults;

    return true;
}

// This function will call the correct swizzle function based on the current Python version
template<> bool PySwizzleGIL2<PyFunctionObject*>(PyFunctionObject* func1, PyFunctionObject* func2) {
    // Check the Python version, cast to correct function object, then swizzle
    static PyVersion python_version = GetPythonVersion();

    WRITELINE_DEBUG(python_version.major);
    WRITELINE_DEBUG(python_version.minor);

    if (python_version.major == 2) {
        if (python_version.minor < 2) {
            return PySwizzleGIL2((PyFunctionObject20*)func1, (PyFunctionObject20*)func2);
        }
        else if (python_version.minor < 3) {
            return PySwizzleGIL2((PyFunctionObject22*)func1, (PyFunctionObject22*)func2);
        }
        else {
            return PySwizzleGIL2((PyFunctionObject23*)func1, (PyFunctionObject23*)func2);
        }
    }
    else if (python_version.major == 3) {
        if (python_version.minor < 3) {
            return PySwizzleGIL2((PyFunctionObject30*)func1, (PyFunctionObject30*)func2);
        }
        else if (python_version.minor < 8) {
            return PySwizzleGIL2((PyFunctionObject33*)func1, (PyFunctionObject33*)func2);
        }
        else if (python_version.minor < 10) {
            return PySwizzleGIL2((PyFunctionObject38*)func1, (PyFunctionObject38*)func2);
        }
        else if (python_version.minor < 11) {
            return PySwizzleGIL2((PyFunctionObject310*)func1, (PyFunctionObject310*)func2);
        }
        else if (python_version.minor < 12) {
            return PySwizzleGIL2((PyFunctionObject311*)func1, (PyFunctionObject311*)func2);
        }
        else {
            return PySwizzleGIL2((PyFunctionObject312*)func1, (PyFunctionObject312*)func2);
        }
    }
    else {
        // Unsupported
        return false;
    }
}