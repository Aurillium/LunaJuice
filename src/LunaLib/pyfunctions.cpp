#include "pyfunctions.h"

template<> bool PySwizzleGIL2<PyFunctionObject20*>(PyFunctionObject20* func1, PyFunctionObject20* func2) {
    PyObject* old_code = func1->func_code;
    PyObject* old_globals = func1->func_globals;
    PyObject* old_defaults = func1->func_defaults;
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
}

// This function will call the correct swizzle function based on the current Python version
template<> bool PySwizzleGIL2<PyFunctionObject*>(PyFunctionObject* func1, PyFunctionObject* func2) {
    // Check the Python version, cast to correct function object, then swizzle
}