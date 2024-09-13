#pragma once
#pragma once
// This file contains various definitions of Python function structures over time
// Luckily these don't tend to change over patches
// Goes from 2.0.1 to 3.13.0rc2
// Note that PyObjects are different and not supported by these definitions,
// but as long as you use the DLL to operate on everything else you'll be fine

// It is likely this will fail on 32-bit Python builds if built on 64-bit, but that's
// also the case for most things in this project right now
#include "include/python/Python.h"

enum PyFunctionConfiguration {
    Python20,
    Python22,
    Python23,
    Python30,
    Python33,
    Python38,
    Python310,
    Python311,
    Python312,
};
// No need to include builds; afaik changes are only between minor versions
// micro included for completeness and possibility of changes
struct PyVersion {
    int major;
    int minor;
    int micro;
};


// Range: 2.2 - 2.7 (check size_t size)
// Definition changes between 2.2 and 2.3 but is functionally the same
#ifdef Py_TRACE_REFS
/* Define pointers to support a doubly-linked list of all live heap objects. */
#define _PyObject_HEAD_EXTRA20            \
    struct _object *_ob_next;           \
    struct _object *_ob_prev;

#define _PyObject_EXTRA_INIT20 0, 0,

#else
#define _PyObject_HEAD_EXTRA20
#define _PyObject_EXTRA_INIT20
#endif

#define PyObject_HEAD20                 \
    _PyObject_HEAD_EXTRA20              \
    Py_ssize_t ob_refcnt;               \
    struct _typeobject *ob_type;

// Range: 2.0.1 only
typedef struct {
    PyObject_HEAD
    PyObject* func_code;
    PyObject* func_globals;
    PyObject* func_defaults;
    PyObject* func_doc;
    PyObject* func_name;
} PyFunctionObject20;

// Range: 2.2 only
typedef struct {
    PyObject_HEAD20
    PyObject* func_code;
    PyObject* func_globals;
    PyObject* func_defaults;
    PyObject* func_closure;
    PyObject* func_doc;
    PyObject* func_name;
    PyObject* func_dict;
    PyObject* func_weakreflist;
} PyFunctionObject22;

// Range 2.3 - 2.7
typedef struct {
    PyObject_HEAD20
    PyObject* func_code;	/* A code object */
    PyObject* func_globals;	/* A dictionary (other mappings won't do) */
    PyObject* func_defaults;	/* NULL or a tuple */
    PyObject* func_closure;	/* NULL or a tuple of cell objects */
    PyObject* func_doc;		/* The __doc__ attribute, can be anything */
    PyObject* func_name;	/* The __name__ attribute, a string object */
    PyObject* func_dict;	/* The __dict__ attribute, a dict or NULL */
    PyObject* func_weakreflist;	/* List of weak references */
    PyObject* func_module;	/* The __module__ attribute, can be anything */

    /* Invariant:
     *     func_closure contains the bindings for func_code->co_freevars, so
     *     PyTuple_Size(func_closure) == PyCode_GetNumFree(func_code)
     *     (func_closure may be NULL if PyCode_GetNumFree(func_code) == 0).
     */
} PyFunctionObject23;



#define PyObject_HEAD30		        PyObject ob_base;

// Range: 3.0 - 3.2
typedef struct {
    PyObject_HEAD30
    PyObject* func_code;	/* A code object, the __code__ attribute */
    PyObject* func_globals;	/* A dictionary (other mappings won't do) */
    PyObject* func_defaults;	/* NULL or a tuple */
    PyObject* func_kwdefaults;	/* NULL or a dict */
    PyObject* func_closure;	/* NULL or a tuple of cell objects */
    PyObject* func_doc;		/* The __doc__ attribute, can be anything */
    PyObject* func_name;	/* The __name__ attribute, a string object */
    PyObject* func_dict;	/* The __dict__ attribute, a dict or NULL */
    PyObject* func_weakreflist;	/* List of weak references */
    PyObject* func_module;	/* The __module__ attribute, can be anything */
    PyObject* func_annotations;	/* Annotations, a dict or NULL */

    /* Invariant:
     *     func_closure contains the bindings for func_code->co_freevars, so
     *     PyTuple_Size(func_closure) == PyCode_GetNumFree(func_code)
     *     (func_closure may be NULL if PyCode_GetNumFree(func_code) == 0).
     */
} PyFunctionObject30;

// Range: 3.3 - 3.7
typedef struct {
    PyObject_HEAD30
    PyObject* func_code;	/* A code object, the __code__ attribute */
    PyObject* func_globals;	/* A dictionary (other mappings won't do) */
    PyObject* func_defaults;	/* NULL or a tuple */
    PyObject* func_kwdefaults;	/* NULL or a dict */
    PyObject* func_closure;	/* NULL or a tuple of cell objects */
    PyObject* func_doc;		/* The __doc__ attribute, can be anything */
    PyObject* func_name;	/* The __name__ attribute, a string object */
    PyObject* func_dict;	/* The __dict__ attribute, a dict or NULL */
    PyObject* func_weakreflist;	/* List of weak references */
    PyObject* func_module;	/* The __module__ attribute, can be anything */
    PyObject* func_annotations;	/* Annotations, a dict or NULL */
    PyObject* func_qualname;    /* The qualified name */

    /* Invariant:
     *     func_closure contains the bindings for func_code->co_freevars, so
     *     PyTuple_Size(func_closure) == PyCode_GetNumFree(func_code)
     *     (func_closure may be NULL if PyCode_GetNumFree(func_code) == 0).
     */
} PyFunctionObject33;

// Range: 3.8 - 3.9
typedef struct {
    PyObject_HEAD30
    PyObject* func_code;        /* A code object, the __code__ attribute */
    PyObject* func_globals;     /* A dictionary (other mappings won't do) */
    PyObject* func_defaults;    /* NULL or a tuple */
    PyObject* func_kwdefaults;  /* NULL or a dict */
    PyObject* func_closure;     /* NULL or a tuple of cell objects */
    PyObject* func_doc;         /* The __doc__ attribute, can be anything */
    PyObject* func_name;        /* The __name__ attribute, a string object */
    PyObject* func_dict;        /* The __dict__ attribute, a dict or NULL */
    PyObject* func_weakreflist; /* List of weak references */
    PyObject* func_module;      /* The __module__ attribute, can be anything */
    PyObject* func_annotations; /* Annotations, a dict or NULL */
    PyObject* func_qualname;    /* The qualified name */
    vectorcallfunc vectorcall;

    /* Invariant:
     *     func_closure contains the bindings for func_code->co_freevars, so
     *     PyTuple_Size(func_closure) == PyCode_GetNumFree(func_code)
     *     (func_closure may be NULL if PyCode_GetNumFree(func_code) == 0).
     */
} PyFunctionObject38;

// From Python 3.10 - ???
#define COMMON_FIELDS310(PREFIX) \
    PyObject *PREFIX ## globals; \
    PyObject *PREFIX ## builtins; \
    PyObject *PREFIX ## name; \
    PyObject *PREFIX ## qualname; \
    PyObject *PREFIX ## code;        /* A code object, the __code__ attribute */ \
    PyObject *PREFIX ## defaults;    /* NULL or a tuple */ \
    PyObject *PREFIX ## kwdefaults;  /* NULL or a dict */ \
    PyObject *PREFIX ## closure;     /* NULL or a tuple of cell objects */

// Range: 3.10 only
typedef struct {
    PyObject_HEAD30
    COMMON_FIELDS310(func_)
    PyObject* func_doc;         /* The __doc__ attribute, can be anything */
    PyObject* func_dict;        /* The __dict__ attribute, a dict or NULL */
    PyObject* func_weakreflist; /* List of weak references */
    PyObject* func_module;      /* The __module__ attribute, can be anything */
    PyObject* func_annotations; /* Annotations, a dict or NULL */
    vectorcallfunc vectorcall;

    /* Invariant:
     *     func_closure contains the bindings for func_code->co_freevars, so
     *     PyTuple_Size(func_closure) == PyCode_GetNumFree(func_code)
     *     (func_closure may be NULL if PyCode_GetNumFree(func_code) == 0).
     */
} PyFunctionObject310;

// Range: 3.11 only
typedef struct {
    PyObject_HEAD30
    COMMON_FIELDS310(func_)
    PyObject* func_doc;         /* The __doc__ attribute, can be anything */
    PyObject* func_dict;        /* The __dict__ attribute, a dict or NULL */
    PyObject* func_weakreflist; /* List of weak references */
    PyObject* func_module;      /* The __module__ attribute, can be anything */
    PyObject* func_annotations; /* Annotations, a dict or NULL */
    vectorcallfunc vectorcall;
    /* Version number for use by specializer.
     * Can set to non-zero when we want to specialize.
     * Will be set to zero if any of these change:
     *     defaults
     *     kwdefaults (only if the object changes, not the contents of the dict)
     *     code
     *     annotations */
    uint32_t func_version;

    /* Invariant:
     *     func_closure contains the bindings for func_code->co_freevars, so
     *     PyTuple_Size(func_closure) == PyCode_GetNumFree(func_code)
     *     (func_closure may be NULL if PyCode_GetNumFree(func_code) == 0).
     */
} PyFunctionObject311;

// Range: 3.12 - 3.13
typedef struct {
    PyObject_HEAD30
    COMMON_FIELDS310(func_)
    PyObject* func_doc;         /* The __doc__ attribute, can be anything */
    PyObject* func_dict;        /* The __dict__ attribute, a dict or NULL */
    PyObject* func_weakreflist; /* List of weak references */
    PyObject* func_module;      /* The __module__ attribute, can be anything */
    PyObject* func_annotations; /* Annotations, a dict or NULL */
    PyObject* func_typeparams;  /* Tuple of active type variables or NULL */
    vectorcallfunc vectorcall;
    /* Version number for use by specializer.
     * Can set to non-zero when we want to specialize.
     * Will be set to zero if any of these change:
     *     defaults
     *     kwdefaults (only if the object changes, not the contents of the dict)
     *     code
     *     annotations
     *     vectorcall function pointer */
    uint32_t func_version;

    /* Invariant:
     *     func_closure contains the bindings for func_code->co_freevars, so
     *     PyTuple_Size(func_closure) == PyCode_GetNumFree(func_code)
     *     (func_closure may be NULL if PyCode_GetNumFree(func_code) == 0).
     */
} PyFunctionObject312;


PyVersion GetPythonVersion();

template<typename T> bool PySwizzleGIL2(T func1, T func2) = delete;
template<> bool PySwizzleGIL2<PyFunctionObject*>(PyFunctionObject* func1, PyFunctionObject* func2);
template<> bool PySwizzleGIL2<PyFunctionObject20*>(PyFunctionObject20* func1, PyFunctionObject20* func2);
template<> bool PySwizzleGIL2<PyFunctionObject22*>(PyFunctionObject22* func1, PyFunctionObject22* func2);
template<> bool PySwizzleGIL2<PyFunctionObject23*>(PyFunctionObject23* func1, PyFunctionObject23* func2);
template<> bool PySwizzleGIL2<PyFunctionObject30*>(PyFunctionObject30* func1, PyFunctionObject30* func2);
template<> bool PySwizzleGIL2<PyFunctionObject33*>(PyFunctionObject33* func1, PyFunctionObject33* func2);
template<> bool PySwizzleGIL2<PyFunctionObject38*>(PyFunctionObject38* func1, PyFunctionObject38* func2);
template<> bool PySwizzleGIL2<PyFunctionObject310*>(PyFunctionObject310* func1, PyFunctionObject310* func2);
template<> bool PySwizzleGIL2<PyFunctionObject311*>(PyFunctionObject311* func1, PyFunctionObject311* func2);
template<> bool PySwizzleGIL2<PyFunctionObject312*>(PyFunctionObject312* func1, PyFunctionObject312* func2);