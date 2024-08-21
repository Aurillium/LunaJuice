#pragma once
#include <malloc.h>
#include <stdio.h>
#include <Windows.h>

#include "util.h"

typedef struct _SIGNATURE_FMT_HELPER {
    LPSTR fmtSignature;
    SIZE_T numArgs;
} SIGNATURE_FMT_HELPER;

SIGNATURE_FMT_HELPER* GetSignatureTemplate(LPCSTR signature);

// WARNING: THESE MUST BE FREED
template <typename T>
static LPSTR CustomFmt(T data) {
    return OptimalSprintf("????");
}

// Integer
template <> static LPSTR CustomFmt<UINT64>(UINT64 value) {
    return OptimalSprintf("0x%016llX", value);
}
template <> static LPSTR CustomFmt<UINT32>(UINT32 value) {
    return OptimalSprintf("0x%08lX", value);
}
template <> static LPSTR CustomFmt<ULONG>(ULONG value) {
    return OptimalSprintf("0x%08lX", value);
}
template <> static LPSTR CustomFmt<UINT16>(UINT16 value) {
    return OptimalSprintf("0x%04hX", value);
}
template <> static LPSTR CustomFmt<UINT8>(UINT8 value) {
    return OptimalSprintf("0x%02hX", value);
}
// Unsigned Integer
template <> static LPSTR CustomFmt<INT64>(INT64 value) {
    return OptimalSprintf("%lld", value);
}
template <> static LPSTR CustomFmt<INT32>(INT32 value) {
    return OptimalSprintf("%ld", value);
}
template <> static LPSTR CustomFmt<LONG>(LONG value) {
    return OptimalSprintf("%ld", value);
}
template <> static LPSTR CustomFmt<INT16>(INT16 value) {
    return OptimalSprintf("%hd", value);
}
template <> static LPSTR CustomFmt<INT8>(INT8 value) {
    return OptimalSprintf("%hhd", value);
}

// Float
template <> static LPSTR CustomFmt<float>(float value) {
    return OptimalSprintf("%.6f", value);
}
template <> static LPSTR CustomFmt<double>(double value) {
    return OptimalSprintf("%.6f", value);
}

// Character
template <> static LPSTR CustomFmt<char>(char value) {
    return OptimalSprintf("\"%s\"", value);
}
template <> static LPSTR CustomFmt<char*>(char* value) {
    return OptimalSprintf("'%c'", value);
}

// void*
template <> static LPSTR CustomFmt<void*>(void* value) {
    return OptimalSprintf("0x%016llX", value);
}

// Integer Pointers
template <> static LPSTR CustomFmt<PUINT64>(PUINT64 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (0x%016llX)", value, *value);
}
template <> static LPSTR CustomFmt<PUINT32>(PUINT32 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (0x%08lX)", value, *value);
}
template <> static LPSTR CustomFmt<PULONG>(PULONG value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (0x%08lX)", value, *value);
}
template <> static LPSTR CustomFmt<PUINT16>(PUINT16 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (0x%04hX)", value, *value);
}
template <> static LPSTR CustomFmt<PUINT8>(PUINT8 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (0x%02hX)", value, *value);
}
// Unsigned Integer Pointers
template <> static LPSTR CustomFmt<PINT64>(PINT64 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (%lld)", value, *value);
}
template <> static LPSTR CustomFmt<PINT32>(PINT32 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (%ld)", value, *value);
}
template <> static LPSTR CustomFmt<PLONG>(PLONG value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (%ld)", value, *value);
}
template <> static LPSTR CustomFmt<PINT16>(PINT16 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (%hd)", value, *value);
}
template <> static LPSTR CustomFmt<PINT8>(PINT8 value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (%hhd)", value, *value);
}
// Float Pointers
template <> static LPSTR CustomFmt<float*>(float* value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (%.6f)", value, *value);
}
template <> static LPSTR CustomFmt<double*>(double* value) {
    if (value == NULL) return OptimalSprintf("NULL");
    return OptimalSprintf("%p (%.6f)", value, *value);
}


static void storeValues(LPSTR* arr, size_t index) {
    // Base case does nothing.
}
template <typename T>
static void fmtAndStore(LPSTR* arr, size_t index, const T& first) {
    arr[index] = CustomFmt(first);
}
template <typename First, typename... Rest>
static void fmtAndStore(LPSTR* arr, size_t index, const First& first, const Rest&... rest) {
    arr[index] = CustomFmt(first);
    fmtAndStore(arr, index + 1, rest...);
}

template <typename... T>
static LPSTR FormatSignature(LPCSTR fmtTemplate, SIZE_T size, T... arguments) {
    LPSTR* values = (LPSTR*)calloc(size, sizeof(LPSTR));
    if (values == NULL) {
        WRITELINE_DEBUG("Could not allocate space to store formatted values.");
        return NULL;
    }

    fmtAndStore(values, 0, arguments...);

    size_t bufferSize = vsnprintf(NULL, 0, fmtTemplate, (va_list)values);
    LPSTR answer = (LPSTR)calloc(bufferSize + 1, sizeof(CHAR));
    if (answer == NULL) {
        WRITELINE_DEBUG("Could not allocate space for final signature format.");
        return NULL;
    }

    vsprintf_s(answer, bufferSize + 1, fmtTemplate, (va_list)values);

    // Free values we're done with
    for (size_t i = 0; i < size; i++) {
        free(values[i]);
    }
    free(values);

    return answer;
}