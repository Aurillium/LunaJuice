#include "pch.h"

#include "debug.h"
#include "functionlogs.h"
#include "util.h"

// This could be using both indexing and direct memory operations
// That could cause instability when type sizes are unexpected
// (sizeof(CHAR) != 1), but not sure

// This function can parse invalid signatures, these should not be passed in
// For performance's sake, the macro generating signatures should work and not
// need to be checked at runtime
// Only data from the macro should be passed in, and then if there are invalid
// signatures there you will have bigger problems than this function
// You will need to free this string
LPSTR GetSignatureTemplate(LPCSTR signature) {
    size_t index = 0;
    int stage = 0;
    size_t nameLength = 0;
    size_t numArgs = 0;
    size_t length = 0;
    bool onlyWhitespace = true;
    LPSTR name = NULL;
    while (TRUE) {
        // Invalid string passed
        if (signature[index] == '\0') {
            WRITELINE_DEBUG("Unexpected end of signature.");
            return NULL;
        }

        if (stage == 0) {
            if (signature[index] == '(') {
                // Logic:
                //   String where index = 0 and signature[index] = '(' would have
                //   function name of 0 length
                nameLength = index;
                // +3 is a little optimisation
                // If there are no args, we can put the brackets into the same buffer and return
                // Takes up less memory and CPU time than creating a new buffer to copy into
                name = (LPSTR)calloc(nameLength + 3, sizeof(CHAR));
                if (name == NULL) {
                    WRITELINE_DEBUG("Could not allocate memory to store function name.");
                    return NULL;
                }
                // Copy name in
                memcpy_s(name, nameLength * sizeof(CHAR), signature, nameLength * sizeof(CHAR));
                stage = 1;
            }
            else if (signature[index] == ')' || signature[index] == ',') {
                // Obviously more characters make this signature invalid, but
                // these are the ones that affect parsing
                WRITELINE_DEBUG("Encountered closing bracket or comma in function name.");
                return NULL;
            }
        }
        else if (stage == 1) {
            if (signature[index] == ')') {
                // numArgs is 0 if onlyWhitespace
                break;
            }

            if (onlyWhitespace && NOT_WHITESPACE(signature[index])) {
                onlyWhitespace = false;
                numArgs = 1; // From 0
            }

            if (signature[index] == ',') {
                numArgs++;
            }
            else if (signature[index] == '(') {
                WRITELINE_DEBUG("Encountered opening bracket in function arguments.");
                return NULL;
            }
        }
        index++;
    }

    // I couldn't compile without initialising it in a way the
    // compiler understands
    if (name == NULL) {
        WRITELINE_DEBUG("An unknown error has occurred in parsing.");
    }

    // As we break on close bracket, the length is
    // the current index + that bracket
    length = index + 1;

    if (numArgs == 0) {
        // Remember the optimisation from earlier?
        name[nameLength] = '(';
        name[nameLength + 1] = ')';
        return name;
    }

    index = 0;
    stage = 0;
    LPSTR* arguments = (LPSTR*)calloc(numArgs, sizeof(LPSTR));
    size_t* argLengths = (size_t*)calloc(numArgs, sizeof(size_t));
    if (arguments == NULL || argLengths == NULL) {
        WRITELINE_DEBUG("Could not allocate memory for arguments and argument lengths.");
        free(name);
        return NULL;
    }

    // Now look at each argument and build a template string for it
    // At the end we merge all of these together using the power of
    // friendship and lots of string operations.

    size_t argStart = 0;
    size_t argIndex = 0;
    // Start as name length
    // The two brackets are accounted for as room for a comma and
    // space are added with each argument, and the last argument
    // doesn't need this
    size_t finalLength = nameLength;
    BOOL sawChars = FALSE;

    while (TRUE) {
        if (stage == 0 && signature[index] == '(') {
            argStart = index + 1;
            stage = 1;
        }
        else if (stage == 1) {
            if (!sawChars && IS_WHITESPACE(signature[index])) {
                // This helps us avoid leading spaces, leading to neater and more predictable logs
                // This does not fix trailing whitespace, but that shouldn't happen really
                argStart = index + 1;
            }
            else if (signature[index] == ',' || signature[index] == ')') {
                size_t argLength = index - argStart;
                // " = %s" (5) + '\0'
                size_t allocLength = argLength + 6 * sizeof(CHAR);
                arguments[argIndex] = (LPSTR)calloc(allocLength, sizeof(CHAR));
                // Remove null byte in copy
                argLengths[argIndex] = allocLength - sizeof(CHAR);
                if (arguments[argIndex] == NULL) {
                    WRITELINE_DEBUG("Could not allocate memory for argument string.");
                    // Free all arguments up until this point
                    for (size_t i = 0; i < argIndex; i++) {
                        free(arguments[i]);
                    }
                    free(arguments);
                    free(argLengths);
                    free(name);
                    return NULL;
                }
                // The same reasoning, but with a comma and space (hence +1)
                // Not needed for the last argument, but this accounts
                // for the two brackets not accounted for at initialisation
                finalLength += allocLength + sizeof(CHAR);

                // Copy argument in
                memcpy_s(arguments[argIndex], argLength * sizeof(CHAR), signature + argStart * sizeof(CHAR), argLength * sizeof(CHAR));
                LPSTR current = arguments[argIndex];
                current[argLength    ] = ' ';
                current[argLength + 1] = '=';
                current[argLength + 2] = ' ';
                current[argLength + 3] = '%';
                current[argLength + 4] = 's';

                if (signature[index] == ')') {
                    break;
                }

                argIndex++;
                argStart = index + 1;
                sawChars = FALSE;
            }
            else {
                sawChars = TRUE;
            }
        }
        index++;
    }

    // Final length, +1 for null byte
    LPSTR finalBuffer = (LPSTR)calloc(finalLength + 1, sizeof(CHAR));
    if (finalBuffer == NULL) {
        WRITELINE_DEBUG("Could not allocate memory for final template.");
        // Free all arguments and name
        for (size_t i = 0; i < numArgs; i++) {
            free(arguments[i]);
        }
        free(arguments);
        free(argLengths);
        free(name);
        return NULL;
    }

    // Start with function name
    memcpy_s(finalBuffer, finalLength, name, nameLength);
    finalBuffer[nameLength] = '(';

    // Set index to start from
    index = nameLength + 1;
    for (size_t i = 0; i < numArgs; i++) {
        // Copy the argument into the final buffer
        memcpy_s(finalBuffer + index, finalLength - index, arguments[i], argLengths[i]);
        index += argLengths[i];
        // Add comma and space if we're not doing the last argument
        if (i != numArgs - 1) {
            finalBuffer[index] = ',';
            finalBuffer[index + 1] = ' ';
            // Make sure we increase the index
            index += 2;
        }
    }
    finalBuffer[index] = ')';

    // Cleanup
    for (size_t i = 0; i < numArgs; i++) {
        free(arguments[i]);
    }
    free(arguments);
    free(argLengths);
    free(name);

    return finalBuffer;
}

FMT_SIGNATURE* GetTypeSpecificSignature(LPCSTR fmtTemplate, SIZE_T size, LPSTR* arguments) {

    FMT_SIGNATURE* answer = (FMT_SIGNATURE*)malloc(sizeof(FMT_SIGNATURE));
    if (answer == NULL) {
        WRITELINE_DEBUG("Could not allocate memory to store answer.");
        return NULL;
    }
    answer->size = size;
    answer->flags = (FMT_SIGNATURE_FLAGS*)calloc(size, sizeof(FMT_SIGNATURE_FLAGS));
    if (answer->flags == NULL) {
        WRITELINE_DEBUG("Could not allocate memory to store format flags.");
        free(answer);
        return NULL;
    }
    LPCSTR* formats = (LPCSTR*)calloc(size, sizeof(LPCSTR));
    for (size_t i = 0; i < size; i++) {
        LPCSTR arg = arguments[i];

        // ============
        //   integers
        // ============

        // 64-bit integers
        if (!strcmp(arg, "HANDLE") ||
            !strcmp(arg, "UINT64") ||
            !strcmp(arg, "ULONGLONG") ||
            !strcmp(arg, "ULONG64") ||
            !strcmp(arg, "unsigned long long") ||
            !strcmp(arg, "unsigned long long int") ||
            !strcmp(arg, "__int64") ||
            !strcmp(arg, "unsigned __int64")
            ) {
            formats[i] = "0x%016llX";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "INT64") ||
            !strcmp(arg, "LONGLONG") ||
            !strcmp(arg, "LONG64") ||
            !strcmp(arg, "long long") ||
            !strcmp(arg, "long long int") ||
            !strcmp(arg, "__int64") ||
            !strcmp(arg, "signed long long") ||
            !strcmp(arg, "signed long long int") ||
            !strcmp(arg, "signed __int64")
            ) {
            formats[i] = "%lld";
            answer->flags[i] = NONE;
        }
        // 32-bit integers
        else if (
            !strcmp(arg, "DWORD") ||
            !strcmp(arg, "UINT32") ||
            !strcmp(arg, "UINT") ||
            !strcmp(arg, "ULONG") ||
            !strcmp(arg, "ULONG32") ||
            !strcmp(arg, "unsigned long") ||
            !strcmp(arg, "unsigned long int") ||
            !strcmp(arg, "__uint32") ||
            !strcmp(arg, "unsigned __int32") ||
            !strcmp(arg, "unsigned int") ||
            !strcmp(arg, "unsigned")
            ) {
            formats[i] = "0x%08lX";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "INT32") ||
            !strcmp(arg, "INT") ||
            !strcmp(arg, "LONG") ||
            !strcmp(arg, "LONG32") ||
            !strcmp(arg, "long") ||
            !strcmp(arg, "long int") ||
            !strcmp(arg, "__int32") ||
            !strcmp(arg, "__char32_t") ||
            !strcmp(arg, "signed long") ||
            !strcmp(arg, "signed long int") ||
            !strcmp(arg, "signed __int32") ||
            !strcmp(arg, "int") ||
            !strcmp(arg, "signed") ||
            !strcmp(arg, "signed int")
            ) {
            formats[i] = "%ld";
            answer->flags[i] = NONE;
        }
        // 16-bit integers
        else if (
            !strcmp(arg, "WORD") ||
            !strcmp(arg, "UINT16") ||
            !strcmp(arg, "USHORT") ||
            !strcmp(arg, "WCHAR") ||
            !strcmp(arg, "unsigned short") ||
            !strcmp(arg, "__uint16") ||
            !strcmp(arg, "unsigned __int16") ||
            !strcmp(arg, "wchar_t") ||
            !strcmp(arg, "__wchar_t")
            ) {
            formats[i] = "0x%04hX";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "INT16") ||
            !strcmp(arg, "SHORT") ||
            !strcmp(arg, "signed short") ||
            !strcmp(arg, "short") ||
            !strcmp(arg, "signed __int16") ||
            !strcmp(arg, "__int16") ||
            !strcmp(arg, "__char16_t")
            ) {
            formats[i] = "%hd";
            answer->flags[i] = NONE;
        }
        // 8-bit integers
        else if (
            !strcmp(arg, "UINT8") ||
            !strcmp(arg, "UCHAR") ||
            !strcmp(arg, "BYTE") ||
            !strcmp(arg, "unsigned char") ||
            !strcmp(arg, "__uint8") ||
            !strcmp(arg, "unsigned __int8")
            ) {
            formats[i] = "0x%02hhx";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "INT8") ||
            !strcmp(arg, "signed __int8") ||
            !strcmp(arg, "__int8")
            ) {
            formats[i] = "%hdd";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "CHAR") ||
            !strcmp(arg, "char") ||
            !strcmp(arg, "signed char")
            ) {
            formats[i] = "'%c'";
            answer->flags[i] = NONE;
        }
        // ============
        //    floats
        // ============
        
        // 64-bit floats
        else if (
            !strcmp(arg, "DOUBLE") ||
            !strcmp(arg, "double") ||
            !strcmp(arg, "long double") ||
            !strcmp(arg, "long float")
            ) {
            formats[i] = "%.6f";
            answer->flags[i] = NONE;
        }
        // 32-bit floats
        else if (
            !strcmp(arg, "FLOAT") ||
            !strcmp(arg, "FLOAT32") ||
            !strcmp(arg, "float") ||
            !strcmp(arg, "float_t")
            ) {
            formats[i] = "%.6f";
            answer->flags[i] = NONE;
        }
        // ============
        //    strings
        // ============
        else if (
            !strcmp(arg, "LPSTR") ||
            !strcmp(arg, "LPCSTR") ||
            !strcmp(arg, "PSTR") ||
            !strcmp(arg, "PCSTR") ||
            !strcmp(arg, "char*") ||
            !strcmp(arg, "signed char*") ||
            !strcmp(arg, "CHAR*")
            ) {
            formats[i] = "\"%s\"";
            answer->flags[i] = NONE;
        }
        // ============
        //   pointers
        // ============
        
        // 64-bit integers
        else if (!strcmp(arg, "LPUINT64") ||
            !strcmp(arg, "PUINT64") ||
            !strcmp(arg, "UINT64*") ||
            !strcmp(arg, "LPULONGLONG") ||
            !strcmp(arg, "PULONGLONG") ||
            !strcmp(arg, "ULONGLONG*") ||
            !strcmp(arg, "LPULONG64") ||
            !strcmp(arg, "PULONG64") ||
            !strcmp(arg, "ULONG64*") ||
            !strcmp(arg, "unsigned long long*") ||
            !strcmp(arg, "unsigned long long int*") ||
            !strcmp(arg, "__int64*") ||
            !strcmp(arg, "unsigned __int64*")
            ) {
            formats[i] = "%p (0x%016llX)";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "LPINT64") ||
            !strcmp(arg, "PINT64") ||
            !strcmp(arg, "INT64*") ||
            !strcmp(arg, "LPLONGLONG") ||
            !strcmp(arg, "PLONGLONG") ||
            !strcmp(arg, "LONGLONG*") ||
            !strcmp(arg, "LPLONG64") ||
            !strcmp(arg, "PLONG64") ||
            !strcmp(arg, "LONG64*") ||
            !strcmp(arg, "long long*") ||
            !strcmp(arg, "long long int*") ||
            !strcmp(arg, "__int64*") ||
            !strcmp(arg, "signed long long*") ||
            !strcmp(arg, "signed long long int*") ||
            !strcmp(arg, "signed __int64*")
            ) {
            formats[i] = "%p (%lld)";
            answer->flags[i] = NONE;
        }
        // 32-bit integers
        else if (
            !strcmp(arg, "LPDWORD") ||
            !strcmp(arg, "PDWORD") ||
            !strcmp(arg, "DWORD*") ||
            !strcmp(arg, "LPUINT32") ||
            !strcmp(arg, "PUINT32") ||
            !strcmp(arg, "UINT32*") ||
            !strcmp(arg, "LPUINT") ||
            !strcmp(arg, "PUINT") ||
            !strcmp(arg, "UINT*") ||
            !strcmp(arg, "LPULONG") ||
            !strcmp(arg, "PULONG") ||
            !strcmp(arg, "ULONG*") ||
            !strcmp(arg, "LPULONG32") ||
            !strcmp(arg, "PULONG32") ||
            !strcmp(arg, "ULONG32*") ||
            !strcmp(arg, "unsigned long*") ||
            !strcmp(arg, "unsigned long int*") ||
            !strcmp(arg, "__uint32*") ||
            !strcmp(arg, "unsigned __int32*") ||
            !strcmp(arg, "unsigned int*") ||
            !strcmp(arg, "unsigned*")
            ) {
            formats[i] = "%p (0x%08lX)";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "LPINT32") ||
            !strcmp(arg, "PINT32") ||
            !strcmp(arg, "INT32*") ||
            !strcmp(arg, "LPINT") ||
            !strcmp(arg, "PINT") ||
            !strcmp(arg, "INT*") ||
            !strcmp(arg, "LPLONG") ||
            !strcmp(arg, "PLONG") ||
            !strcmp(arg, "LONG*") ||
            !strcmp(arg, "LPLONG32") ||
            !strcmp(arg, "PLONG32") ||
            !strcmp(arg, "LONG32*") ||
            !strcmp(arg, "long*") ||
            !strcmp(arg, "long int*") ||
            !strcmp(arg, "__int32*") ||
            !strcmp(arg, "__char32_t*") ||
            !strcmp(arg, "signed long*") ||
            !strcmp(arg, "signed long int*") ||
            !strcmp(arg, "signed __int32*") ||
            !strcmp(arg, "int*") ||
            !strcmp(arg, "signed*") ||
            !strcmp(arg, "signed int*")
            ) {
            formats[i] = "%p (%ld)";
            answer->flags[i] = NONE;
        }
        // 16-bit integers
        else if (
            !strcmp(arg, "LPWORD") ||
            !strcmp(arg, "PWORD") ||
            !strcmp(arg, "WORD*") ||
            !strcmp(arg, "LPUINT16") ||
            !strcmp(arg, "PUINT16") ||
            !strcmp(arg, "UINT16*") ||
            !strcmp(arg, "LPUSHORT") ||
            !strcmp(arg, "PUSHORT") ||
            !strcmp(arg, "USHORT*") ||
            !strcmp(arg, "LPWCHAR") ||
            !strcmp(arg, "PWCHAR") ||
            !strcmp(arg, "WCHAR*") ||
            !strcmp(arg, "unsigned short*") ||
            !strcmp(arg, "__uint16*") ||
            !strcmp(arg, "unsigned __int16*") ||
            !strcmp(arg, "wchar_t*") ||
            !strcmp(arg, "__wchar_t*")
            ) {
            formats[i] = "%p (0x%04hX)";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "LPINT16") ||
            !strcmp(arg, "PINT16") ||
            !strcmp(arg, "INT16*") ||
            !strcmp(arg, "LPSHORT") ||
            !strcmp(arg, "PSHORT") ||
            !strcmp(arg, "SHORT*") ||
            !strcmp(arg, "signed short*") ||
            !strcmp(arg, "short*") ||
            !strcmp(arg, "signed __int16*") ||
            !strcmp(arg, "__int16*") ||
            !strcmp(arg, "__char16_t*")
            ) {
            formats[i] = "%p (%hd)";
            answer->flags[i] = NONE;
        }
        // 8-bit integers
        else if (
            !strcmp(arg, "LPUINT8") ||
            !strcmp(arg, "PUINT8") ||
            !strcmp(arg, "UINT8*") ||
            !strcmp(arg, "LPUCHAR") ||
            !strcmp(arg, "PUCHAR") ||
            !strcmp(arg, "UCHAR*") ||
            !strcmp(arg, "LPBYTE") ||
            !strcmp(arg, "PBYTE") ||
            !strcmp(arg, "BYTE*") ||
            !strcmp(arg, "unsigned char*") ||
            !strcmp(arg, "__uint8*") ||
            !strcmp(arg, "unsigned __int8*")
            ) {
            formats[i] = "%p (0x%02hhx)";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "LPINT8") ||
            !strcmp(arg, "PINT8") ||
            !strcmp(arg, "INT8*") ||
            !strcmp(arg, "signed __int8*") ||
            !strcmp(arg, "__int8*")
            ) {
            formats[i] = "%p (%hdd)";
            answer->flags[i] = NONE;
        }
        else if (
            !strcmp(arg, "LPCHAR") ||
            !strcmp(arg, "PCHAR")
            ) {
            formats[i] = "%p ('%c')";
            answer->flags[i] = NONE;
        }
        // 64-bit floats
        else if (
            !strcmp(arg, "LPDOUBLE") ||
            !strcmp(arg, "PDOUBLE") ||
            !strcmp(arg, "DOUBLE*") ||
            !strcmp(arg, "double*") ||
            !strcmp(arg, "long double*") ||
            !strcmp(arg, "long float*")
            ) {
            formats[i] = "%p (%.6f)";
            answer->flags[i] = NONE;
        }
        // 32-bit floats
        else if (
            !strcmp(arg, "LPFLOAT") ||
            !strcmp(arg, "PFLOAT") ||
            !strcmp(arg, "FLOAT*") ||
            !strcmp(arg, "LPFLOAT32") ||
            !strcmp(arg, "PFLOAT32") ||
            !strcmp(arg, "FLOAT32*") ||
            !strcmp(arg, "float*") ||
            !strcmp(arg, "float_t*")
            ) {
            formats[i] = "%p (%.6f)";
            answer->flags[i] = NONE;
        }
        // ============
        //     else
        // ============
        else {
            formats[i] = "????";
            answer->flags[i] = UNKNOWN;
        }
    }

    size_t bufferSize = vsnprintf(NULL, 0, fmtTemplate, (va_list)formats);
    answer->finalSignature = (LPSTR)calloc(bufferSize + 1, sizeof(CHAR));
    if (answer->finalSignature == NULL) {
        WRITELINE_DEBUG("Could not allocate space for final signature format.");
        free(answer->flags);
        free(answer);
        return NULL;
    }

    vsprintf_s(answer->finalSignature, bufferSize + 1, fmtTemplate, (va_list)formats);

    return answer;
}

// Look at buffer overrun
LPSTR FormatFromSignatureInfo(FMT_SIGNATURE* fmtSignature, void** arguments) {

    void** finalArgs;
    size_t finalArgsSize = fmtSignature->size;
    for (size_t i = 0; i < fmtSignature->size; i++) {
        // We need an extra space for the value of the pointer
        if (fmtSignature->flags[i] == RESOLVE_POINTER) {
            finalArgsSize++;
        }
    }
    finalArgs = (void**)calloc(finalArgsSize, sizeof(void*));
    if (finalArgs == NULL) {
        WRITELINE_DEBUG("Could not allocate space for final argument values.");
        return NULL;
    }
    size_t index = 0;
    for (size_t i = 0; i < fmtSignature->size; i++) {
        finalArgs[index] = arguments[index];
        if (fmtSignature->flags[i] == RESOLVE_POINTER) {
            index++;
            finalArgs[index] = *(void**)(arguments[index]);
        } else if (fmtSignature->flags[i] == UNKNOWN) {
            index--;
        }
        index++;
    }

    size_t bufferSize = vsnprintf(NULL, 0, fmtSignature->finalSignature, (va_list)finalArgs);
    LPSTR call = (LPSTR)calloc(bufferSize + 1, sizeof(CHAR));
    if (call == NULL) {
        WRITELINE_DEBUG("Could not allocate space for final call string.");
        free(finalArgs);
        return NULL;
    }

    vsprintf_s(call, bufferSize + 1, fmtSignature->finalSignature, (va_list)finalArgs);

    free(finalArgs);

    return call;
}