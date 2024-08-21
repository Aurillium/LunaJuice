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
// You will need to free the return value and the string contained
SIGNATURE_FMT_HELPER* GetSignatureTemplate(LPCSTR signature) {
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
        
        SIGNATURE_FMT_HELPER* answer = (SIGNATURE_FMT_HELPER*)malloc(sizeof(SIGNATURE_FMT_HELPER));
        if (answer == NULL) {
            WRITELINE_DEBUG("Could not allocate memory for signature helper.");
            return NULL;
        }
        answer->fmtSignature = name;
        answer->numArgs = 0;
        return answer;
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

    SIGNATURE_FMT_HELPER* answer = (SIGNATURE_FMT_HELPER*)malloc(sizeof(SIGNATURE_FMT_HELPER));
    if (answer == NULL) {
        WRITELINE_DEBUG("Could not allocate memory for signature helper.");
        return NULL;
    }

    answer->fmtSignature = finalBuffer;
    answer->numArgs = numArgs;
    return answer;
}