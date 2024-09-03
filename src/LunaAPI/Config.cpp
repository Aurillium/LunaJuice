#include "pch.h"
#include <iostream>

#include "Config.h"
#include "output.h"

using namespace LunaAPI;

void RandomString(char* buffer, const char* options, size_t length) {
    size_t numOptions = strlen(options);
    for (size_t i = 0; i < length; i++) {
        buffer[i] = options[rand() % numOptions];
    }
}

LunaStart::LunaStart() {
    RandomString(id, LUNA_ID_CHARACTERS, LUNA_MAX_ID_LENGTH);
    hooks = DEFAULT_HOOKS;
    mitigations = NoMitigations;
}

LunaStart::LunaStart(LPCSTR implantID) {
    if (implantID == NULL || implantID[0] == 0) {
        RandomString(id, LUNA_ID_CHARACTERS, LUNA_MAX_ID_LENGTH);
    } else {
        size_t idLength = strlen(implantID);
        if (idLength > LUNA_MAX_ID_LENGTH) {
            DISP_WARN("Implant ID cannot be above " << LUNA_MAX_ID_LENGTH << "Characters. '" << implantID << "' will be truncated");
        }
        memcpy_s(id, LUNA_MAX_ID_LENGTH, implantID, idLength);
    }
    
    hooks = DEFAULT_HOOKS;
    mitigations = NoMitigations;
}

BOOL LunaStart::SetID(LPCSTR implantID) {
    if (implantID == NULL) {
        return FALSE;
    }
    size_t idLength = strlen(implantID);
    if (idLength > LUNA_MAX_ID_LENGTH) {
        DISP_WARN("Implant ID cannot be above " << LUNA_MAX_ID_LENGTH << "Characters. '" << implantID << "' will be truncated");
    }
    memcpy_s(id, LUNA_MAX_ID_LENGTH, implantID, idLength);
    return TRUE;
}