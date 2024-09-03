#include "pch.h"
#include <iostream>
#include <random>

#include "Config.h"
#include "random.h"
#include "output.h"

using namespace LunaAPI;

LunaStart::LunaStart() {
    RandomString(id, LUNA_ID_CHARACTERS, LUNA_MAX_ID_LENGTH);
    hooks = DEFAULT_HOOKS;
    mitigations = Mitigate_None;
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
    mitigations = Mitigate_None;
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