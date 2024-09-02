#include "pch.h"
#include <Windows.h>

#include "shared_util.h"
#include "mitigations.h"

static LunaAPI::MitigationFlags mitigations;

LunaAPI::MitigationFlags GetMitigations()
{
	return mitigations;
}

// Potentially we would conduct some checks here
void SetMitigations(LunaAPI::MitigationFlags flags)
{
	mitigations = flags;
}
