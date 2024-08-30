#include "pch.h"
#include <Windows.h>

#include "shared.h"
#include "mitigations.h"

static MitigationFlags mitigations;

MitigationFlags GetMitigations()
{
	return mitigations;
}

// Potentially we would conduct some checks here
void SetMitigations(MitigationFlags flags)
{
	mitigations = flags;
}
