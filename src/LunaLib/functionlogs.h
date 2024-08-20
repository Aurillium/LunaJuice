#pragma once
#include <Windows.h>

LPSTR GetSignatureTemplate(LPCSTR signature);

// What to do before the format can be used
typedef enum _FmtSignatureFlags {
	NONE,
	UNKNOWN,
	//GET_BYTES, // Get the bytes of a byte array and convert them to hex for display
	RESOLVE_POINTER // Resolve a pointer and display its value
} FMT_SIGNATURE_FLAGS;

typedef struct _FmtSignature {
	LPSTR finalSignature;
	FMT_SIGNATURE_FLAGS* flags;
	SIZE_T size;
} FMT_SIGNATURE;

FMT_SIGNATURE* GetTypeSpecificSignature(LPCSTR fmtTemplate, SIZE_T size, LPSTR* arguments);
LPSTR FormatFromSignatureInfo(FMT_SIGNATURE* fmtSignature, void** arguments);