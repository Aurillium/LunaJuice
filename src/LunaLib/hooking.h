#pragma once
#include "hookingv2.h"
#include "hookingv3.h"
#include "hookingv4.h"

// Macro to make hooking easier
// Make sure you follow the naming format though!
// Hooked_{name}, Real_{name}
#define QUICK_HOOK(dll, name) (InstallHookV4(dll, #name, (void*)Hooked_##name, (void**)&Real_##name))
#define EXTERN_HOOK(name) extern name##_t Real_##name;

// Quickly define hooks
// Example:
// typedef BOOL(WINAPI* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
// BOOL WINAPI Hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
//
// Becomes:
// HOOKDEF(MessageBoxA, BOOL, WINAPI, (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType));
#define HOOKHEAD(name, calltype, ret, sig) \
typedef ret(calltype* name##_t)sig; \
ret calltype Hooked_##name##sig;

#define HOOKDEF(name, calltype, ret, sig) \
name##_t Real_##name; \
LPCSTR String_##name = #ret " " #calltype " " #name #sig; \
ret calltype Hooked_##name##sig

// These variables cannot be static, no matter what Visual Studio says:
// https://stackoverflow.com/questions/1358400/what-is-external-linkage-and-internal-linkage
// https://stackoverflow.com/questions/6469849/one-or-more-multiply-defined-symbols-found