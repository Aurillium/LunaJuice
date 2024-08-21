#include "pch.h"
#include <Windows.h>

#include "debug.h"
#include "hooks.h"

#include "include/capstone/capstone.h"

EXTERN_HOOK(NtReadFile);

// Function to determine the prologue length
size_t GetFunctionPrologueLength(IN void* functionAddress) {
    csh handle;
    cs_insn* insn;
    size_t count;
    size_t prologueLength = 0;
    const size_t MAX_INSTRUCTIONS = 14; // Limit to prevent excessive disassembly
    const size_t MIN_BYTES = 14;

    // Initialize Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return 0;
        // TODO: Error handling
    }

    // Disassemble the function
    count = cs_disasm(handle, (const uint8_t*)functionAddress, 64, (uint64_t)functionAddress, MAX_INSTRUCTIONS, &insn);
    if (count > 0) {
        // Determine the prologue length (commonly includes setup instructions like PUSH, MOV, etc.)
        // Example condition: terminate on a specific instruction or byte pattern
        for (size_t i = 0; i < count; i++) {
            prologueLength += insn[i].size;
            // Exit early if we have enough bytes to create trampoline
            if (prologueLength >= MIN_BYTES) {
                break;
            }
        }
        cs_free(insn, count);
    }
    cs_close(&handle);

    return prologueLength;
}

uintptr_t AdjustRelativeAddress(uintptr_t oldBase, uintptr_t newBase, int64_t displacement) {
    // As long as we have some base, not necessarily the exact address of the instruction,
    // we're good. We just can't change the lengths of any of them.
    return oldBase + displacement - newBase;
}

// TODO
// This will correct any issues associated with relative memory
BOOL SmartTrampoline(IN void* functionAddress, IN size_t prologueLength, IN void* trampoline) {
    csh handle;
    cs_insn* insn;
    size_t count;
    size_t baseOffset = 0;
    const size_t MAX_INSTRUCTIONS = 14; // Limit to prevent excessive disassembly
    const size_t MIN_BYTES = 14;

    // Initialize Capstone
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return 0;
        // TODO: Error handling
    }

    count = cs_disasm(handle, (const uint8_t*)functionAddress, 64, (uint64_t)functionAddress, prologueLength, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            cs_insn* instruction = &insn[i];

            if (instruction->id == X86_INS_JMP || instruction->id == X86_INS_CALL /*|| instruction->id == X86_CALL*/) {
                // Here we need to account for
                // - addresses within the trampoline going to other addresses within the trampoline
                // - addresses within the trampoline going outside the trampoline
                // - addresses outside the trampoline going inside the trampoline
                //   - May want to process entire function?

                // Why do we subtract the instruction address then add it back later?
                int64_t displacement = instruction->detail->x86.operands[0].imm;// -instruction->address;
                uintptr_t newDisplacement = AdjustRelativeAddress((uintptr_t)functionAddress, (uintptr_t)trampoline, displacement);

                // Modify the trampoline's instruction with the new displacement
                //instruction->detail->x86.operands[0].mem.
                uintptr_t offset = (uintptr_t)trampoline + (instruction->address - (uintptr_t)functionAddress);
                *(int32_t*)(offset + 1) = newDisplacement;
            }

            baseOffset += insn[i].size;
        }
    }
}

// Trampoline hooking
// More advanced than IAT but more stable (in theory)
BOOL InstallHookV3(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction) {
    // Get the DLL the function is from
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL) {
        WRITE_DEBUG("Failed to get module handle, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return false;
    }

    // Get target function address
    void* targetFunctionAddress = GetProcAddress(hModule, functionName);
    if (targetFunctionAddress == NULL) {
        WRITE_DEBUG("Could not find target function, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return false;
    }

    // Set up trampoline
    size_t prologueLength = GetFunctionPrologueLength(targetFunctionAddress);
    void* trampoline = VirtualAlloc(NULL, prologueLength + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (trampoline == NULL) {
        WRITE_DEBUG("Could not allocate trampoline, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return false;
    }
    // Copy first 14 bytes of function into beginning of trampoline
    memcpy(trampoline, targetFunctionAddress, prologueLength);

    // Address of after the first 14 bytes (these are in trampoline)
    uintptr_t trampolineJmpBackAddr = (uintptr_t)targetFunctionAddress + prologueLength;
    // Add the jump after original first 14 bytes
    *(BYTE*)((BYTE*)trampoline + prologueLength) = 0xFF;            // jmp setup
    *(BYTE*)((BYTE*)trampoline + prologueLength + 1) = 0x25;
    *(DWORD*)((BYTE*)trampoline + prologueLength + 2) = 0x00000000;     // end jmp setup
    *(uintptr_t*)((BYTE*)trampoline + prologueLength + 6) = trampolineJmpBackAddr;

    // Overwrite memory protection so we can write jump to hook
    DWORD oldProtect;
    if (!VirtualProtect(targetFunctionAddress, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        WRITE_DEBUG("Could change memory protection, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return false;
    }

    // Get address of hook
    uintptr_t hookFuncAddr = (uintptr_t)hookFunction;
    // https://github.com/bats3c/EvtMute/blob/master/EvtMute/EvtMuteHook/dllmain.cpp#L57
    // https://gist.github.com/benpturner/43b46506e4f98e5b860f72c3a6c42367
    // TAKEAWAYS: NEEDS TO BE LONGER, 0x41 extends registers to r8-r15
    // 0xC3 is ret, not needed here
    // 0x00 is noop
    // Update: going with absolute indirect jump for now
    // Write the jump towards hook function where the first 14 bytes used to be
    //*(BYTE*)targetFunctionAddress = 0x49;                 // mov r11, hookfunc
    //*(BYTE*)((BYTE*)targetFunctionAddress + 1) = 0xBB;
    //*(uintptr_t*)((BYTE*)targetFunctionAddress + 2) = hookFuncAddr;
    //*(BYTE*)((BYTE*)targetFunctionAddress + 10) = 0xFF;   // jmp r11
    //*(BYTE*)((BYTE*)targetFunctionAddress + 11) = 0xE3;

    // Write the jump towards hook function where the first 14 bytes used to be
    // Perform absolute indirect jump
    *(BYTE*)targetFunctionAddress = 0xFF;
    *(BYTE*)((BYTE*)targetFunctionAddress + 1) = 0x25;
    *(DWORD*)((BYTE*)targetFunctionAddress + 2) = 0x00000000;
    *(uintptr_t*)((BYTE*)targetFunctionAddress + 6) = hookFuncAddr;


    // Rewrite old protections
    if (!VirtualProtect(targetFunctionAddress, 14, oldProtect, &oldProtect)) {
        WRITE_DEBUG("Could restore memory protection, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return false;
    }

    // Send trampoline back as the original function
    *originalFunction = trampoline;

    // Debug info
    // NtReadFile is an example and function of interest
    WRITELINE_DEBUG("----------------------");
    WRITELINE_DEBUG("Function:             " << functionName);
    WRITELINE_DEBUG("Hook function:        " << hookFunction);
    WRITELINE_DEBUG("Original function:    " << *originalFunction);
    WRITELINE_DEBUG("Trampoline address:   " << trampoline);
    WRITELINE_DEBUG("Real NtReadFile:      " << (void*)Real_NtReadFile);
    WRITELINE_DEBUG("Trampoline[20...]:    " << (void*)*(uintptr_t*)((BYTE*)trampoline + 20));
    WRITELINE_DEBUG("Target function addr: " << targetFunctionAddress);
    WRITELINE_DEBUG("First jmp to:         " << (void*)*(uintptr_t*)((BYTE*)targetFunctionAddress + 2));
    WRITELINE_DEBUG("----------------------");

    // Real equals the target address, should equal trampoline -- this is because global variable is not changed (why?)

    WRITE_DEBUG("Successfully hooked ");
    WRITELINE_DEBUG(functionName);
}