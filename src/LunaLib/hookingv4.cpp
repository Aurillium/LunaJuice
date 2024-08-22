#include "pch.h"
#include <iostream>
#include <Windows.h>

#include "debug.h"
#include "hooks.h"

#include "include/capstone/capstone.h"

EXTERN_HOOK(NtReadFile);

#define RELATIVE_JUMP_LENGTH 5

// Lots of code either from or based on https://kylehalladay.com/blog/2020/11/13/Hooking-By-Example.html
// Most of my contribution is comments and changes, this was more advanced than my planned technique

// Try to allocate some memory near an address
// Helps us hook functions more effectively; it means
// we can minimise the prologue to ~5 bytes
// Must be freed when we're done with it
void* AllocatePageNearAddress(void* targetAddr)
{
    // Get page size
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

    // Find page boundaries
    uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); // Round down to nearest page boundary
    uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
    uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

    // Get page
    uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

    uint64_t pageOffset = 1;
    while (1)
    {
        uint64_t byteOffset = pageOffset * PAGE_SIZE;
        uint64_t highAddr = startPage + byteOffset;
        uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

        // This would mean we can't find a compatible page
        bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

        // Try to allocate a whole page at a compatible address
        if (highAddr < maxAddr)
        {
            void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr)
                return outAddr;
        }

        if (lowAddr > minAddr)
        {
            void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (outAddr != nullptr)
                return outAddr;
        }

        pageOffset++;

        // No compatible page
        if (needsExit)
        {
            break;
        }
    }

    return nullptr;
}

// Writes a jump to target at overwrite
void WriteAbsoluteJump64(void* overwrite, void* target)
{
    // Jump template (blank bytes become address)
    uint8_t jumpCode[] = {
        0x49, 0xBA,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE2 // Jump to r10. We use r10 because it is
                         // not used in the calling conventions
    };

    // Get address as 64-bit int
    uint64_t address = (uint64_t)target;
    // Write passed address into operand
    memcpy(&jumpCode[2], &address, sizeof(address));
    // Write finished instruction to memory
    memcpy(overwrite, jumpCode, sizeof(jumpCode));
}

struct X64Instructions
{
    cs_insn* instructions;
    uint32_t numInstructions;
    uint32_t numBytes;
};

X64Instructions GetPrologue(void* function) {
    const size_t MAX_INSTRUCTIONS = RELATIVE_JUMP_LENGTH; // Limit to prevent excessive disassembly
    const size_t MIN_BYTES = RELATIVE_JUMP_LENGTH;

    // Start up Capstone
    csh handle;
    cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    size_t count;
    cs_insn* disassembledInstructions; // Manually free later
    // Start disassembly
    count = cs_disasm(handle, (uint8_t*)function, 20, (uint64_t)function, MAX_INSTRUCTIONS, &disassembledInstructions);

    // Record prologue byte and instruction length
    uint32_t prologueLength = 0;
    uint32_t prologueInstructions = 0;
    for (int32_t i = 0; i < count; ++i)
    {
        // Add to byte length
        prologueLength += disassembledInstructions[i].size;
        // Increment instructions
        prologueInstructions++;
        // Break if we have enough space
        if (prologueLength >= MIN_BYTES) break;
    }

    // Replace original with no-op bytes
    memset(function, 0x90, prologueLength);

    // Close handle and return info
    cs_close(&handle);
    return { disassembledInstructions, prologueInstructions, prologueLength };
}

// Get displacement
// There's a few types it can be though depending on the instruction
// So we use a template
template<class T>
T GetDisplacement(cs_insn* inst, uint8_t offset)
{
    T disp;
    memcpy(&disp, &inst->bytes[offset], sizeof(T));
    return disp;
}

// "Rewrite instruction bytes so that any RIP-relative displacement operands
//  make sense with wherever we're relocating to"
// This is complex
void RelocateInstruction(cs_insn* inst, void* dstLocation)
{
    cs_x86* x86 = &(inst->detail->x86);
    uint8_t offset = x86->encoding.disp_offset;

    uint64_t displacement = inst->bytes[x86->encoding.disp_offset];
    switch (x86->encoding.disp_size)
    {
        case 1:
        {
            int8_t disp = GetDisplacement<uint8_t>(inst, offset);
            disp -= uint64_t(dstLocation) - inst->address;
            memcpy(&inst->bytes[offset], &disp, 1);
        }
        break;

        case 2:
        {
            int16_t disp = GetDisplacement<uint16_t>(inst, offset);
            disp -= uint64_t(dstLocation) - inst->address;
            memcpy(&inst->bytes[offset], &disp, 2);
        }
        break;

        case 4:
        {
            int32_t disp = GetDisplacement<int32_t>(inst, offset);
            disp -= uint64_t(dstLocation) - inst->address;
            memcpy(&inst->bytes[offset], &disp, 4);
        }
        break;
    }
}

bool IsRIPRelativeInstr(cs_insn& inst)
{
    cs_x86* x86 = &(inst.detail->x86);

    for (uint32_t i = 0; i < inst.detail->x86.op_count; i++)
    {
        cs_x86_op* op = &(x86->operands[i]);

        // Check if memory type is RIP relative, like lea rcx,[rip+0xbeef]
        // Second condition is if we are relative to RIP
        return op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP;
    }

    return false;
}

// All relative calls start with E8 in x64
bool IsRelativeCall(cs_insn& inst)
{
    bool isCall = inst.id == X86_INS_CALL;
    bool startsWithE8 = inst.bytes[0] == 0xE8;
    return isCall && startsWithE8;
}
// This is more complex
bool IsRelativeJump(cs_insn& inst)
{
    // This range of instructions are all jumps
    bool isAnyJumpInstruction = inst.id >= X86_INS_JAE && inst.id <= X86_INS_JS;
    bool isJmp = inst.id == X86_INS_JMP;
    bool startsWithEBorE9 = inst.bytes[0] == 0xEB || inst.bytes[0] == 0xE9;
    // If it is jump and starts with E8 or E9, it is relative
    // If it's not specifically jump but is another jump instruction,
    // it is also relative
    return isJmp ? startsWithEBorE9 : isAnyJumpInstruction;
}
uint32_t AddJmpToAbsTable(cs_insn& jmp, uint8_t* absoluteJumpTable)
{
    // TODO: Can we do this without string conversion?
    char* targetAddrStr = jmp.op_str; // Where the instruction intended to go
    uint64_t targetAddr = _strtoui64(targetAddrStr, NULL, 0);
    // We already have a function for this
    WriteAbsoluteJump64(absoluteJumpTable, (void*)targetAddr);
    return 13; // Size of mov/jmp combo
}
uint32_t AddCallToAbsTable(cs_insn& call, uint8_t* absTableMem, uint8_t* jumpBackToHookedFunc)
{
    char* targetAddrStr = call.op_str; //where the instruction intended to go
    uint64_t targetAddr = _strtoui64(targetAddrStr, NULL, 0);

    uint8_t* dstMem = absTableMem;

    uint8_t callCode[] =
    {
        0x49, 0xBA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // movabs 64 bit value into r10
        0x41, 0xFF, 0xD2, // Call r10
    };
    memcpy(&callCode[2], &targetAddr, sizeof(void*));
    memcpy(dstMem, &callCode, sizeof(callCode));
    dstMem += sizeof(callCode);

    // After the call, we need to add a second 2 byte jump, which will jump back to the 
    // Final jump of the stolen bytes
    uint8_t jmpBytes[2] = { 0xEB, jumpBackToHookedFunc - (absTableMem + sizeof(jmpBytes)) };
    memcpy(dstMem, jmpBytes, sizeof(jmpBytes));

    return sizeof(callCode) + sizeof(jmpBytes); // 15
}

void RewriteCallInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry)
{
    uint8_t distToJumpTable = absTableEntry - (instrPtr + instr->size);

    // Calls need to be rewritten as relative jumps to the abs table
    // But we want to preserve the length of the instruction, so pad with NOPs
    uint8_t jmpBytes[2] = { 0xEB, distToJumpTable };
    memset(instr->bytes, 0x90, instr->size);
    memcpy(instr->bytes, jmpBytes, sizeof(jmpBytes));
}
void RewriteJumpInstruction(cs_insn* instr, uint8_t* instrPtr, uint8_t* absTableEntry)
{
    uint8_t distToJumpTable = absTableEntry - (instrPtr + instr->size);

    // jmp instructions can have a 1 or 2 byte opcode, and need a 1-4 byte operand
    // Rewrite the operand for the jump to go to the jump table
    uint8_t instrByteSize = instr->bytes[0] == 0x0F ? 2 : 1;
    uint8_t operandSize = instr->size - instrByteSize;

    switch (operandSize)
    {
    case 1: { instr->bytes[instrByteSize] = distToJumpTable; }break;
    case 2: { uint16_t dist16 = distToJumpTable; memcpy(&instr->bytes[instrByteSize], &dist16, 2); } break;
    case 4: { uint32_t dist32 = distToJumpTable; memcpy(&instr->bytes[instrByteSize], &dist32, 4); } break;
    }
}

uint32_t BuildTrampoline(void* target, void* trampoline) {
    X64Instructions prologue = GetPrologue(target);

    uint8_t* trampolineMem = (uint8_t*)trampoline;
    uint8_t* jumpFromAddress = trampolineMem + prologue.numBytes;
    // Need 13 bytes for mov/jmp combo
    uint8_t* absoluteTableMem = jumpFromAddress + 13;

    // Copy instructions from the prologue to the trampoline
    for (uint32_t i = 0; i < prologue.numInstructions; ++i)
    {
        cs_insn& inst = prologue.instructions[i];

        for (uint32_t i = 0; i < prologue.numInstructions; ++i)
        {
            cs_insn& inst = prologue.instructions[i];

            //perform any fixup logic to the stolen instructions here
            if (IsRIPRelativeInstr(inst))
            {
                RelocateInstruction(&inst, trampolineMem);
            }
            else if (IsRelativeJump(inst))
            {
                uint32_t aitSize = AddJmpToAbsTable(inst, absoluteTableMem);
                RewriteJumpInstruction(&inst, trampolineMem, absoluteTableMem);
                absoluteTableMem += aitSize;
            }
            else if (IsRelativeCall(inst))
            {
                uint32_t aitSize = AddCallToAbsTable(inst, absoluteTableMem, jumpFromAddress);
                RewriteCallInstruction(&inst, trampolineMem, absoluteTableMem);
                absoluteTableMem += aitSize;
            }
            memcpy(trampolineMem, inst.bytes, inst.size);
            trampolineMem += inst.size;
        }

        memcpy(trampolineMem, inst.bytes, inst.size);
        trampolineMem += inst.size;
    }

    WriteAbsoluteJump64(jumpFromAddress, (uint8_t*)target + RELATIVE_JUMP_LENGTH);

    // Free those instructions from earlier
    free(prologue.instructions);
    // Return the length of the trampoline
    return uint32_t((uint8_t*)absoluteTableMem - trampoline);
}

BOOL InstallHookV4(IN LPCSTR moduleName, IN LPCSTR functionName, IN void* hookFunction, OUT void** originalFunction) {
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

    // Overwrite memory protection so we can write jump to hook
    DWORD oldProtect;
    if (!VirtualProtect(targetFunctionAddress, 14, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        WRITE_DEBUG("Could change memory protection, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return false;
    }

    // Create trampoline
    void* trampoline = AllocatePageNearAddress(targetFunctionAddress);
    uint32_t trampolineSize = BuildTrampoline(targetFunctionAddress, trampoline);

    // Create relay function to jump to hook
    void* relayFuncMemory = (char*)trampoline + trampolineSize;
    WriteAbsoluteJump64(relayFuncMemory, hookFunction); //write relay func instructions

    // Set up relative jump to relay
    uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };
    const int32_t relAddr = (int32_t)relayFuncMemory - ((int32_t)targetFunctionAddress + sizeof(jmpInstruction));

    // Write address into the 4 operand bytes
    memcpy(jmpInstruction + 1, &relAddr, 4);
    // Write the jump back to the function's location
    memcpy(targetFunctionAddress, jmpInstruction, sizeof(jmpInstruction));

    // Rewrite old protections
    if (!VirtualProtect(targetFunctionAddress, 14, oldProtect, &oldProtect)) {
        WRITE_DEBUG("Could restore memory protection, failed to hook ");
        WRITELINE_DEBUG(functionName);
        return false;
    }

    // Send trampoline back as the original function
    *originalFunction = trampoline;
    //*originalFunction = targetFunctionAddress;

    // Debug info
    // NtReadFile is an example and function of interest
    WRITELINE_DEBUG("----------------------");
    WRITELINE_DEBUG("Function:             " << functionName);
    WRITELINE_DEBUG("Hook function:        " << hookFunction);
    WRITELINE_DEBUG("Original function:    " << *originalFunction);
    WRITELINE_DEBUG("Trampoline address:   " << trampoline);
    WRITELINE_DEBUG("Real NtReadFile:      " << (void*)Real_NtReadFile);
    WRITELINE_DEBUG("Trampoline[17...]:    " << (void*)*(uintptr_t*)((BYTE*)trampoline + 17));
    WRITELINE_DEBUG("Target function addr: " << targetFunctionAddress);
    WRITELINE_DEBUG("First jmp to:         " << (void*)*(uintptr_t*)((BYTE*)targetFunctionAddress + 2));
    WRITELINE_DEBUG("----------------------");

    // Real equals the target address, should equal trampoline -- this is because global variable is not changed (why?)

    WRITE_DEBUG("Successfully hooked ");
    WRITELINE_DEBUG(functionName);
}