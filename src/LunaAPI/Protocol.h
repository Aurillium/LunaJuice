#pragma once

namespace LunaAPI {

	typedef enum _OpCode {
		// 1 - 15 reserved for connection/encryption
		Op_SetDefaultMitigations	= 0x00000010,
		Op_SetDefaultLogging		= 0x00000011,
		Op_SetFunctionConfig		= 0x00000012,
		Op_SetFunctionState			= 0x00000013,
		Op_SetSecuritySettings		= 0x00000014,

		Op_GetDefaultPolicy			= 0x00000020,
		Op_GetFunctionInfo			= 0x00000021,
		Op_GetSecuritySettings		= 0x00000022
	} OpCode;

	typedef enum _ResponseCode {
		Resp_Success		= 0xffff0000,
		Resp_Error			= 0xffff8000,
		Resp_InvalidRequest	= 0xffff8001,
		Resp_OutOfMemory	= 0xffff8002,
		Resp_InvalidCommand	= 0xffff8003
	} ResponseCode;

	typedef union _CommCode {
		ResponseCode response;
		OpCode opcode;
	} CommCode;

	typedef struct _PacketHeader {
		CommCode code;
		DWORD length;
	} PacketHeader;
}