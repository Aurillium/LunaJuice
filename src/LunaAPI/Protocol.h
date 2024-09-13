#pragma once

namespace LunaAPI {
	// All the below codes are set to be easily distinguished
	// Virtual codes can be AND-compared with Resp_Virtal,
	// error responses can be compared with Resp_Error,
	// responses in general can be compared with Resp_Success,
	// and opcodes cannot be compared
	// Opcodes are not designed to be distinguished based on type,
	// they're just categorised for convenience

	// The registry is not designed to be used by the client, it is
	// only intended to be used to set up new connections
	typedef enum _OpCode {
		// 0 does not exist
		// 0x01 - 0x0F for connection/encryption
		Op_Marco					= 0x0001,
		Op_Polo						= 0x0002,
		Op_Disconnect				= 0x000F,

		// 0x10 - 0x1F: Registry operations
		Op_GetRegistrySize			= 0x0010,
		Op_QueryByIdentifier		= 0x0011,
		Op_GetFunctionIdentifier	= 0x0012,
		Op_GetEntryInfo				= 0x0013,

		// 0x20 - 0x2F: Security settings
		Op_SetSecuritySettings		= 0x0020,
		Op_GetSecuritySettings		= 0x0021,

		// 0x60 - 0x7F: Native
		Op_NativeRegisterHook		= 0x0060,
		Op_NativeSetDefaultMiti		= 0x0061,
		Op_NativeGetDefaultMiti		= 0x0062,
		Op_NativeSetDefaultLogs		= 0x0063,
		Op_NativeGetDefaultLogs		= 0x0064,

		Op_NativeSetFunctionConfig	= 0x0065,
		Op_NativeAddFunctionConfig	= 0x0066,
		Op_NativeDelFunctionConfig	= 0x0067,
		Op_NativeGetFunctionConfig	= 0x0068,
		Op_NativeSetFunctionState	= 0x0069,
		Op_NativeGetFunctionState	= 0x006A,

		// 0x80 - 0x9F: Python
		// Python does not have mitigations as there's
		// too much ground to cover effectively
		Op_PythonRegisterHook		= 0x0080,
		Op_PythonSetDefaultLogs		= 0x0081,
		Op_PythonGetDefaultLogs		= 0x0082,

		Op_PythonSetFunctionConfig	= 0x0083,
		Op_PythonAddFunctionConfig	= 0x0084,
		Op_PythonDelFunctionConfig	= 0x0085,
		Op_PythonGetFunctionConfig	= 0x0086,
		Op_PythonSetFunctionState	= 0x0087,
		Op_PythonGetFunctionState	= 0x0088,

		Op_PythonEval				= 0x0089,
		Op_PythonExec				= 0x008A,
		Op_PythonVersion			= 0x008B,
		Op_PythonInitialise			= 0x008C,


		// OLD PROTOCOL

		// 0x10 - 0x2F for set config
		//Op_RegisterNativeHook		= 0x0010,	// Done
		//Op_SetDefaultMitigations	= 0x0011,	// Done
		//Op_SetDefaultLogging		= 0x0012,	// Done
		//Op_SetFunctionConfig		= 0x0013,	// Done
		//Op_AddFunctionConfig		= 0x0014,	// Done
		//Op_DelFunctionConfig		= 0x0015,	// Done
		//Op_SetFunctionState			= 0x0016,	// Untested
		//Op_SetSecuritySettings		= 0x0017,	// Done

		// 0x30 - 0x3F for get config
		// x33 and x32 can be used to enumerate the registry
		//Op_GetDefaultPolicy			= 0x0030,	// Done
		//Op_GetFunctionInfo			= 0x0031,	// Done
		//Op_GetFunctionIdentifier	= 0x0032,	
		//Op_GetRegistrySize			= 0x0033,	// Done
		//Op_QueryByIdentifier		= 0x0034	// Done
	} OpCode;

	typedef enum _ResponseCode {
		Resp_Success			= 0x8000,
		Resp_Error				= 0xf000,
		Resp_InvalidRequest		= 0xf001,
		Resp_OutOfMemory		= 0xf002,
		Resp_InvalidCommand		= 0xf003,
		Resp_BadParameter		= 0xf004,
		Resp_UnknownError		= 0xf005,	// In general we should aim to minimise this
		Resp_NotFound			= 0xf006,
		Resp_OperationFailed	= 0xf007,
		Resp_WrongType			= 0xf008,

		// C errors
		Resp_C					= 0xf100,
		Resp_UnsupportedHook	= 0xf101,

		// Python errors
		Resp_Python				= 0xf200,
		Resp_PyNotFound			= 0xf201,
		Resp_PyNotRunning		= 0xf202,
		Resp_PyException		= 0xf203,
		Resp_PyIsCFunction		= 0xf204,
		Resp_PyIsBoundMethod	= 0xf205,

		// "Virtual" codes, used by the client internally
		Resp_Virtual			= 0xff00,
		Resp_Disconnect			= 0xff01,
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