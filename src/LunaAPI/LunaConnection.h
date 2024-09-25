#pragma once
#include <Windows.h>
#include <mutex>

#include "framework.h"
#include "output.h"

#include "Protocol.h"

using namespace LunaAPI;

namespace LunaAPI {
	struct RPCArguments {
		RPCArguments* next;
		void* value;
	};

	class LUNA_API LunaConnection {
	private:
		// Buffer info
		PVOID currentBuffer;
		SIZE_T currentLength;	// The current length of the whole packet
		SIZE_T bufferPosition;	// The current position within the buffer
		SIZE_T bufferBase;		// The base position of the buffer in the packet
		SIZE_T bufferLength;	// The length of the current buffer
		// Position within buffer = bufferBase + bufferPosition
		// Next read length = min(MAX_DATA, currentLength - (bufferBase + bufferLength))
	protected:
		HANDLE hPipe;
		std::recursive_mutex* mtx;

		ResponseCode lastResponse;
		BOOL LoadNextBuffer();
	public:
		// Util
		LunaConnection(HANDLE hPipe);
		~LunaConnection();
		ResponseCode GetLastError();
		template<typename T> BOOL GetTyped(T* buffer);	// The only function that should take data from the buffer
		BOOL GetRaw(void* buffer, DWORD length);		// The other only function, for types like char* buffers

		// Helper
		PacketHeader WaitForPacket();

		// Define important headers for sending data
		BOOL SendHeader(ResponseCode code, DWORD length = 0);
		BOOL SendPacket(ResponseCode code, LPCVOID buffer, DWORD length);
	};
}

template<typename T> BOOL LunaConnection::GetTyped(T* buffer) {
	std::lock_guard<std::recursive_mutex> lock(*mtx);

	return this->GetRaw((void*)buffer, sizeof(T));
}

BOOL SendPacket(HANDLE hPipe, OpCode code, LPCVOID buffer, size_t length);
BOOL RecvPacket(HANDLE hPipe, PacketHeader* header, LPVOID* buffer);
BOOL RecvFixedPacket(HANDLE hPipe, PacketHeader* header, LPVOID buffer, size_t length);
BOOL RecvHeader(HANDLE hPipe, PacketHeader* header);
BOOL RecvFixedData(HANDLE hPipe, LPVOID buffer, size_t length);
