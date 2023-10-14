#pragma once

#include <windows.h>
#include <stdio.h>

//extern "C" {
//
//	// asm routine
//	void hijack_warpper_routine();
//
//}


#define THREAD_HIJACK_ACCESS THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME

//typedef unsigned int DWORD;
//typedef unsigned long long DWORD64;

typedef struct
{
	DWORD eax;
	DWORD ebx;
	DWORD ecx;
	DWORD edx;
	DWORD esi;
	DWORD edi;
	DWORD esp;
	DWORD ebp;

	DWORD eflags;
	DWORD eip;

}BASIC_CONTEXT32;

typedef struct
{
	DWORD64 rax;
	DWORD64 rbx;
	DWORD64 rcx;
	DWORD64 rdx;
	DWORD64 rsi;
	DWORD64 rdi;
	DWORD64 rsp;
	DWORD64 rbp;

	DWORD64 r8;
	DWORD64 r9;
	DWORD64 r10;
	DWORD64 r11;
	DWORD64 r12;
	DWORD64 r13;
	DWORD64 r14;
	DWORD64 r15;

	DWORD64 rflags;
	DWORD64 rip;

}BASIC_CONTEXT64;

typedef struct
{
	HANDLE hProc;
	HANDLE hThread;
	BASIC_CONTEXT32* lpOriCon;
	BASIC_CONTEXT32* lpCallCon;
	PVOID WarpperRoutine;
	PVOID lpArgs;
	unsigned int ArgSize;
	unsigned int ArgAlignNum;

}HJK_CON32;

typedef struct
{
	HANDLE hProc;
	HANDLE hThread;
	BASIC_CONTEXT64* lpOriCon;
	BASIC_CONTEXT64* lpCallCon;
	PVOID WarpperRoutine;
	PVOID lpArgs;
	unsigned int ArgSize;
	unsigned int ArgAlignNum;
}HJK_CON64;

#ifdef _WIN64
typedef BASIC_CONTEXT64 BASIC_CONTEXT;
typedef HJK_CON64 HJK_CON;
#else
typedef BASIC_CONTEXT32 BASIC_CONTEXT;
typedef HJK_CON32 HJK_CON;
#endif



PVOID alloc_on_stack(PVOID lpStackPtr, unsigned int DesiredSize, unsigned int AlignNum);
unsigned char* get_shellcode(unsigned int* lpShellSize);
unsigned char* get_shellcode_wow64(unsigned int* lpShellSize);

/* differs on versions */
bool get_basic_context(HANDLE hThread, BASIC_CONTEXT* lpContext);
bool hijack_thread_context(HJK_CON* lpHijackContext);

bool get_basic_context_wow64(HANDLE hThread, BASIC_CONTEXT32* lpContext);
bool hijack_thread_context_wow64(HJK_CON32* lpHijackContext);