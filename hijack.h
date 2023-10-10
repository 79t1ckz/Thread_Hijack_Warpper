#pragma once

#include <windows.h>
#include <stdio.h>

extern "C" {

	// asm routine
	void hijack_warpper_routine();

}

/* logger */
#define infoln(format, ...) printf(format "\n", ##__VA_ARGS__)
#define errln(format, ...) printf("[ERR]" format "\n", ##__VA_ARGS__)
#define errln_ex(format, ...) printf("[ERR %d]" format "\n", GetLastError(), ##__VA_ARGS__)

#define dbgln(format, ...)
//#define dbgln(format, ...) printf("<dbg> " format "\n", ##__VA_ARGS__)

#define THREAD_HIJACK_ACCESS THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME

typedef unsigned int dword;
typedef unsigned long long qword;

typedef struct _BASIC_CONTEXT32
{
	dword eax;
	dword ebx;
	dword ecx;
	dword edx;
	dword esi;
	dword edi;
	dword esp;
	dword ebp;

	dword eflags;
	dword eip;

}BASIC_CONTEXT32;

typedef struct _BASIC_CONTEXT64
{
	qword rax;
	qword rbx;
	qword rcx;
	qword rdx;
	qword rsi;
	qword rdi;
	qword rsp;
	qword rbp;

	qword r8;
	qword r9;
	qword r10;
	qword r11;
	qword r12;
	qword r13;
	qword r14;
	qword r15;

	qword rflags;
	qword rip;

}BASIC_CONTEXT64;

#ifdef _WIN64
typedef BASIC_CONTEXT64 BASIC_CONTEXT;
typedef unsigned long long UPVOID;
#else
typedef BASIC_CONTEXT32 BASIC_CONTEXT;
typedef unsigned int UPVOID;
#endif

bool get_basic_context(HANDLE hThread, BASIC_CONTEXT* lpContext);

bool hijack_thread_ex(
	HANDLE hProc, HANDLE hThread,
	BASIC_CONTEXT* lpOriContext, BASIC_CONTEXT* lpCallContext,
	PVOID WarpperRoutineAddr, 
	PVOID lpArgs, unsigned int ArgSize,
	unsigned int ArgAlignNum);

bool hijack_thread(
	HANDLE hThread,
	BASIC_CONTEXT* lpOriContext, BASIC_CONTEXT* lpCallContext,
	PVOID lpArgs,
	unsigned int ArgSize, 
	unsigned int ArgAlignNum);