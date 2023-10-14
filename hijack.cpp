#include "hijack.h"

/* necessary logger */
#define errln(format, ...) printf("[ERR]" format "\n", ##__VA_ARGS__)
#define errln_ex(format, ...) printf("[ERR %d]" format "\n", GetLastError(), ##__VA_ARGS__)

#ifdef _DEBUG
#define infoln(format, ...) printf(format "\n", ##__VA_ARGS__)
#define dbgln(format, ...) printf("<dbg> " format "\n", ##__VA_ARGS__)
#else
#define infoln(format, ...)
#define dbgln(format, ...)
#endif


unsigned char shellcode_32[] =
{
	0x58, 0x5B, 0x59, 0x5A, 0x5E, 0x5F, 0x83, 0xC4, 0x04, 0x5D, 0x9D, 0x5B, 0x5E, 0x5F, 0x0F, 0xAE,
	0x07, 0xFF, 0xD3, 0x0F, 0xAE, 0x0F, 0x8B, 0x06, 0x8B, 0x5E, 0x04, 0x8B, 0x4E, 0x08, 0x8B, 0x56,
	0x0C, 0x8B, 0x6E, 0x1C, 0x8B, 0x7E, 0x20, 0x57, 0x9D, 0x8B, 0x7E, 0x24, 0x8B, 0x66, 0x18, 0x57,
	0x8B, 0x7E, 0x14, 0x8B, 0x76, 0x10, 0xC3
};

unsigned char shellcode_64[] = 
{
	0x58, 0x5B, 0x59, 0x5A, 0x5E, 0x5F, 0x48, 0x83, 0xC4, 0x08, 0x5D, 0x41, 0x58, 0x41, 0x59, 0x41,
	0x5A, 0x41, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x9D, 0x5B, 0x5E, 0x5F, 0x0F,
	0xAE, 0x07, 0xFF, 0xD3, 0x0F, 0xAE, 0x0F, 0x48, 0x8B, 0x06, 0x48, 0x8B, 0x5E, 0x08, 0x48, 0x8B,
	0x4E, 0x10, 0x48, 0x8B, 0x56, 0x18, 0x48, 0x8B, 0x6E, 0x38, 0x4C, 0x8B, 0x46, 0x40, 0x4C, 0x8B,
	0x4E, 0x48, 0x4C, 0x8B, 0x56, 0x50, 0x4C, 0x8B, 0x5E, 0x58, 0x4C, 0x8B, 0x66, 0x60, 0x4C, 0x8B,
	0x6E, 0x68, 0x4C, 0x8B, 0x76, 0x70, 0x4C, 0x8B, 0x7E, 0x78, 0x48, 0x8B, 0xBE, 0x80, 0x00, 0x00,
	0x00, 0x57, 0x9D, 0x48, 0x8B, 0xBE, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x66, 0x30, 0x57, 0x48,
	0x8B, 0x7E, 0x28, 0x48, 0x8B, 0x76, 0x20, 0xC3
};


extern "C" {
	void hijack_warpper_routine();
}

unsigned char* get_shellcode(unsigned int* lpSize)
{
#ifdef _WIN64
	*lpSize = sizeof(shellcode_64);
	return shellcode_64;
#else
	*lpSize = sizeof(shellcode_32);
	return shellcode_32;
#endif
}

unsigned char* get_shellcode_wow64(unsigned int* lpSize)
{
	*lpSize = sizeof(shellcode_32);
	return shellcode_32;
}

PVOID alloc_on_stack(PVOID stack_ptr, unsigned int size, unsigned int align)
{
	if (align == 0)
		align = sizeof(PVOID);

	unsigned long long ptr_num = (unsigned long long)stack_ptr;

	ptr_num -= size;

	ptr_num = ptr_num / align * align;

	return (PVOID)ptr_num;
}



//bool get_basic_context_64(HANDLE hThread, BASIC_CONTEXT* lpBasic)
//{
//	CONTEXT con;
//	con.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
//	if (!GetThreadContext(hThread, &con)) {
//		errln_ex("failed to get thread context.. maybe thread is running?");
//		return false;
//	}
//
//#ifdef _WIN64
//	lpContext->rax = con.Rax;
//	lpContext->rbx = con.Rbx;
//	lpContext->rcx = con.Rcx;
//	lpContext->rdx = con.Rdx;
//	lpContext->rsi = con.Rsi;
//	lpContext->rdi = con.Rdi;
//	lpContext->rsp = con.Rsp;
//	lpContext->rbp = con.Rbp;
//
//	lpContext->r8 = con.R8;
//	lpContext->r9 = con.R9;
//	lpContext->r10 = con.R10;
//	lpContext->r11 = con.R11;
//	lpContext->r12 = con.R12;
//	lpContext->r13 = con.R13;
//	lpContext->r14 = con.R14;
//	lpContext->r15 = con.R15;
//
//	lpContext->rflags = con.EFlags;
//	lpContext->rip = con.Rip;
//#else
//	lpContext->eax = con.Eax;
//	lpContext->ebx = con.Ebx;
//	lpContext->ecx = con.Ecx;
//	lpContext->edx = con.Edx;
//	lpContext->esi = con.Esi;
//	lpContext->edi = con.Edi;
//	lpContext->esp = con.Esp;
//	lpContext->ebp = con.Ebp;
//
//	lpContext->eflags = con.EFlags;
//	lpContext->eip = con.Eip;
//#endif
//
//	return true;
//}

//bool hijack_thread_ex(
//	HANDLE hProc, HANDLE hThread,
//	BASIC_CONTEXT* lpOriContext, BASIC_CONTEXT* lpCallContext,
//	PVOID lpWarpperRouitne, PVOID lpArgs,
//	unsigned int ArgSize, unsigned int ArgAlignNum)
//
///*
//	lpCallContext - callee-preserved regs are invalid.
//*/
//
//{
//	PUCHAR stack_ptr;
//	PVOID lp_basic_context;
//	PVOID lp_fxarea;
//	CONTEXT con_for_hijack;
//
//	/* get stack point */
//#ifdef _WIN64
//	stack_ptr = (PUCHAR)lpOriContext->rsp;
//#else 
//	stack_ptr = (PUCHAR)lpOriContext->esp;
//#endif
//
//	dbgln("stack_ptr = %p", stack_ptr);
//
//	//stack_ptr -= 0x100;
//
//	/* fill the context */
//	stack_ptr -= sizeof(BASIC_CONTEXT);
//	lp_basic_context = stack_ptr;
//	if (!WriteProcessMemory(hProc, stack_ptr, lpOriContext, sizeof(BASIC_CONTEXT), NULL)) {
//		errln_ex("failed to fill the basic context data??");
//		return false;
//	}
//
//	/* fill FxArea */
//	stack_ptr -= 512;
//	stack_ptr = (PUCHAR)((UPVOID)stack_ptr & ~15);
//	lp_fxarea = stack_ptr;
//
//	infoln("fxarea = %p", lp_fxarea);
//
//	/* check arg size */
//	if (ArgSize % sizeof(UPVOID)) {
//		errln("arg error: ArgSize = %d (it must be aligned to 4 or 8)", ArgSize);
//		return false;
//	}
//
//	/* get arg-alignment */
//	if (ArgAlignNum % sizeof(UPVOID)) {
//		errln("arg error: ArgAlignNum = %d (ite must be aligned to 2^n and >= 4 or 8)", ArgAlignNum);
//		return false;
//	}
//
//	/* fill args */
//	stack_ptr -= ArgSize;
//	if (ArgAlignNum) {
//		stack_ptr = (PUCHAR)((UPVOID)stack_ptr & ~((UPVOID)ArgAlignNum - 1));
//	}
//
//	if (lpArgs && !WriteProcessMemory(hProc, stack_ptr, lpArgs, ArgSize, NULL)) {
//		errln_ex("failed to fill args..");
//		return false;
//	}
//	else if (lpArgs)
//		infoln("Args: %p", stack_ptr);
//
//	/* fill "args" for asm_routine */
//
//	stack_ptr -= sizeof(PVOID);
//	if (!WriteProcessMemory(hProc, stack_ptr, &lp_fxarea, sizeof(PVOID), NULL)) {
//		errln_ex("failed to fill lpFxsaveArea");
//		return false;
//	}
//
//	stack_ptr -= sizeof(PVOID);
//	if (!WriteProcessMemory(hProc, stack_ptr, &lp_basic_context, sizeof(PVOID), NULL)) {
//		errln_ex("failed to fill lpBasicContext");
//		return false;
//	}
//
//	/* fill call context */
//	stack_ptr -= sizeof(BASIC_CONTEXT);
//	if (!WriteProcessMemory(hProc, stack_ptr, lpCallContext, sizeof(BASIC_CONTEXT), NULL)) {
//		errln_ex("failed to load call context");
//		return false;
//	}
//
//	/* set context */
//	con_for_hijack.ContextFlags = CONTEXT_ALL;
//	if (!GetThreadContext(hThread, &con_for_hijack)) {
//		errln_ex("failed to get thread context.. maybe thread is running?");
//		return false;
//	}
//	
//#ifdef _WIN64
//	con_for_hijack.Rsp = (UPVOID)stack_ptr;
//	con_for_hijack.Rip = (UPVOID)lpWarpperRouitne;
//#else
//	con_for_hijack.Esp = (UPVOID)stack_ptr;
//	con_for_hijack.Eip = (UPVOID)lpWarpperRouitne;
//#endif
//
//	if (!SetThreadContext(hThread, &con_for_hijack)) {
//		errln_ex("failed to get thread context.. maybe thread is running?");
//		return false;
//	}
//
//	infoln("hijacked thread!");
//	return true;
//}
//
//bool hijack_thread(
//	HANDLE hThread, 
//	BASIC_CONTEXT* lpOriContext, 
//	BASIC_CONTEXT* lpCallContext, 
//	PVOID lpArgs, 
//	unsigned int ArgSize, 
//	unsigned int ArgAlignNum)
//{
//	return hijack_thread_ex(GetCurrentProcess(), hThread,
//				lpOriContext, lpCallContext, 
//				hijack_warpper_routine,
//				lpArgs, ArgSize, 
//				ArgAlignNum);
//}

bool hijack_thread_context(HJK_CON* lpHjk)
{
	PVOID stack_ptr;
	PVOID fxarea_ptr;
	PVOID basic_context_ptr;
	CONTEXT hjk_con;

	/* argument check */
	if (lpHjk->WarpperRoutine == NULL && lpHjk->hProc == GetCurrentProcess()) {
		lpHjk->WarpperRoutine = hijack_warpper_routine;
	}
	else if (lpHjk->WarpperRoutine == NULL) {
		errln("arg error: invaild warpper routine");
		return false;
	}

	/* get stack ptr */
#ifdef _WIN64
	stack_ptr = (PVOID)lpHjk->lpCallCon->rsp;
#else
	stack_ptr = (PVOID)lpHjk->lpCallCon->esp;
#endif

	/* fill original context */
	stack_ptr = alloc_on_stack(stack_ptr, sizeof(BASIC_CONTEXT), 0);
	basic_context_ptr = stack_ptr;
	if (!WriteProcessMemory(lpHjk->hProc, stack_ptr, lpHjk->lpOriCon, sizeof(BASIC_CONTEXT), NULL)) {
		errln_ex("failed to fill the basic context data??");
		return false;
	}

	/* fill FxArea */
	stack_ptr = alloc_on_stack(stack_ptr, 512, 16);
	fxarea_ptr = stack_ptr;

	/* fill Arguments for async function */
	stack_ptr = alloc_on_stack(stack_ptr, lpHjk->ArgSize, lpHjk->ArgAlignNum);
	
	if (lpHjk->lpArgs &&
		!WriteProcessMemory(lpHjk->hProc, stack_ptr, lpHjk->lpArgs, lpHjk->ArgSize, NULL)) {
		errln_ex("failed to fill the argument for async function");
		return false;
	}

	/* fill "args" for asm_routine */
	stack_ptr = alloc_on_stack(stack_ptr, sizeof(PVOID), 0);
	if (!WriteProcessMemory(lpHjk->hProc, stack_ptr, &fxarea_ptr, sizeof(PVOID), NULL)) {
		errln_ex("failed to fill lpFxsaveArea");
		return false;
	}

	stack_ptr = alloc_on_stack(stack_ptr, sizeof(PVOID), 0);
	if (!WriteProcessMemory(lpHjk->hProc, stack_ptr, &basic_context_ptr, sizeof(PVOID), NULL)) {
		errln_ex("failed to fill lpBasicContext");
		return false;
	}

	/* fill call context */
	stack_ptr = alloc_on_stack(stack_ptr, sizeof(BASIC_CONTEXT), 0);
	if (!WriteProcessMemory(lpHjk->hProc, stack_ptr, lpHjk->lpCallCon, sizeof(BASIC_CONTEXT), NULL)) {
		errln_ex("failed to load call context");
		return false;
	}

	/* set context */
	hjk_con.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(lpHjk->hThread, &hjk_con)) {
		errln_ex("failed to get thread context.. maybe thread is running?");
		return false;
	}

#ifdef _WIN64
	hjk_con.Rsp = (DWORD64)stack_ptr;
	hjk_con.Rip = (DWORD64)lpHjk->WarpperRoutine;
#else
	hjk_con.Esp = (DWORD)stack_ptr;
	hjk_con.Eip = (DWORD)lpHjk->WarpperRoutine;
#endif

	if (!SetThreadContext(lpHjk->hThread, &hjk_con)) {
		errln_ex("failed to get thread context.. maybe thread is running?");
		return false;
	}

	infoln("hijacked thread!");
	return true;

}

bool hijack_thread_context_wow64(HJK_CON32* lpHjk32)
{
	PVOID stack_ptr;
	PVOID fxarea_ptr;
	PVOID basic_context_ptr;
	WOW64_CONTEXT hjk_con;

	/* argument check */
	if (lpHjk32->WarpperRoutine == NULL) {
		errln("arg error: invaild warpper routine");
		return false;
	}

	/* get stack ptr */
	stack_ptr = (PVOID)lpHjk32->lpCallCon->esp;

	/* fill original context */
	stack_ptr = alloc_on_stack(stack_ptr, sizeof(BASIC_CONTEXT), 0);
	basic_context_ptr = stack_ptr;
	if (!WriteProcessMemory(lpHjk32->hProc, stack_ptr, lpHjk32->lpOriCon, sizeof(BASIC_CONTEXT), NULL)) {
		errln_ex("failed to fill the basic context data??");
		return false;
	}

	/* fill FxArea */
	stack_ptr = alloc_on_stack(stack_ptr, 512, 16);
	fxarea_ptr = stack_ptr;

	/* fill Arguments for async function */
	stack_ptr = alloc_on_stack(stack_ptr, lpHjk32->ArgSize, lpHjk32->ArgAlignNum);

	if (lpHjk32->lpArgs &&
		!WriteProcessMemory(lpHjk32->hProc, stack_ptr, lpHjk32->lpArgs, lpHjk32->ArgSize, NULL)) {
		errln_ex("failed to fill the argument for async function");
		return false;
	}

	/* fill "args" for asm_routine */
	stack_ptr = alloc_on_stack(stack_ptr, 4, 4);
	if (!WriteProcessMemory(lpHjk32->hProc, stack_ptr, &fxarea_ptr, sizeof(PVOID), NULL)) {
		errln_ex("failed to fill lpFxsaveArea");
		return false;
	}

	stack_ptr = alloc_on_stack(stack_ptr, 4, 4);
	if (!WriteProcessMemory(lpHjk32->hProc, stack_ptr, &basic_context_ptr, sizeof(PVOID), NULL)) {
		errln_ex("failed to fill lpBasicContext");
		return false;
	}

	/* fill call context */
	stack_ptr = alloc_on_stack(stack_ptr, 4, 4);
	if (!WriteProcessMemory(lpHjk32->hProc, stack_ptr, lpHjk32->lpCallCon, sizeof(BASIC_CONTEXT), NULL)) {
		errln_ex("failed to load call context");
		return false;
	}

	/* set context */
	hjk_con.ContextFlags = CONTEXT_ALL;
	if (!Wow64GetThreadContext(lpHjk32->hThread, &hjk_con)) {
		errln_ex("failed to get thread context.. maybe thread is running?");
		return false;
	}

	hjk_con.Esp = (DWORD)stack_ptr;
	hjk_con.Eip = (DWORD)lpHjk32->WarpperRoutine;

	if (!Wow64SetThreadContext(lpHjk32->hThread, &hjk_con)) {
		errln_ex("failed to get thread context.. maybe thread is running?");
		return false;
	}

	infoln("hijacked thread!");
	return true;

}

bool get_basic_context(HANDLE hThread, BASIC_CONTEXT* lpContext)
{
	CONTEXT con;
	con.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	if (!GetThreadContext(hThread, &con)) {
		errln_ex("failed to get thread context.. maybe thread is running?");
		return false;
	}

#ifdef _WIN64
	lpContext->rax = con.Rax;
	lpContext->rbx = con.Rbx;
	lpContext->rcx = con.Rcx;
	lpContext->rdx = con.Rdx;
	lpContext->rsi = con.Rsi;
	lpContext->rdi = con.Rdi;
	lpContext->rsp = con.Rsp;
	lpContext->rbp = con.Rbp;

	lpContext->r8 = con.R8;
	lpContext->r9 = con.R9;
	lpContext->r10 = con.R10;
	lpContext->r11 = con.R11;
	lpContext->r12 = con.R12;
	lpContext->r13 = con.R13;
	lpContext->r14 = con.R14;
	lpContext->r15 = con.R15;

	lpContext->rflags = con.EFlags;
	lpContext->rip = con.Rip;
#else
	lpContext->eax = con.Eax;
	lpContext->ebx = con.Ebx;
	lpContext->ecx = con.Ecx;
	lpContext->edx = con.Edx;
	lpContext->esi = con.Esi;
	lpContext->edi = con.Edi;
	lpContext->esp = con.Esp;
	lpContext->ebp = con.Ebp;

	lpContext->eflags = con.EFlags;
	lpContext->eip = con.Eip;
#endif

	return true;
}

bool get_basic_context_wow64(HANDLE hThread, BASIC_CONTEXT32* lpCon32)
{
	WOW64_CONTEXT con;
	con.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	if (!Wow64GetThreadContext(hThread, &con)) {
		errln_ex("failed to get wow64 thread context.. maybe thread is running?");
		return false;
	}

	lpCon32->eax = con.Eax;
	lpCon32->ebx = con.Ebx;
	lpCon32->ecx = con.Ecx;
	lpCon32->edx = con.Edx;
	lpCon32->esi = con.Esi;
	lpCon32->edi = con.Edi;
	lpCon32->esp = con.Esp;
	lpCon32->ebp = con.Ebp;

	lpCon32->eflags = con.EFlags;
	lpCon32->eip = con.Eip;

	return true;
}
