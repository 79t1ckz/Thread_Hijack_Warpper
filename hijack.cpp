#include "hijack.h"

bool hijack_thread_ex(
	HANDLE hProc, HANDLE hThread,
	BASIC_CONTEXT* lpOriContext, BASIC_CONTEXT* lpCallContext,
	PVOID lpWarpperRouitne, PVOID lpArgs,
	unsigned int ArgSize, unsigned int ArgAlignNum)

/*
	lpCallContext - callee-preserved regs are invalid.
*/

{
	PUCHAR stack_ptr;
	PVOID lp_basic_context;
	PVOID lp_fxarea;
	CONTEXT con_for_hijack;

	/* get stack point */
#ifdef _WIN64
	stack_ptr = (PUCHAR)lpOriContext->rsp;
#else 
	stack_ptr = (PUCHAR)lpOriContext->esp;
#endif

	dbgln("stack_ptr = %p", stack_ptr);

	stack_ptr -= 0x100;

	/* fill the context */
	stack_ptr -= sizeof(BASIC_CONTEXT);
	lp_basic_context = stack_ptr;
	if (!WriteProcessMemory(hProc, stack_ptr, lpOriContext, sizeof(BASIC_CONTEXT), NULL)) {
		errln_ex("failed to fill the basic context data??");
		return false;
	}

	/* fill FxArea */
	stack_ptr -= 512;
	stack_ptr = (PUCHAR)((UPVOID)stack_ptr & ~15);
	lp_fxarea = stack_ptr;

	infoln("fxarea = %p", lp_fxarea);

	/* check arg size */
	if (ArgSize % sizeof(UPVOID)) {
		errln("arg error: ArgSize = %d (it must be aligned to 4 or 8)", ArgSize);
		return false;
	}

	/* get arg-alignment */
	if (ArgAlignNum % sizeof(UPVOID)) {
		errln("arg error: ArgAlignNum = %d (ite must be aligned to 2^n and >= 4 or 8)", ArgAlignNum);
		return false;
	}

	/* fill args */
	stack_ptr -= ArgSize;
	if (ArgAlignNum) {
		stack_ptr = (PUCHAR)((UPVOID)stack_ptr & ~((UPVOID)ArgAlignNum - 1));
	}

	if (lpArgs && !WriteProcessMemory(hProc, stack_ptr, lpArgs, ArgSize, NULL)) {
		errln_ex("failed to fill args..");
		return false;
	}
	else if (lpArgs)
		infoln("Args: %p", stack_ptr);

	/* fill "args" for asm_routine */

	stack_ptr -= sizeof(PVOID);
	if (!WriteProcessMemory(hProc, stack_ptr, &lp_fxarea, sizeof(PVOID), NULL)) {
		errln_ex("failed to fill lpFxsaveArea");
		return false;
	}

	stack_ptr -= sizeof(PVOID);
	if (!WriteProcessMemory(hProc, stack_ptr, &lp_basic_context, sizeof(PVOID), NULL)) {
		errln_ex("failed to fill lpBasicContext");
		return false;
	}

	/* fill call context */
	stack_ptr -= sizeof(BASIC_CONTEXT);
	if (!WriteProcessMemory(hProc, stack_ptr, lpCallContext, sizeof(BASIC_CONTEXT), NULL)) {
		errln_ex("failed to load call context");
		return false;
	}

	/* set context */
	con_for_hijack.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hThread, &con_for_hijack)) {
		errln_ex("failed to get thread context.. maybe thread is running?");
		return false;
	}
	
#ifdef _WIN64
	con_for_hijack.Rsp = (UPVOID)stack_ptr;
	con_for_hijack.Rip = (UPVOID)lpWarpperRouitne;
#else
	con_for_hijack.Esp = (UPVOID)stack_ptr;
	con_for_hijack.Eip = (UPVOID)lpWarpperRouitne;
#endif

	if (!SetThreadContext(hThread, &con_for_hijack)) {
		errln_ex("failed to get thread context.. maybe thread is running?");
		return false;
	}

	infoln("hijacked thread!");
	return true;
}

bool hijack_thread(
	HANDLE hThread, 
	BASIC_CONTEXT* lpOriContext, 
	BASIC_CONTEXT* lpCallContext, 
	PVOID lpArgs, 
	unsigned int ArgSize, 
	unsigned int ArgAlignNum)
{
	return hijack_thread_ex(GetCurrentProcess(), hThread,
				lpOriContext, lpCallContext, 
				hijack_warpper_routine,
				lpArgs, ArgSize, 
				ArgAlignNum);
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