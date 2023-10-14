#include "hijack.h"

#define infoln(format, ...) printf(format "\n", ##__VA_ARGS__)
#define errln(format, ...) printf("[ERR]" format "\n", ##__VA_ARGS__)
#define errln_ex(format, ...) printf("[ERR %d]" format "\n", GetLastError(), ##__VA_ARGS__)

unsigned char lpText[] = "THREAD GOT HIJACKED!!";
unsigned char lpTitle[] = "INFO";

DWORD WINAPI test_thread(LPVOID lParam)
{
	int i = 0;
	while (1)
	{
		Sleep(1000);
		infoln("%d - beep", i++);
	}
}

void test_hijack(HANDLE hThread)
{
	PVOID lpArgs;
	BASIC_CONTEXT orig_con;
	BASIC_CONTEXT call_con;
	HJK_CON hjk_con;

	SuspendThread(hThread);

	get_basic_context(hThread, &orig_con);

	memcpy(&call_con, &orig_con, sizeof(BASIC_CONTEXT));



#ifdef _WIN64
	call_con.rcx = NULL;
	call_con.rdx = (DWORD64)lpText;
	call_con.r8 = (DWORD64)lpTitle;
	call_con.r9 = NULL;
	lpArgs = NULL;

	call_con.rip = (DWORD64)MessageBoxA;
#else
	DWORD args_arr[4];
	args_arr[0] = NULL;
	args_arr[1] = (DWORD)lpText;
	args_arr[2] = (DWORD)lpTitle;
	args_arr[3] = NULL;
	lpArgs = args_arr;

	call_con.eip = (DWORD)MessageBoxA;

#endif

	hjk_con.hProc = GetCurrentProcess();
	hjk_con.hThread = hThread;
	hjk_con.WarpperRoutine = NULL;

	hjk_con.lpArgs = lpArgs;
	hjk_con.ArgSize = 4 * sizeof(PVOID);
	hjk_con.ArgAlignNum = 16;

	hjk_con.lpOriCon = &orig_con;
	hjk_con.lpCallCon = &call_con;


	hijack_thread_context(&hjk_con);

	ResumeThread(hThread);
}

int main()
{
	infoln("Hello world!");

	DWORD ThreadId = 0;
	HANDLE hThread = CreateThread(NULL, 0, test_thread, NULL, 0, &ThreadId);

	infoln("thread id = %d", ThreadId);

	if (hThread == NULL) {
		errln_ex("failed to create thread!");
		return 0;
	}

	Sleep(500);

	int result = false;
	do {
		
		test_hijack(hThread);

		result = MessageBoxA(NULL, "Try again?", "info", MB_ICONINFORMATION | MB_YESNO);

	} while (result != IDNO);


	return 0;
}