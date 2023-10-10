#include "hijack.h"

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
	BASIC_CONTEXT orig_con;
	BASIC_CONTEXT hijack_con;
	SuspendThread(hThread);
	if (!get_basic_context(hThread, &orig_con)) {
		return;
	}

	memcpy(&hijack_con, &orig_con, sizeof(BASIC_CONTEXT));

#ifdef _WIN64
	hijack_con.rcx = NULL;
	hijack_con.rdx = (qword)lpText;
	hijack_con.r8 = (qword)lpTitle;
	hijack_con.r9 = NULL;

	hijack_con.rip = (qword)MessageBoxA;

	bool result = hijack_thread(hThread,
		&orig_con,
		&hijack_con,
		NULL,
		4 * sizeof(UPVOID),
		16);

#else
	/* don't handle memory leak, because I'm lazy */
	void** args = new void* [4];
	args[0] = NULL;
	args[1] = (void*)lpText;
	args[2] = (void*)lpTitle;
	args[3] = NULL;

	hijack_con.eip = (dword)MessageBoxA;

	bool result = hijack_thread(hThread,
		&orig_con,
		&hijack_con,
		args,
		4 * sizeof(UPVOID),
		16);

#endif



	ResumeThread(hThread);

#ifndef _WIN64
	delete[] args;
#endif
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

	//WaitForSingleObject(hThread, INFINITE);

	return 0;
}