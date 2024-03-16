#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

// Logging for debug
#ifdef _DEBUG
#define LOG(str) std::cout << str << std::endl
#else
#define LOG(str)
#endif

HANDLE hProc;

bool LoadLibraryInject(const char* dllPath)
{
	// Allocate space for our dll path.
	void* base = VirtualAllocEx(hProc, nullptr, strlen(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Write dll path to our allocated space.
	if (!WriteProcessMemory(hProc, base, dllPath, strlen(dllPath), nullptr))
	{
		LOG("[-] Failed to write Dll path!");
		CloseHandle(hProc);
		return false;
	}

	// Create thread that executes LoadLibraryA to load our dll.
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), base, 0, nullptr);
	if (hThread)
		CloseHandle(hThread);

	return true;
}

DWORD GetProcessId(const char* processName)
{
	// Creat Snapshot of all Processes. Use TH32CS_SNAPMODULE if you want to find Modules.
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!hSnap)
	{
		LOG("[-] Failed create snapshot!");
		return 0;
	}

	PROCESSENTRY32 procEntry;
	// To understand read: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
	if (Process32First(hSnap, &procEntry))
	{
		while (Process32Next(hSnap, &procEntry))
		{
			// Compare target process name with the currently looped.
			if (!strcmp(procEntry.szExeFile, processName))
			{
				CloseHandle(hSnap);
				return procEntry.th32ProcessID;
			}
		}
	}
	else
	{
		LOG("[-] Process32First returned false!");
		CloseHandle(hSnap);
		return 0;
	}

	CloseHandle(hSnap);
	return 0;
}

int main(int argc, char* argv[])
{
	int processId = 0;
	const char* dllPath;
	char fullDllPath[MAX_PATH];

	if (argc < 3)
	{
		LOG("Usage: Injector.exe [Process ID / Process name] [DLL Path]");
		return 1;
	}
	else
	{
		bool id = true;
		// Check if 1st argument is a process id or process name
		for (char c : std::string(argv[1]))
		{
			if (!isdigit(c))
			{
				id = false;
				break;
			}
		}

		// atoi turns a string to numbers
		processId = id ? atoi(argv[1]) : GetProcessId(argv[1]);
		dllPath = argv[2];
	}

	if (GetFullPathNameA(dllPath, MAX_PATH, fullDllPath, nullptr) == 0)
	{
		LOG("[-] Failed to get Full Path of DLL!");
		return 1;
	}

	LOG("[+] Got Full Path of DLL!");
	LOG(dllPath);

	// Opening a handle to our target process
	hProc = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
	if (!hProc)
	{
		LOG("[-] Failed to get Handle to Process!");
		return 1;
	}

	LOG("[+] Got Handle to Process!");

	if (!LoadLibraryInject(fullDllPath))
	{
		LOG("[-] Failed to Inject!");
		CloseHandle(hProc);
		return 1;
	}

	LOG("[+] Successfully Injected!");

	// Close handle to target process cause not needed.
	CloseHandle(hProc);
	return 0;
}