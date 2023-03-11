#include "my_widget.h"
#include <QPushButton>
#include <QDebug>
#include <windows.h>
#include <Psapi.h>

enum
{
	CTL_REGISTER_PROTECT_CALLBACK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_UNREGISTER_PROTECT_CALLBACK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_REGISTER_DBG_CALLBACK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_UNREGISTER_DBG_CALLBACK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_READ = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_PRE_WRITE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_WRITE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_GET_STATISTIC = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_PROTECT_HANDLE_TABLE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS),
	CTL_DBG_HANDLE_TABLE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
};


HANDLE hdevice;

void PrintLastErrorString()
{
    DWORD err_code = GetLastError();
    if(err_code == 0)
    {
		puts("没有错误信息\n");
	    return;
    }
    char* buffer = nullptr;
	//int size = FormatMessageA
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, err_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL);
    printf("%s",buffer);
	LocalFree(buffer);
}

DWORD GetProcessArchitecture(const HANDLE& ProcessHandle)
{
	BOOL IsWow64;
	DWORD TargetArchitecture = 32;

	if (!IsWow64Process(ProcessHandle, &IsWow64))  //判断函数是否che
	{
		return 0;
	}
	if (IsWow64) //真32位
	{
		TargetArchitecture = 32;  //目标进程位数
	}
	else {
		SYSTEM_INFO SystemInfo = { 0 };
		GetNativeSystemInfo(&SystemInfo);  //获得系统信息
		if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) //得到系统位数64
			TargetArchitecture = 64;
		else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)//得到系统位数32
			TargetArchitecture = 32;
		else return 0;
	}
	return TargetArchitecture;
}




my_widget::my_widget(QWidget* parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	connect(ui.pushButton_inject, &QPushButton::clicked, this,
		[=]() {
			//加载驱动
			HMODULE hmodule = LoadLibraryA("ntdll.dll");
			typedef int (*type_RtlAdjustPrivilege)(int, bool, bool, int*);
			type_RtlAdjustPrivilege RtlAdjustPrivilege = (type_RtlAdjustPrivilege)GetProcAddress(hmodule, "RtlAdjustPrivilege");
			int enabled = 0;
			//SeDebugPrivilege
			ULONG result = RtlAdjustPrivilege(0x14, true, false, &enabled);
			if (result == 0xc0000061)
			{
				MessageBoxW(0,L"提权失败，没有管理员权限",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
				CloseHandle(hmodule);
				return;
			}
			else if (result != 0)
			{
				MessageBoxW(0,L"提权失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
				CloseHandle(hmodule);
				return;
			}
			SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			if (hSCManager == NULL)
			{
				MessageBoxW(0,L"打开服务控制管理器失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
				return;
			}
			static char current[MAX_PATH]={};
			static char file_path[MAX_PATH]={};
			static char service_name[10]={"moye"};
			GetCurrentDirectoryA(MAX_PATH, current);
			sprintf_s(file_path,"%s\\callback.sys",current);

			SC_HANDLE hService = CreateServiceA(hSCManager, service_name, service_name, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, file_path, NULL, NULL, NULL, NULL, NULL);
			if (hService == NULL)
			{
				if (GetLastError() == ERROR_SERVICE_EXISTS)
				{
					hService = OpenServiceA(hSCManager, service_name, SERVICE_ALL_ACCESS);
					if (hService == NULL)
					{
						MessageBoxW(0,L"打开服务失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
						CloseServiceHandle(hSCManager);
						return;
					}
				}
				else
				{
					MessageBoxW(0,L"创建服务失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
					CloseServiceHandle(hSCManager);
					return;
				}
			}
			SERVICE_DESCRIPTIONW service_description = { (LPWSTR)L"这是寞叶的驱动" };
			ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, (LPVOID)&service_description);
			if (!StartServiceA(hService, NULL, NULL))
			{
				if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
				{
					MessageBoxW(0,L"启动服务失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
					DeleteService(hService);
					CloseServiceHandle(hService);
					CloseServiceHandle(hSCManager);
					return;
				}
			}
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			hdevice = CreateFileA("\\\\.\\my_link", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hdevice == INVALID_HANDLE_VALUE)
			{
				MessageBoxW(0, L"打开符号链接失败", L"提示", MB_TOPMOST | MB_ICONWARNING | MB_OK);
				return;
			}

			//注入模块
			bool ok;
			ULONG pid = ui.plainTextEdit_pid->toPlainText().toULong(&ok);
			if (!ok) {
				MessageBoxW(0,L"数据格式有误",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
				return;
			}
			m_pid = pid;
			m_hDbgProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			if (m_hDbgProcess == NULL)
			{
				MessageBoxW(0,L"打开进程失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
				return;
			}
			char dllPath[MAX_PATH] = {};
			PVOID ProcAdd = NULL;
			DWORD arch = GetProcessArchitecture(m_hDbgProcess);
			if(arch==32)
			{
				sprintf_s(dllPath, "%s\\hook32.dll", current);
				SHELLEXECUTEINFOA shellinfo = { 0 };
				shellinfo.cbSize = sizeof(shellinfo);
				shellinfo.hwnd = NULL;
				shellinfo.lpVerb = "open";
				shellinfo.lpFile = "get_address.exe";			//此处写执行文件的路径
				shellinfo.lpParameters = NULL;
				shellinfo.nShow = SW_HIDE;
				shellinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
				BOOL bResult = ShellExecuteExA(&shellinfo);
				if ((int)shellinfo.hInstApp <= 32)
				{
					MessageBoxW(0,L"执行get_address.exe失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
					return;
				}
				WaitForSingleObject(shellinfo.hProcess, INFINITE);
				//从address.txt读取地址
				FILE* fp = NULL;
				fopen_s(&fp, "address.txt", "rb");
				if (fp == NULL)
				{
					MessageBoxW(0,L"打开文件address.txt失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
					return;
				}
				char address[17] = {};
				fgets(address, sizeof(address), fp);
				fclose(fp);
				ProcAdd = (PVOID)std::stoi(address,nullptr,16);
				// HMODULE hMods[1024];
				// DWORD cbNeeded;
				// if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT))
				// {
				// 	for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
				// 	{
				// 		char mod_name[MAX_PATH]={};
				// 		GetModuleBaseName(hProcess,hMods[i],mod_name,sizeof(mod_name));
				// 		qDebug()<<"mod_name = "<<mod_name;
				// 		if(_stricmp("kernel32.dll",mod_name)==0)
				// 		{
				// 			// MODULEINFO info;
				// 			// GetModuleInformation(hProcess,hMods[i],&info,sizeof(info));
				// 			hmodule=hMods[i];
				// 			qDebug()<<"kernel32.dll hmodule = "<<hmodule;
				// 			break;
				// 		}
				// 	}
				// }
				// else
				// {
				// 	MessageBoxW(0,L"获取32位进程模块kernel32.dll基址失败\n",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
				// }
			}
			else if(arch==64)
			{
				sprintf_s(dllPath, "%s\\hook64.dll", current);
				hmodule = GetModuleHandleA("kernel32.dll");
				ProcAdd = GetProcAddress(hmodule, "LoadLibraryA");
			}
			else
			{
				MessageBoxW(0,L"获取目标进程位数失败",L"提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
				CloseHandle(m_hDbgProcess);
				return;
			}
			qDebug()<<"ProcAdd = "<<ProcAdd;
			PVOID paraAddr = VirtualAllocEx(m_hDbgProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
			WriteProcessMemory(m_hDbgProcess, paraAddr, dllPath, strlen(dllPath) + 1, NULL);
			DWORD threadid = 0;
			HANDLE hThread = NULL;
			hThread = CreateRemoteThread(m_hDbgProcess, NULL, 0, (LPTHREAD_START_ROUTINE)ProcAdd, paraAddr, 0, &threadid);
			if (hThread == NULL)
			{
				MessageBoxW(0, L"创建远程线程失败", L"提示", MB_TOPMOST | MB_ICONWARNING | MB_OK);
				return;
			}
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
			//CloseHandle(m_hDbgProcess);
			timer_id = startTimer(1000, Qt::VeryCoarseTimer);
		}
	);

}

void my_widget::timerEvent(QTimerEvent* event)
{
	//判断调试器是否退出
	DWORD exit_code;
	HANDLE handle;
	DWORD dwRet = 0;
	char buffer[300] = {};
	sprintf_s(buffer,"%p",m_pid);
	do
	{
		handle=OpenProcess(PROCESS_ALL_ACCESS,FALSE,m_pid);
		DeviceIoControl(hdevice, CTL_DBG_HANDLE_TABLE, buffer, sizeof(buffer), nullptr, 0, &dwRet, NULL);
	}
	while(GetExitCodeProcess(handle,&exit_code)==0);
	CloseHandle(handle);
	if(exit_code==STILL_ACTIVE)
	{
		LONG cnt_read = 0;
		LONG cnt_write = 0;
		LONG cnt_callback_protect = 0;
		LONG cnt_callback_dbg = 0;
		LONG cnt_handle_protect = 0;
		LONG cnt_handle_dbg = 0;
		DeviceIoControl(hdevice, CTL_GET_STATISTIC, nullptr, 0, buffer, sizeof(buffer), &dwRet, NULL);
		sscanf_s(buffer, "%d %d %d %d %d %d", &cnt_read, &cnt_write, &cnt_callback_protect, &cnt_callback_dbg, &cnt_handle_protect, &cnt_handle_dbg);
		sprintf_s(buffer, "处理读内存请求：%d次\n处理写内存请求：%d次\n回调保护调试器：%d次\n回调提权：%d次\n句柄降权保护调试器：%d次\n句柄提权：%d次\n", cnt_read, cnt_write, cnt_callback_protect, cnt_callback_dbg, cnt_handle_protect, cnt_handle_dbg);
		ui.textBrowser_statistic->setText(buffer);
		return;
	}
	else
	{
		DWORD dwRet = 0;
		DeviceIoControl(hdevice, CTL_UNREGISTER_DBG_CALLBACK, nullptr, 0, nullptr, 0, &dwRet, NULL);
		DeviceIoControl(hdevice, CTL_UNREGISTER_PROTECT_CALLBACK, nullptr, 0, nullptr, 0, &dwRet, NULL);
		ui.textBrowser_statistic->setText("调试器已退出");
		CloseHandle(m_hDbgProcess);
		killTimer(timer_id);
	}
}




my_widget::~my_widget()
{
	CloseHandle(m_hDbgProcess);
	killTimer(timer_id);
	SC_HANDLE hSCManager = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hService = OpenServiceA(hSCManager,"moye",SERVICE_ALL_ACCESS);
	SERVICE_STATUS status;
	ControlService(hService,SERVICE_CONTROL_STOP,&status);
	DeleteService(hService);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}
