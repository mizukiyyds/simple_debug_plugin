// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <cstdio>
#include <Windows.h>

#define CTL_CODE( DeviceType, Function, Method, Access ) ( ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) )

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
CRITICAL_SECTION cs;

DWORD msg1(LPVOID lp_thread_parameter)
{
	MessageBoxA(0,"获取OpenProcess地址失败","提示",MB_TOPMOST|MB_ICONINFORMATION|MB_OK);
    return 0;
}
DWORD msg2(LPVOID lp_thread_parameter)
{
	MessageBoxA(0,"获取模块句柄失败","提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
	return 0;
}
DWORD msg3(LPVOID lp_thread_parameter)
{
	MessageBoxA(0,"获取ReadProcessMemory地址失败","提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
	return 0;
}
DWORD msg4(LPVOID lp_thread_parameter)
{
	MessageBoxA(0,"获取WriteProcessMemory地址失败","提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
	return 0;
}
DWORD msg5(LPVOID lp_thread_parameter)
{
	MessageBoxA(0,"获取NtOpenProcess地址失败","提示",MB_TOPMOST|MB_ICONWARNING|MB_OK);
	return 0;
}
DWORD msg6(LPVOID lp_thread_parameter)
{
	MessageBoxA(0,"模块加载完毕","提示",MB_TOPMOST|MB_ICONINFORMATION|MB_OK);
	return 0;
}

BOOL WINAPI hook_read_func(
    _In_ HANDLE hProcess,
    _In_ LPCVOID lpBaseAddress,
    _Out_writes_bytes_to_(nSize,*lpNumberOfBytesRead) LPVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesRead
    )
{
    DWORD pid = GetProcessId(hProcess);
    DWORD dwRet = 0;
    char msg[100]={};

    sprintf_s(msg,"%p %p",pid,lpBaseAddress);
    //EnterCriticalSection(&cs);
    DeviceIoControl(hdevice,CTL_READ,msg,sizeof(msg),lpBuffer,nSize,&dwRet,NULL);
	//LeaveCriticalSection(&cs);
	if(lpNumberOfBytesRead!=nullptr) *lpNumberOfBytesRead = dwRet;
	return true;
}


BOOL WINAPI hook_write_func(
    _In_ HANDLE hProcess,
    _In_ LPCVOID lpBaseAddress,
    _Out_writes_bytes_to_(nSize,*lpNumberOfBytesRead) LPVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesRead
    )
{
    DWORD pid = GetProcessId(hProcess);
    DWORD dwRet = 0;
    char msg[100]={};
    sprintf_s(msg,"%p %p",pid,lpBaseAddress);
    EnterCriticalSection(&cs);
	DeviceIoControl(hdevice,CTL_PRE_WRITE,msg,sizeof(msg),nullptr,0,&dwRet,NULL);
	DeviceIoControl(hdevice,CTL_WRITE,lpBuffer,nSize,nullptr,0,&dwRet,NULL);
	LeaveCriticalSection(&cs);
	if(lpNumberOfBytesRead!=nullptr) *lpNumberOfBytesRead = dwRet;
	return true;
}



void hook_ReadWriteProcessMemory()
{
    HMODULE hmodule = GetModuleHandleA("Kernel32.dll");
    if(hmodule == NULL)
    {
    	CreateThread(NULL,NULL,msg2,NULL,NULL,NULL);
        return;
    }
	PVOID address_read = GetProcAddress(hmodule,"ReadProcessMemory");
    if(address_read == NULL)
    {
    	CreateThread(NULL,NULL,msg3,NULL,NULL,NULL);
        return;
    }
    PVOID address_write = GetProcAddress(hmodule,"WriteProcessMemory");
    if(address_write == NULL)
    {
    	CreateThread(NULL,NULL,msg4,NULL,NULL,NULL);
        return;
    }
    DWORD old_protect;
    VirtualProtect(address_read,12, PAGE_EXECUTE_READWRITE, &old_protect);
    //mov rax,address_read
    //jmp rax
    ((BYTE*)address_read)[0]=0x48;
    ((BYTE*)address_read)[1]=0xB8;
    *(UINT64*)((BYTE*)address_read+2)=(UINT64)hook_read_func;
    ((BYTE*)address_read)[10]=0xFF;
    ((BYTE*)address_read)[11]=0xE0;
    VirtualProtect(address_read,12, old_protect, &old_protect);

    VirtualProtect(address_write,12, PAGE_EXECUTE_READWRITE, &old_protect);
    //mov rax,address_read
    //jmp rax
    ((BYTE*)address_write)[0]=0x48;
    ((BYTE*)address_write)[1]=0xB8;
    *(UINT64*)((BYTE*)address_write+2)=(UINT64)hook_write_func;
    ((BYTE*)address_write)[10]=0xFF;
    ((BYTE*)address_write)[11]=0xE0;
    VirtualProtect(address_write,12, old_protect, &old_protect);

}





typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI *pfn_NtOpenProcess) (
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


pfn_NtOpenProcess NtOpenProcess = (pfn_NtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtOpenProcess");
HANDLE WINAPI hook_open_func(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ DWORD dwProcessId
    )
{
    
	CLIENT_ID ClientId;
	OBJECT_ATTRIBUTES oa; 
	HANDLE hprocess; 
	ClientId.UniqueThread = 0i64;
    ClientId.UniqueProcess = (HANDLE)dwProcessId;
    //OBJ_INHERIT = 0x2
    InitializeObjectAttributes(&oa, NULL, (bInheritHandle ? 2 : 0), NULL, NULL);
	DWORD dwRet = 0;
    char msg[100]={};
    sprintf_s(msg,"%p",dwProcessId);
    //EnterCriticalSection(&cs);
    DeviceIoControl(hdevice, CTL_REGISTER_DBG_CALLBACK, msg, sizeof(msg), nullptr, 0, &dwRet, NULL);
    //LeaveCriticalSection(&cs);
	NtOpenProcess(&hprocess, dwDesiredAccess, &oa, &ClientId);
	DeviceIoControl(hdevice, CTL_UNREGISTER_DBG_CALLBACK, nullptr, 0, nullptr, 0, &dwRet, NULL);
    return hprocess;
}

PVOID address_open = GetProcAddress(GetModuleHandleA("Kernel32.dll"),"OpenProcess");
void hook_OpenProcess()
{
    DWORD old_protect;
    VirtualProtect(address_open,12, PAGE_EXECUTE_READWRITE, &old_protect);
    //mov rax,address_open
    //jmp rax
    ((BYTE*)address_open)[0]=0x48;
    ((BYTE*)address_open)[1]=0xB8;
    *(UINT64*)((BYTE*)address_open+2)=(UINT64)hook_open_func;
    ((BYTE*)address_open)[10]=0xFF;
    ((BYTE*)address_open)[11]=0xE0;
    VirtualProtect(address_open,12, old_protect, &old_protect);
}

void RegisterCallbacks()
{
	DWORD dwRet = 0;
    char msg[100]={};
    //注册保护调试器回调
    sprintf_s(msg,"%p",GetCurrentProcessId());
    //EnterCriticalSection(&cs);
    DeviceIoControl(hdevice, CTL_REGISTER_PROTECT_CALLBACK, msg, sizeof(msg), nullptr, 0, &dwRet, NULL);
    //LeaveCriticalSection(&cs);
}


DWORD HandleProtect()
{
    DWORD dwRet = 0;
    char msg[100]={};
    sprintf_s(msg,"%p",GetCurrentProcessId());
	while(1)
	{
		DeviceIoControl(hdevice, CTL_PROTECT_HANDLE_TABLE, msg, sizeof(msg), nullptr, 0, &dwRet, NULL);
        Sleep(10000);
	}
}

DWORD HandleDbg()
{
    DWORD dwRet = 0;
    char msg[100]={};
    sprintf_s(msg,"%p",GetCurrentProcessId());
	while(1)
	{
		DeviceIoControl(hdevice, CTL_DBG_HANDLE_TABLE, msg, sizeof(msg), nullptr, 0, &dwRet, NULL);
        Sleep(1000);
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitializeCriticalSection(&cs);
        hdevice = CreateFileA("\\\\.\\my_link", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hdevice == INVALID_HANDLE_VALUE)
		{
            MessageBoxA(0, "打开符号链接失败(可能需要以管理员权限运行调试器)", "提示", MB_TOPMOST | MB_ICONWARNING | MB_OK);
			return -1;
		}
        CreateThread(0,0,(LPTHREAD_START_ROUTINE)HandleProtect,0,0,0);
        CreateThread(0,0,(LPTHREAD_START_ROUTINE)HandleDbg,0,0,0);
        RegisterCallbacks();
    	hook_ReadWriteProcessMemory();
        hook_OpenProcess();
        CreateThread(0,0,(LPTHREAD_START_ROUTINE)msg6,0,0,0);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

