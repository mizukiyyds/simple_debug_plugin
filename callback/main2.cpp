#include <stdio.h>
#include <stdlib.h>

#include "def.h"


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

//用于同步
KMUTEX Mutex;


//r3-r0交互数据
//char g_buffer[1024*1024] = {};
HANDLE g_pid;

PVOID g_address;
// ULONG len;


//回调句柄
PVOID protect_handle=0;
PVOID dbg_handle=0;

//统计数据
LONG cnt_read=0;
LONG cnt_write=0;
LONG cnt_callback_protect=0;
LONG cnt_callback_dbg=0;
LONG cnt_handle_protect=0;
LONG cnt_handle_dbg=0;

void UnRegisterCallback(HANDLE& reg_handle);


void DrvUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint("Unload\n");
	UnRegisterCallback(dbg_handle);
	UnRegisterCallback(protect_handle);
	UNICODE_STRING symbolic_name = RTL_CONSTANT_STRING(L"\\??\\my_link");
	IoDeleteSymbolicLink(&symbolic_name);
	IoDeleteDevice(DriverObject->DeviceObject);
	return;
}


void DebugDelay(int seconds = 1)
{
	LARGE_INTEGER timeout = {};
	timeout.QuadPart = -10 * 1000 * 1000;
	timeout.QuadPart *= seconds;
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
}


OB_PREOP_CALLBACK_STATUS DbgPreOperationCallback(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	__try
	{
		PEPROCESS process;
		HANDLE callback_pid = 0;
		//获取进程
		if (PreInfo->ObjectType == *PsThreadType) {
			process = IoThreadToProcess((PETHREAD)PreInfo->Object);
		}
		else if (PreInfo->ObjectType == *PsProcessType) {
			process = (PEPROCESS)PreInfo->Object;
		}
		else
		{
			return OB_PREOP_SUCCESS;
		}
		callback_pid = PsGetProcessId(process);
		if (callback_pid == RegistrationContext) {
			InterlockedIncrement(&cnt_callback_dbg);
			if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
			}
			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Exception\n");
	}
	return OB_PREOP_SUCCESS;
}


void RegisterDbgCallback(HANDLE pid)
{
	OB_OPERATION_REGISTRATION obOperationRegistrations[2] = {};
	//protect进程类型
	obOperationRegistrations[0].ObjectType = PsProcessType;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[0].PreOperation = DbgPreOperationCallback;
	obOperationRegistrations[0].PostOperation = NULL;
	//protect线程类型
	obOperationRegistrations[1].ObjectType = PsThreadType;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[1].PreOperation = DbgPreOperationCallback;
	obOperationRegistrations[1].PostOperation = NULL;

	OB_CALLBACK_REGISTRATION obCallbackRegistration;
	obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obCallbackRegistration.OperationRegistrationCount = 2;
	obCallbackRegistration.RegistrationContext = (PVOID)pid;
	obCallbackRegistration.Altitude = RTL_CONSTANT_STRING(L"23333");
	obCallbackRegistration.OperationRegistration = obOperationRegistrations;
	if(!NT_SUCCESS(	ObRegisterCallbacks(&obCallbackRegistration, &dbg_handle) ))
	{
		DbgPrint("Exception register dbg callback\n");
	}
}



OB_PREOP_CALLBACK_STATUS ProtectPreOperationCallback(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	__try
	{
		PEPROCESS process;
		HANDLE callback_pid = 0;
		//获取进程
		if (PreInfo->ObjectType == *PsThreadType) {
			process = IoThreadToProcess((PETHREAD)PreInfo->Object);
		}
		else if (PreInfo->ObjectType == *PsProcessType) {
			process = (PEPROCESS)PreInfo->Object;
		}
		else
		{
			return OB_PREOP_SUCCESS;
		}
		callback_pid = PsGetProcessId(process);
		if (callback_pid == RegistrationContext) {
			InterlockedIncrement(&cnt_callback_protect);
			if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
				PreInfo->Parameters->CreateHandleInformation.DesiredAccess = 0;
			}
			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Exception\n");
	}
	return OB_PREOP_SUCCESS;
}



void RegisterProtectCallback(HANDLE pid)
{
	OB_OPERATION_REGISTRATION obOperationRegistrations[2] = {};
	//protect进程类型
	obOperationRegistrations[0].ObjectType = PsProcessType;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[0].PreOperation = ProtectPreOperationCallback;
	obOperationRegistrations[0].PostOperation = NULL;
	//protect线程类型
	obOperationRegistrations[1].ObjectType = PsThreadType;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	obOperationRegistrations[1].PreOperation = ProtectPreOperationCallback;
	obOperationRegistrations[1].PostOperation = NULL;

	OB_CALLBACK_REGISTRATION obCallbackRegistration;
	obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	obCallbackRegistration.OperationRegistrationCount = 2;
	obCallbackRegistration.RegistrationContext = (PVOID)pid;
	obCallbackRegistration.Altitude = RTL_CONSTANT_STRING(L"23333.3");
	obCallbackRegistration.OperationRegistration = obOperationRegistrations;
	if(!NT_SUCCESS(	ObRegisterCallbacks(&obCallbackRegistration, &protect_handle) ))
	{
		DbgPrint("Exception register protect callback\n");
	}
}

void UnRegisterCallback(HANDLE& reg_handle)
{
	if (reg_handle != 0) {
		ObUnRegisterCallbacks(reg_handle);
		reg_handle = 0;
	}
	else
	{
		DbgPrint("Unneed UnRegisterCallback\n");
	}
}


ULONG myWriteProcessMemory(CONST HANDLE pid, CONST PVOID address, CONST PVOID buffer, CONST SIZE_T len)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS proc = NULL;
    UINT64 RetureSize;
	__try
	{
		status = PsLookupProcessByProcessId(pid, &proc);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("PsLookupProcessByProcessId fail. pid = %d\n", pid);
			return 0;
		}
		UNICODE_STRING name=RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
		pfn_MmCopyVirtualMemory MmCopyVirtualMemory=(pfn_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&name);
		status = MmCopyVirtualMemory(PsGetCurrentProcess(),buffer,proc,address,len,KernelMode,&RetureSize);
		InterlockedIncrement(&cnt_write);
		ObDereferenceObject(proc);
		return (ULONG)RetureSize;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("myWriteProcessMemory exception\n");
		ObDereferenceObject(proc);
		return 0;
	}
}

ULONG myReadProcessMemory(CONST HANDLE pid, CONST PVOID address, CONST PVOID buffer, CONST SIZE_T len)
{
	
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS proc = NULL;
    UINT64 ReturnSize;
	__try
	{
		status = PsLookupProcessByProcessId(pid, &proc);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("PsLookupProcessByProcessId fail. pid = %d\n", pid);
			return 0;
		}
		UNICODE_STRING name=RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
		pfn_MmCopyVirtualMemory MmCopyVirtualMemory=(pfn_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&name);
		status = MmCopyVirtualMemory(proc,address,PsGetCurrentProcess(),buffer,len,KernelMode,&ReturnSize);
		InterlockedIncrement(&cnt_read);
		ObDereferenceObject(proc);
		return (ULONG)ReturnSize;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("myReadProcessMemory exception\n");
		ObDereferenceObject(proc);
		return 0;
	}
}

ULONG MDLReadMemoryR3(CONST HANDLE pid, CONST PVOID address, CONST PVOID buffer, CONST ULONG len)
{
	PEPROCESS eprocess = NULL;
	KAPC_STATE apc = {0};
	PMDL mdl=0;
	PVOID map=0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
	{
		DbgPrint("PsLookupProcessByProcessId fail. pid = %d\n", pid);
		return 0;
	}
	ObDereferenceObject(eprocess);
	__try
	{
		KeStackAttachProcess(eprocess, &apc);
		mdl = IoAllocateMdl(address, len, FALSE, FALSE, NULL);
		if (mdl == NULL)
		{
			//DbgPrint("MDLReadMemoryR3 IoAllocateMdl fail\n");
			return 0;
		}
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		KeUnstackDetachProcess(&apc);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//DbgPrint("MDLReadMemoryR3 get Mdl exception\n");
		KeUnstackDetachProcess(&apc);
		return 0;
	}
	map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
	if (map == NULL)
	{
		//DbgPrint("MDLReadMemoryR3 MmMapLockedPagesSpecifyCache fail\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return 0;
	}
	RtlCopyMemory(buffer, map, len);
	MmUnmapLockedPages(map, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	InterlockedIncrement(&cnt_read);
	return len;
}

ULONG MDLWriteMemoryR3(CONST HANDLE pid, CONST PVOID address, CONST PVOID buffer, CONST ULONG len)
{
	PEPROCESS eprocess = NULL;
	KAPC_STATE apc = {0};
	PMDL mdl=0;
	PVOID map=0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
	{
		DbgPrint("PsLookupProcessByProcessId fail. pid = %d\n", pid);
		return 0;
	}
	ObDereferenceObject(eprocess);
	__try
	{
		KeStackAttachProcess(eprocess, &apc);
		mdl = IoAllocateMdl(address, len, FALSE, FALSE, NULL);
		if (mdl == NULL)
		{
			//DbgPrint("MDLWriteMemoryR3 IoAllocateMdl fail\n");
			return 0;
		}
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
		KeUnstackDetachProcess(&apc);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//DbgPrint("MDLWriteMemoryR3 get Mdl exception\n");
		IoFreeMdl(mdl);
		KeUnstackDetachProcess(&apc);
		return 0;
	}
	map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
	if (map == NULL)
	{
		//DbgPrint("MDLWriteMemoryR3 MmMapLockedPagesSpecifyCache fail\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return 0;
	}
	RtlCopyMemory(map, buffer, len);
	MmUnmapLockedPages(map, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	InterlockedIncrement(&cnt_write);
	return len;
}



ULONG PhysicalReadMemoryR3(CONST HANDLE pid, CONST PVOID address, CONST PVOID buffer, CONST ULONG len)
{
	PEPROCESS eprocess = NULL;
	KAPC_STATE apc = {0};
	PHYSICAL_ADDRESS physical_address={};
	PVOID map=0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
	{
		DbgPrint("PsLookupProcessByProcessId fail. pid = %d\n", pid);
		return 0;
	}
	ObDereferenceObject(eprocess);
	KeStackAttachProcess(eprocess, &apc);
	physical_address = MmGetPhysicalAddress(address);
	KeUnstackDetachProcess(&apc);
	if(physical_address.QuadPart!=0)
	{
		map = MmMapIoSpace(physical_address, len, MmCached);
		if (map == NULL)
		{
			DbgPrint("PhysicalReadMemoryR3 MmMapIoSpace fail\n");
			return 0;
		}
		RtlCopyMemory(buffer, map, len);
		MmUnmapIoSpace(map, len);
		InterlockedIncrement(&cnt_read);
		return len;
	}
	else
	{
		DbgPrint("GetPhysicalAddress fail\n");
		return 0;
	}
}

ULONG PhysicalWriteMemoryR3(CONST HANDLE pid, CONST PVOID address, CONST PVOID buffer, CONST ULONG len)
{
	PEPROCESS eprocess = NULL;
	KAPC_STATE apc = {0};
	PHYSICAL_ADDRESS physical_address={};
	PVOID map=0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &eprocess)))
	{
		DbgPrint("PsLookupProcessByProcessId fail. pid = %d\n", pid);
		return 0;
	}
	ObDereferenceObject(eprocess);
	KeStackAttachProcess(eprocess, &apc);
	physical_address = MmGetPhysicalAddress(address);
	KeUnstackDetachProcess(&apc);
	if(physical_address.QuadPart!=0)
	{
		map = MmMapIoSpace(physical_address, len, MmCached);
		if (map == NULL)
		{
			DbgPrint("PhysicalWriteMemoryR3 MmMapIoSpace fail\n");
			return 0;
		}
		RtlCopyMemory(map, buffer, len);
		MmUnmapIoSpace(map, len);
		InterlockedIncrement(&cnt_write);
		return len;
	}
	else
	{
		DbgPrint("GetPhysicalAddress fail\n");
		return 0;
	}
}



BOOLEAN EnumProtectHandleRoutine(PVOID HANDLE_TABLE,PHANDLE_TABLE_ENTRY HandleTableEntry,HANDLE Handle,PVOID EnumParameter)
{
	if(MmIsAddressValid(HANDLE_TABLE)&&MmIsAddressValid(HandleTableEntry))
	{
		PVOID body = (PVOID)((*(PULONG64)HandleTableEntry>>20<<4|0xffff000000000000)+0x30);
		if(MmIsAddressValid(body))
		{
			//PVOID header = body-0x30;
			//DbgPrint("%wZ\n",(PUNICODE_STRING)((ULONG64)type+0x10));
			POBJECT_TYPE type = ObGetObjectType(body);
			if(type==*PsProcessType&&body==EnumParameter)
			{
				if(HandleTableEntry->GrantedAccess!=0)
				{
					_InterlockedExchange((PLONG)&HandleTableEntry->GrantedAccess,0);
					_InterlockedIncrement(&cnt_handle_protect);
				}
			}
		}
		_InterlockedExchangeAdd64((PLONG64)HandleTableEntry,1);
		ExfUnblockPushLock((PULONG_PTR)((ULONG64)HANDLE_TABLE+0x30),0);
	}
    return FALSE;
}
void LowerHandleAccess(CONST HANDLE pid)
{
	PEPROCESS protect_eprocess;
	PEPROCESS eprocess = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &protect_eprocess)))
	{
		return;
	}
	for (ULONG enum_pid = 0x4; enum_pid <= 0x40000; enum_pid += 4)
	{
		
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)enum_pid, &eprocess)))
		{
			continue;
		}
		ObDereferenceObject(eprocess);
		PVOID handle_table = (PVOID) * (PULONG64)((ULONG64)eprocess + 0x570);
		if (MmIsAddressValid(handle_table))
		{
			ExEnumHandleTable(handle_table, EnumProtectHandleRoutine, protect_eprocess, NULL);
		}
		// else
		// {
		// 	DbgPrint("enum_pid = %lu ,handle_table = %p invalid\n", enum_pid, handle_table);
		// }
	}
}

BOOLEAN EnumDbgHandleRoutine(PVOID HANDLE_TABLE,PHANDLE_TABLE_ENTRY HandleTableEntry,HANDLE Handle,PVOID EnumParameter)
{
	if(MmIsAddressValid(HANDLE_TABLE)&&MmIsAddressValid(HandleTableEntry))
	{
		PVOID body = (PVOID)((*(PULONG64)HandleTableEntry>>20<<4|0xffff000000000000)+0x30);
		if(MmIsAddressValid(body))
		{
			POBJECT_TYPE type = ObGetObjectType(body);
			if(type==*PsProcessType)
			{
				if(HandleTableEntry->GrantedAccess!=0x1FFFFF)
				{
					_InterlockedExchange((PLONG)&HandleTableEntry->GrantedAccess,0x1FFFFF);
					_InterlockedIncrement(&cnt_handle_dbg);
				}
			}
		}
		_InterlockedExchangeAdd64((PLONG64)HandleTableEntry,1);
		ExfUnblockPushLock((PULONG_PTR)((ULONG64)HANDLE_TABLE+0x30),0);
	}
    return FALSE;
}


void RaiseHandleAccess(CONST HANDLE pid)
{
	PEPROCESS eprocess = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &eprocess)))
	{
		return;
	}
	ObDereferenceObject(eprocess);
	PVOID handle_table = (PVOID) * (PULONG64)((ULONG64)eprocess + 0x570);
	if (MmIsAddressValid(handle_table))
	{
		ExEnumHandleTable(handle_table, EnumDbgHandleRoutine, NULL, NULL);
	}

}





























































BOOLEAN get_PspCidTable(ULONG64* tableAddr)
{
	// 获取 PsLookupProcessByProcessId 地址
	UNICODE_STRING uc_funcName;
	RtlInitUnicodeString(&uc_funcName, L"PsLookupProcessByProcessId");
	ULONG64 ul_funcAddr = (ULONG64)MmGetSystemRoutineAddress(&uc_funcName);
	if (ul_funcAddr == NULL)
	{
		return FALSE;
	}
	DbgPrint("PsLookupProcessByProcessId addr = %p \n", ul_funcAddr);

	// 前 40 字节有 call（PspReferenceCidTableEntry）
	/*
	0: kd> uf PsLookupProcessByProcessId
		nt!PsLookupProcessByProcessId:
		fffff802`0841cfe0 48895c2418      mov     qword ptr [rsp+18h],rbx
		fffff802`0841cfe5 56              push    rsi
		fffff802`0841cfe6 4883ec20        sub     rsp,20h
		fffff802`0841cfea 48897c2438      mov     qword ptr [rsp+38h],rdi
		fffff802`0841cfef 488bf2          mov     rsi,rdx
		fffff802`0841cff2 65488b3c2588010000 mov   rdi,qword ptr gs:[188h]
		fffff802`0841cffb 66ff8fe6010000  dec     word ptr [rdi+1E6h]
		fffff802`0841d002 b203            mov     dl,3
		fffff802`0841d004 e887000000      call    nt!PspReferenceCidTableEntry (fffff802`0841d090)
		fffff802`0841d009 488bd8          mov     rbx,rax
		fffff802`0841d00c 4885c0          test    rax,rax
		fffff802`0841d00f 7435            je      nt!PsLookupProcessByProcessId+0x66 (fffff802`0841d046)  Branch
	*/
	ULONG64 ul_entry = 0;
	for (INT i = 0; i < 100; i++)
	{
		// fffff802`0841d004 e8 87 00 00 00      call    nt!PspReferenceCidTableEntry (fffff802`0841d090)
		if (*(PUCHAR)(ul_funcAddr + i) == 0xe8)
		{
			ul_entry = ul_funcAddr + i;
			break;
		}
	}

	if (ul_entry != 0)
	{
		// 解析 call 地址
		INT i_callCode = *(INT*)(ul_entry + 1);
		//DbgPrint("i_callCode = %p \n", i_callCode);
		ULONG64 ul_callJmp = ul_entry + i_callCode + 5;
		//DbgPrint("ul_callJmp = %p \n", ul_callJmp);

		// 来到 call（PspReferenceCidTableEntry） 内找 PspCidTable
		/*
		0: kd> uf PspReferenceCidTableEntry
			nt!PspReferenceCidTableEntry+0x115:
			fffff802`0841d1a5 488b0d8473f5ff  mov     rcx,qword ptr [nt!PspCidTable (fffff802`08374530)]
			fffff802`0841d1ac b801000000      mov     eax,1
			fffff802`0841d1b1 f0480fc107      lock xadd qword ptr [rdi],rax
			fffff802`0841d1b6 4883c130        add     rcx,30h
			fffff802`0841d1ba f0830c2400      lock or dword ptr [rsp],0
			fffff802`0841d1bf 48833900        cmp     qword ptr [rcx],0
			fffff802`0841d1c3 0f843fffffff    je      nt!PspReferenceCidTableEntry+0x78 (fffff802`0841d108)  Branch
		*/
		for (INT i = 0; i < 0x120; i++)
		{
			// fffff802`0841d1a5 48 8b 0d 84 73 f5 ff  mov     rcx,qword ptr [nt!PspCidTable (fffff802`08374530)]
			if (*(PUCHAR)(ul_callJmp + i) == 0x48 && *(PUCHAR)(ul_callJmp + i + 1) == 0x8b && *(PUCHAR)(ul_callJmp + i + 2) == 0x0d)
			{
				// 解析 mov 地址
				INT i_movCode = *(INT*)(ul_callJmp + i + 3);
				//DbgPrint("i_movCode = %p \n", i_movCode);
				ULONG64 ul_movJmp = ul_callJmp + i + i_movCode + 7;
				//DbgPrint("ul_movJmp = %p \n", ul_movJmp);

				// 得到 PspCidTable
				*tableAddr = ul_movJmp;
				return TRUE;
			}
		}
	}
	return FALSE;
}


VOID parse_table_1(ULONG64 BaseAddr, INT index1, INT index2);
VOID parse_table_2(ULONG64 BaseAddr, INT index2);
VOID parse_table_3(ULONG64 BaseAddr);

VOID parse_table_1(ULONG64 BaseAddr, INT index1, INT index2)
{
	// 遍历一级表（每个表项大小 16 ），表大小 4k，所以遍历 4096/16 = 256 次
	PEPROCESS p_eprocess = NULL;
	PETHREAD p_ethread = NULL;
	HANDLE i_id = 0;
	for (INT i = 0; i < 256; i++)
	{
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 16)))
		{
			DbgPrint("非法地址= %p \n", BaseAddr + i * 16);
			continue;
		}

		ULONG64 ul_recode = *(PULONG64)(BaseAddr + i * 16);
		// 解密
		ULONG64 ul_decode = (LONG64)ul_recode >> 0x10;
		ul_decode &= 0xfffffffffffffff0;
		
		// 判断是进程还是线程
		i_id = (HANDLE)(4*i + (4*256)*index1 + (4*256*512)*index2);
		if (PsLookupProcessByProcessId(i_id, &p_eprocess) == STATUS_SUCCESS)
		{
			DbgPrint("进程PID: %d | ID: %d | 内存地址: %p | 对象: %p \n", i_id, i, BaseAddr + i * 0x10, ul_decode);
		}
		else if (PsLookupThreadByThreadId(i_id, &p_ethread) == STATUS_SUCCESS)
		{
			DbgPrint("线程TID: %d | ID: %d | 内存地址: %p | 对象: %p \n", i_id, i, BaseAddr + i * 0x10, ul_decode);
		}
	}
}

VOID parse_table_2(ULONG64 BaseAddr, INT index2)
{
	// 遍历二级表（每个表项大小 8）,表大小 4k，所以遍历 4096/8 = 512 次
	ULONG64 ul_baseAddr_1 = 0;
	for (INT i = 0; i < 512; i++)
	{
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8)))
		{
			//DbgPrint("非法二级表指针（1）:%p \n", BaseAddr + i * 8);
			continue;
		}
		if (!MmIsAddressValid((PVOID64)*(PULONG64)(BaseAddr + i * 8)))
		{
			//DbgPrint("非法二级表指针（2）:%p \n", BaseAddr + i * 8);
			continue;
		}
		ul_baseAddr_1 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_1(ul_baseAddr_1, i, index2);
	}
}

VOID parse_table_3(ULONG64 BaseAddr)
{
	// 遍历三级表（每个表项大小 8）,表大小 4k，所以遍历 4096/8 = 512 次
	ULONG64 ul_baseAddr_2 = 0;
	for (INT i = 0; i < 512; i++)
	{
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8)))
		{
			continue;
		}
		if (!MmIsAddressValid((PVOID64)* (PULONG64)(BaseAddr + i * 8)))
		{
			continue;
		}
		ul_baseAddr_2 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_2(ul_baseAddr_2, i);
	}
}

VOID EnumHandleTable()
{
	ULONG64 table_addr=0;
	if(!get_PspCidTable(&table_addr)) return;
	DbgPrint("PspCidTable = %p\n",table_addr);
	ULONG64 ul_tableCode = *(PULONG64)(((ULONG64)*(PULONG64)table_addr) + 8);
	// 取低2位
	INT i_low2 = ul_tableCode & 3;
	// TableCode 低 2位抹零
	if (i_low2 == 0)
	{
		DbgPrint("table level = 1\n");
		parse_table_1(ul_tableCode & (~3), 0, 0);
	}
	// 二级表
	else if (i_low2 == 1)
	{
		DbgPrint("table level = 2\n");
		parse_table_2(ul_tableCode & (~3), 0);
	}
	// 三级表
	else if (i_low2 == 2)
	{
		DbgPrint("table level = 3\n");
		parse_table_3(ul_tableCode & (~3));
	}
	else
	{
		DbgPrint("PspCidTable invalid\n");
	}
}




void EnumProcessModules(HANDLE pid)
{
	NTSTATUS status;
	KAPC_STATE KAPC = { 0 };
	PEPROCESS eprocess = 0;
	UNICODE_STRING func_name=RTL_CONSTANT_STRING(L"PsGetProcessPeb");
	pfn_PsGetProcessPeb PsGetProcessPeb = (pfn_PsGetProcessPeb)MmGetSystemRoutineAddress(&func_name);
	UNICODE_STRING kernel32 = RTL_CONSTANT_STRING(L"kernel32.dll");
	status = PsLookupProcessByProcessId(pid, &eprocess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsLookupProcessByProcessId fail\n");
		return;
	}
	PVOID pPeb = PsGetProcessPeb(eprocess);
	if (pPeb == NULL)
	{
		DbgPrint("pPeb == NULL\n");
		ObDereferenceObject(eprocess);
		return;
	}
	__try
	{
		KeStackAttachProcess(eprocess, &KAPC);
		PVOID Ldr = (PVOID)((ULONGLONG)pPeb + 0x018);
		ProbeForRead(Ldr, 8, 8);
		PLIST_ENTRY ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + 0x010);
		ProbeForRead(ModListHead, 8, 8);
		PLIST_ENTRY Module = ModListHead->Flink;
		while (ModListHead != Module)
		{
			//打印信息：基址、大小、DLL路径
			DbgPrint("模块基址=%p 大小=%ld 路径=%wZ\n",(PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase),
				(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage),&(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));

			// if(RtlCompareUnicodeString(&((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName,
			// 	&kernel32,true)==0)
			// {
			// 	DbgPrint("%lu\n",((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
			// 	DbgPrint("%llu\n",((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
			// 	sprintf_s(g_buffer,sizeof(g_buffer),"%p",((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
			// 	break;
			// }
			Module = Module->Flink;
			//测试下一个模块信息的可读性
			ProbeForRead(Module, 80, 8);
		}
		KeUnstackDetachProcess(&KAPC);
		ObDereferenceObject(eprocess);
		return;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("EnumProcessModules exception\n");
		KeUnstackDetachProcess(&KAPC);
		ObDereferenceObject(eprocess);
		return;
	}
}



NTSTATUS DispatchControl(PDEVICE_OBJECT DriverObject, IRP* irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG in_buf_len = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG out_buf_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID buf = irp->AssociatedIrp.SystemBuffer;
	ULONG retn_size = 0;

	//KeWaitForMutexObject(&Mutex, Executive, KernelMode, FALSE, NULL);
	switch (code)
	{
	case CTL_REGISTER_PROTECT_CALLBACK:
		{
			HANDLE pid=0;
			sscanf_s((char*)buf,"%p",&pid);
			RegisterProtectCallback(pid);
			break;
		}
	case CTL_UNREGISTER_PROTECT_CALLBACK:
		{
			UnRegisterCallback(protect_handle);
			break;
		}
	case CTL_REGISTER_DBG_CALLBACK:
		{
			HANDLE pid=0;
			sscanf_s((char*)buf,"%p",&pid);
			RegisterDbgCallback(pid);
			break;
		}
	case CTL_UNREGISTER_DBG_CALLBACK:
		{
			UnRegisterCallback(dbg_handle);
			break;
		}
	case CTL_READ:
		{
			HANDLE pid=0;
			PVOID address=0;
			sscanf_s((char*)buf,"%p %p",&pid,&address);
			retn_size=MDLReadMemoryR3(pid,address,buf,out_buf_len);
			//retn_size=PhysicalReadMemoryR3(pid,address,buf,out_buf_len);
			break;
		}
	case CTL_PRE_WRITE:
		{
			sscanf_s((char*)buf,"%p %p",&g_pid,&g_address);
			break;
		}
	case CTL_WRITE:
		{
			retn_size=MDLWriteMemoryR3(g_pid,g_address, buf, in_buf_len);
			//retn_size=PhysicalWriteMemoryR3(g_pid,g_address, buf, in_buf_len);
			break;
		}

	case CTL_GET_STATISTIC:
		{
			if(out_buf_len<80)
			{
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			sprintf_s((char*)buf,out_buf_len,"%d %d %d %d %d %d",cnt_read,cnt_write,cnt_callback_protect,cnt_callback_dbg,cnt_handle_protect,cnt_handle_dbg);
			retn_size=strlen((char*)buf);
			break;
		}
	case CTL_PROTECT_HANDLE_TABLE:
		{
			HANDLE pid=0;
			sscanf_s((char*)buf,"%p",&pid);
			LowerHandleAccess(pid);
			break;
		}
	case CTL_DBG_HANDLE_TABLE:
		{
			HANDLE pid=0;
			sscanf_s((char*)buf,"%p",&pid);
			RaiseHandleAccess(pid);
			break;
		}
	default:
		status = STATUS_INVALID_PARAMETER;
		DbgPrint("invalid control code\n");
	}
	//KeReleaseMutex(&Mutex, FALSE);

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = retn_size;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchRoutine(PDEVICE_OBJECT DriverObject, IRP* irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	static char* irp_name[] =
	{ "IRP_MJ_CREATE					 ",
		"IRP_MJ_CREATE_NAMED_PIPE        ",
		 "IRP_MJ_CLOSE                   ",
		 "IRP_MJ_READ                    ",
		 "IRP_MJ_WRITE                   ",
		 "IRP_MJ_QUERY_INFORMATION       ",
		 "IRP_MJ_SET_INFORMATION         ",
		 "IRP_MJ_QUERY_EA                ",
		 "IRP_MJ_SET_EA                  ",
		 "IRP_MJ_FLUSH_BUFFERS           ",
		 "IRP_MJ_QUERY_VOLUME_INFORMATION",
		 "IRP_MJ_SET_VOLUME_INFORMATION  ",
		 "IRP_MJ_DIRECTORY_CONTROL       ",
		 "IRP_MJ_FILE_SYSTEM_CONTROL     ",
		 "IRP_MJ_DEVICE_CONTROL          ",
		 "IRP_MJ_INTERNAL_DEVICE_CONTROL ",
		 "IRP_MJ_SHUTDOWN                ",
		 "IRP_MJ_LOCK_CONTROL            ",
		 "IRP_MJ_CLEANUP                 ",
		 "IRP_MJ_CREATE_MAILSLOT         ",
		 "IRP_MJ_QUERY_SECURITY          ",
		 "IRP_MJ_SET_SECURITY            ",
		 "IRP_MJ_POWER                   ",
		 "IRP_MJ_SYSTEM_CONTROL          ",
		 "IRP_MJ_DEVICE_CHANGE           ",
		 "IRP_MJ_QUERY_QUOTA             ",
		 "IRP_MJ_SET_QUOTA               ",
		 "IRP_MJ_PNP                     ",
		 "IRP_MJ_PNP_POWER               ",
		 "IRP_MJ_MAXIMUM_FUNCTION		 "
	};

	DbgPrint("%s\n", irp_name[stack->MajorFunction]);
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	((PLDR_DATA)DriverObject->DriverSection)->Flags |= 0x20;    //绕过签名检测
	DriverObject->DriverUnload = DrvUnload;
	KeInitializeMutex(&Mutex, 0);
	UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\my_device");
	PDEVICE_OBJECT device_object;
	status = IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device_object);
	if (!NT_SUCCESS(status))
	{
		//设备已经存在
		if (status == STATUS_OBJECT_NAME_COLLISION)
		{
			DbgPrint("设备已经存在\n");
			return status;
		}
		else
		{
			DbgPrint("创建设备失败，status = %#x\n", status);
			return status;
		}
	}
	device_object->Flags |= DO_BUFFERED_IO;
	device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	UNICODE_STRING symbolic_name = RTL_CONSTANT_STRING(L"\\??\\my_link");
	status = IoCreateSymbolicLink(&symbolic_name, &device_name);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("创建符号链接失败，status = %#x\n", status);
		IoDeleteDevice(device_object);
		return status;
	}
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DispatchRoutine;
	}
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;

	DbgPrint("init finish\n");
	return STATUS_SUCCESS;
}

