// #include <stdio.h>
// #include <stdlib.h>
// #include <ntifs.h>
// #include <ntddk.h>
// #include <wdm.h>
//
// typedef struct _LDR_DATA_TABLE_ENTRY
// {
// 	LIST_ENTRY64	InLoadOrderLinks;
// 	LIST_ENTRY64	InMemoryOrderLinks;
// 	LIST_ENTRY64	InInitializationOrderLinks;
// 	PVOID			DllBase;
// 	PVOID			EntryPoint;
// 	ULONG			SizeOfImage;
// 	UNICODE_STRING	FullDllName;
// 	UNICODE_STRING 	BaseDllName;
// 	ULONG			Flags;
// 	USHORT			LoadCount;
// 	USHORT			TlsIndex;
// 	PVOID			SectionPointer;
// 	ULONG			CheckSum;
// 	PVOID			LoadedImports;
// 	PVOID			EntryPointActivationContext;
// 	PVOID			PatchInformation;
// 	LIST_ENTRY64	ForwarderLinks;
// 	LIST_ENTRY64	ServiceTagLinks;
// 	LIST_ENTRY64	StaticLinks;
// 	PVOID			ContextInformation;
// 	ULONG64			OriginalBase;
// 	LARGE_INTEGER	LoadTime;
// } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//
// typedef struct _LDR_DATA
// {
// 	struct _LIST_ENTRY InLoadOrderLinks;
// 	struct _LIST_ENTRY InMemoryOrderLinks;
// 	struct _LIST_ENTRY InInitializationOrderLinks;
// 	VOID* DllBase;
// 	VOID* EntryPoint;
// 	ULONG32      SizeOfImage;
// 	UINT8        _PADDING0_[0x4];
// 	struct _UNICODE_STRING FullDllName;
// 	struct _UNICODE_STRING BaseDllName;
// 	ULONG32      Flags;
// }LDR_DATA, * PLDR_DATA;
// /*
// typedef struct _PEB32
// {
//     UCHAR InheritedAddressSpace;
//     UCHAR ReadImageFileExecOptions;
//     UCHAR BeingDebugged;
//     UCHAR BitField;
//     ULONG Mutant;
//     ULONG ImageBaseAddress;
//     ULONG Ldr;
//     ULONG ProcessParameters;
//     ULONG SubSystemData;
//     ULONG ProcessHeap;
//     ULONG FastPebLock;
//     ULONG AtlThunkSListPtr;
//     ULONG IFEOKey;
//     ULONG CrossProcessFlags;
//     ULONG UserSharedInfoPtr;
//     ULONG SystemReserved;
//     ULONG AtlThunkSListPtr32;
//     ULONG ApiSetMap;
// } PEB32, *PPEB32;
//
// typedef struct _PEB_LDR_DATA32
// {
//     ULONG Length;
//     UCHAR Initialized;
//     ULONG SsHandle;
//     LIST_ENTRY32 InLoadOrderModuleList;
//     LIST_ENTRY32 InMemoryOrderModuleList;
//     LIST_ENTRY32 InInitializationOrderModuleList;
// } PEB_LDR_DATA32, *PPEB_LDR_DATA32;
//
//
//
//
//
// typedef struct _LDR_DATA_TABLE_ENTRY32
// {
//     LIST_ENTRY32 InLoadOrderLinks;
//     LIST_ENTRY32 InMemoryOrderLinks;
//     LIST_ENTRY32 InInitializationOrderLinks;
//     ULONG DllBase;
//     ULONG EntryPoint;
//     ULONG SizeOfImage;
//     UNICODE_STRING32 FullDllName;
//     UNICODE_STRING32 BaseDllName;
//     ULONG Flags;
//     USHORT LoadCount;
//     USHORT TlsIndex;
//     LIST_ENTRY32 HashLinks;
//     ULONG TimeDateStamp;
// } LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
//
// */
//
//
// NTKERNELAPI CHAR* PsGetProcessImageFileName(PEPROCESS Process);
//
// typedef PVOID (__stdcall *pfn_PsGetProcessPeb)(PEPROCESS);
// typedef NTKERNELAPI PVOID (NTAPI *pfn_PsGetProcessWow64Process)(PEPROCESS Process);
// //NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
// typedef NTSTATUS (NTAPI *pfn_MmCopyVirtualMemory)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
//
//
// #define PROCESS_TERMINATE                  (0x0001)
// #define PROCESS_CREATE_THREAD              (0x0002)
// #define PROCESS_SET_SESSIONID              (0x0004)
// #define PROCESS_VM_OPERATION               (0x0008)
// #define PROCESS_VM_READ                    (0x0010)
// #define PROCESS_VM_WRITE                   (0x0020)
// #define PROCESS_DUP_HANDLE                 (0x0040)
// #define PROCESS_CREATE_PROCESS             (0x0080)
// #define PROCESS_SET_QUOTA                  (0x0100)
// #define PROCESS_SET_INFORMATION            (0x0200)
// #define PROCESS_QUERY_INFORMATION          (0x0400)
// #define PROCESS_SUSPEND_RESUME             (0x0800)
// #define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
// #define PROCESS_SET_LIMITED_INFORMATION    (0x2000)
//
//
//
//
//
//
//
//
//
//
//
//
// enum
// {
// 	CTL_MSG_TO_R0 = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_MSG_FROM_R0 = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_REGISTER_CALLBACK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_UNREGISTER_CALLBACK = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_READ = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_WRITE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_MSG_TYPE_PID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_MSG_TYPE_ADDRESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_MSG_TYPE_LEN = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_MSG_TYPE_PROTECTPID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_MSG_TYPE_DBGPID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_GET_STATISTIC = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS),
// 	CTL_BUFFER_TYPE_WOW64KERNEL32 = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
// };
//
// //用于同步
// KMUTEX Mutex;
//
// //r3-r0交互数据
// char g_buffer[1024*1024] = {};
// HANDLE pid;
// HANDLE protect_pid;
// HANDLE dbg_pid;
// PVOID address;
// ULONG len;
//
//
// //回调句柄
// PVOID reg_handle=0;
//
//
// //统计数据
// LONG cnt_read=0;
// LONG cnt_write=0;
// LONG cnt_callback_protect=0;
// LONG cnt_callback_dbg=0;
//
//
// void UnRegisterCallback();
//
//
//
// void DrvUnload(PDRIVER_OBJECT DriverObject)
// {
// 	DbgPrint("Unload\n");
// 	UNICODE_STRING symbolic_name = RTL_CONSTANT_STRING(L"\\??\\my_link");
// 	IoDeleteSymbolicLink(&symbolic_name);
// 	IoDeleteDevice(DriverObject->DeviceObject);
// 	UnRegisterCallback();
// 	return;
// }
//
//
// void DebugDelay(int seconds = 1)
// {
// 	LARGE_INTEGER timeout = {};
// 	timeout.QuadPart = -10 * 1000 * 1000;
// 	timeout.QuadPart *= seconds;
// 	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
// }
//
//
// OB_PREOP_CALLBACK_STATUS PreOperationCallback(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
// {
// 	__try
// 	{
// 		PEPROCESS process;
// 		HANDLE callback_pid = 0;
// 		//获取进程
// 		if (PreInfo->ObjectType == *PsThreadType) {
// 			process = IoThreadToProcess((PETHREAD)PreInfo->Object);
// 		}
// 		else if (PreInfo->ObjectType == *PsProcessType) {
// 			process = (PEPROCESS)PreInfo->Object;
// 		}
// 		else
// 		{
// 			DbgPrint("Unknow\n");
// 			return OB_PREOP_SUCCESS;
// 		}
// 		callback_pid = PsGetProcessId(process);
// 		KeWaitForMutexObject(&Mutex, Executive, KernelMode, FALSE, NULL);
// 		if (callback_pid == protect_pid) {
// 			DbgPrint("protect pid = %d\n", callback_pid);
// 			InterlockedIncrement(&cnt_callback_protect);
// 			if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
// 				PreInfo->Parameters->CreateHandleInformation.DesiredAccess = 0;
// 			}
// 			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
// 				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
// 			}
// 		}
// 		else if(callback_pid == dbg_pid)
// 		{
// 			DbgPrint("dbg pid = %d\n", callback_pid);
// 			InterlockedIncrement(&cnt_callback_dbg);
// 			if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
// 				PreInfo->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
// 			}
// 			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
// 				PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_ALL_ACCESS;
// 			}
// 		}
// 		KeReleaseMutex(&Mutex, FALSE);
// 	}
// 	__except (EXCEPTION_EXECUTE_HANDLER)
// 	{
// 		DbgPrint("Exception\n");
// 	}
// 	return OB_PREOP_SUCCESS;
// }
//
//
//
// void RegisterCallback()
// {
// 	OB_OPERATION_REGISTRATION obOperationRegistrations[2] = {};
// 	//protect进程类型
// 	obOperationRegistrations[0].ObjectType = PsProcessType;
// 	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
// 	obOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
// 	obOperationRegistrations[0].PreOperation = PreOperationCallback;
// 	obOperationRegistrations[0].PostOperation = NULL;
// 	//protect线程类型
// 	obOperationRegistrations[1].ObjectType = PsThreadType;
// 	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
// 	obOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
// 	obOperationRegistrations[1].PreOperation = PreOperationCallback;
// 	obOperationRegistrations[1].PostOperation = NULL;
//
// 	OB_CALLBACK_REGISTRATION obCallbackRegistration;
// 	obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
// 	obCallbackRegistration.OperationRegistrationCount = 2;
// 	obCallbackRegistration.RegistrationContext = NULL;
// 	obCallbackRegistration.Altitude = RTL_CONSTANT_STRING(L"114514");
// 	obCallbackRegistration.OperationRegistration = obOperationRegistrations;
//
// 	DbgPrint("register callback = %#x\n", ObRegisterCallbacks(&obCallbackRegistration, &reg_handle));
//
// }
//
// void UnRegisterCallback()
// {
// 	if (reg_handle != 0) {
// 		ObUnRegisterCallbacks(reg_handle);
// 		reg_handle = 0;
// 		DbgPrint("UnRegisterCallback success\n");
// 	}
// 	else
// 	{
// 		DbgPrint("UnRegisterCallback invalid reg_handle\n");
// 	}
//
// }
//
//
// void WriteProcessMemory()
// {
// 	NTSTATUS status = STATUS_SUCCESS;
// 	PEPROCESS proc = NULL;
//     UINT64 RetureSize;
// 	__try
// 	{
// 		status = PsLookupProcessByProcessId(pid, &proc);
// 		if (!NT_SUCCESS(status))
// 		{
// 			DbgPrint("PsLookupProcessByProcessId fail\npid = %d\n", pid);
// 			return;
// 		}
// 		UNICODE_STRING name=RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
// 		pfn_MmCopyVirtualMemory MmCopyVirtualMemory=(pfn_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&name);
// 		if(MmCopyVirtualMemory==NULL)
// 		{
// 			DbgPrint("MmGetSystemRoutineAddress MmCopyVirtualMemory fail\n");
// 			ObDereferenceObject(proc);
// 			return;
// 		}
// 		MmCopyVirtualMemory(PsGetCurrentProcess(),g_buffer,proc,address,sizeof(g_buffer),KernelMode,&RetureSize);
// 		InterlockedIncrement(&cnt_write);
// 		ObDereferenceObject(proc);
// 		DbgPrint("WriteProcessMemory finish\n");
// 	}
// 	__except (EXCEPTION_EXECUTE_HANDLER)
// 	{
// 		DbgPrint("WriteProcessMemory exception\n");
// 		ObDereferenceObject(proc);
// 	}
// 	// DbgPrint("address=%p\n",address);
// 	// DbgPrint("len=%lu\n",len);
// 	// DbgPrint("pid=%lu\n",pid);
// 	// NTSTATUS status = STATUS_SUCCESS;
// 	// PEPROCESS proc = NULL;
// 	// PKAPC_STATE pApcState = NULL;
// 	// __try
// 	// {
// 	// 	status = PsLookupProcessByProcessId(pid, &proc);
// 	// 	if (!NT_SUCCESS(status))
// 	// 	{
// 	// 		DbgPrint("PsLookupProcessByProcessId fail\npid = %d\n", pid);
// 	// 		return;
// 	// 	}
// 	// 	pApcState = (PKAPC_STATE)ExAllocatePool(PagedPool, sizeof(PKAPC_STATE));
// 	// 	if (pApcState == NULL)
// 	// 	{
// 	// 		DbgPrint("ExAllocatePool fail\n");
// 	// 		ObDereferenceObject(proc);
// 	// 		return;
// 	// 	}
// 	// 	KeStackAttachProcess(proc, pApcState);
// 	//
// 	// 	typedef NTSTATUS(*pZwProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);
// 	// 	UNICODE_STRING func_name = RTL_CONSTANT_STRING(L"ZwProtectVirtualMemory");
// 	// 	pZwProtectVirtualMemory ZwProtectVirtualMemory = (pZwProtectVirtualMemory)MmGetSystemRoutineAddress(&func_name);
// 	// 	if(ZwProtectVirtualMemory==NULL)
// 	// 	{
// 	// 		DbgPrint("ZwProtectVirtualMemory fail\n");
// 	// 		ObDereferenceObject(proc);
// 	// 		ExFreePool(pApcState);
// 	// 		return;
// 	// 	}
// 	// 	ULONG oldprotect;
// 	// 	PVOID tmp_addr=address;
// 	// 	ULONG tmp_len=len;
// 	// 	DbgPrint("ZwProtectVirtualMemory = %#x\n",
// 	// 		ZwProtectVirtualMemory((HANDLE)-1,&tmp_addr,&tmp_len,PAGE_EXECUTE_READWRITE,&oldprotect)
// 	// 		);
// 	// 	
// 	// 	ULONG i=0;
// 	// 	__try
// 	// 	{
// 	// 		for(i=0;i<len;i++)
// 	// 		{
// 	// 			((char*)address)[i]=g_buffer[i];
// 	// 		}
// 	// 	}
// 	// 	__except (EXCEPTION_EXECUTE_HANDLER)
// 	// 	{
// 	// 		DbgPrint("writing (address=%p)[%d] exception\n",address,i);
// 	// 	}
// 	// 	tmp_addr=address;
// 	// 	tmp_len=len;
// 	// 	DbgPrint("ZwProtectVirtualMemory = %#x\n",
// 	// 		ZwProtectVirtualMemory((HANDLE)-1,&tmp_addr,&tmp_len,oldprotect,&oldprotect)
// 	// 		);
// 	// 	KeUnstackDetachProcess(pApcState);
// 	// 	ObDereferenceObject(proc);
// 	// 	ExFreePool(pApcState);
// 	// 	DbgPrint("WriteProcessMemory finish\n");
// 	// }
// 	// __except (EXCEPTION_EXECUTE_HANDLER)
// 	// {
// 	// 	DbgPrint("WriteProcessMemory exception\n");
// 	// 	KeUnstackDetachProcess(pApcState);
// 	// 	ObDereferenceObject(proc);
// 	// }
// }
//
// void ReadProcessMemory()
// {
// 	
// 	NTSTATUS status = STATUS_SUCCESS;
// 	PEPROCESS proc = NULL;
//     UINT64 RetureSize;
// 	__try
// 	{
// 		status = PsLookupProcessByProcessId(pid, &proc);
// 		if (!NT_SUCCESS(status))
// 		{
// 			DbgPrint("PsLookupProcessByProcessId fail\npid = %d\n", pid);
// 			return;
// 		}
// 		UNICODE_STRING name=RTL_CONSTANT_STRING(L"MmCopyVirtualMemory");
// 		pfn_MmCopyVirtualMemory MmCopyVirtualMemory=(pfn_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&name);
// 		if(MmCopyVirtualMemory==NULL)
// 		{
// 			DbgPrint("MmGetSystemRoutineAddress MmCopyVirtualMemory fail\n");
// 			ObDereferenceObject(proc);
// 			return;
// 		}
// 		MmCopyVirtualMemory(proc,address,PsGetCurrentProcess(),g_buffer,sizeof(g_buffer),KernelMode,&RetureSize);
// 		InterlockedIncrement(&cnt_read);
// 		ObDereferenceObject(proc);
// 		DbgPrint("ReadProcessMemory finish\n");
// 	}
// 	__except (EXCEPTION_EXECUTE_HANDLER)
// 	{
// 		DbgPrint("ReadProcessMemory exception\n");
// 		ObDereferenceObject(proc);
// 	}
// }
//
//
//
// // void GetWow64Kernel32Address()
// // {
// // 	NTSTATUS status=STATUS_SUCCESS;
// // 	PEPROCESS eprocess = NULL;
// // 	__try {
// // 		
// // 		status = PsLookupProcessByProcessId(pid, &eprocess);
// // 		if (!NT_SUCCESS(status))
// // 		{
// // 			DbgPrint("PsLookupProcessByProcessId fail\n");
// // 			return;
// // 		}
// // 		PPEB32 ppeb32 = (PPEB32)((char*)eprocess + 0x1b0);
// // 		for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)ppeb32->Ldr)->InLoadOrderModuleList.Flink;
// // 			pListEntry != &((PPEB_LDR_DATA32)ppeb32->Ldr)->InLoadOrderModuleList; pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
// // 		{
// // 			PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
// // 			if (LdrEntry->BaseDllName.Buffer == NULL)
// // 			{
// // 				continue;
// // 			}
// // 			if(_wcsicmp((PWCHAR)LdrEntry->BaseDllName.Buffer,L"kernel32.dll")==0)
// // 			{
// // 				DbgPrint("Wow64 kernel32.dll -> %#x",LdrEntry->DllBase);
// // 			}
// // 		}
// //
// // 		ObDereferenceObject(eprocess);
// // 	}
// //     __except (EXCEPTION_EXECUTE_HANDLER) {
// // 		DbgPrint("GetWow64Kernel32Address exception\n");
// // 		//KeUnstackDetachProcess(&apc);
// // 		ObDereferenceObject(eprocess);
// //     }
// //     return;
// // }
//
// void GetWow64Kernel32Address()
// {
// 	NTSTATUS status;
// 	KAPC_STATE KAPC = { 0 };
// 	PEPROCESS eprocess = 0;
// 	UNICODE_STRING func_name=RTL_CONSTANT_STRING(L"PsGetProcessPeb");
// 	pfn_PsGetProcessPeb PsGetProcessPeb = (pfn_PsGetProcessPeb)MmGetSystemRoutineAddress(&func_name);
// 	UNICODE_STRING kernel32 = RTL_CONSTANT_STRING(L"kernel32.dll");
// 	status = PsLookupProcessByProcessId(pid, &eprocess);
// 	if (!NT_SUCCESS(status))
// 	{
// 		DbgPrint("PsLookupProcessByProcessId fail\n");
// 		return;
// 	}
// 	PVOID pPeb = PsGetProcessPeb(eprocess);
// 	if (pPeb == NULL)
// 	{
// 		DbgPrint("pPeb == NULL\n");
// 		ObDereferenceObject(eprocess);
// 		return;
// 	}
// 	__try
// 	{
// 		KeStackAttachProcess(eprocess, &KAPC);
// 		PVOID Ldr = (PVOID)((ULONGLONG)pPeb + 0x018);
// 		ProbeForRead(Ldr, 8, 8);
// 		PLIST_ENTRY ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + 0x010);
// 		ProbeForRead(ModListHead, 8, 8);
// 		PLIST_ENTRY Module = ModListHead->Flink;
// 		while (ModListHead != Module)
// 		{
// 			//打印信息：基址、大小、DLL路径
// 			DbgPrint("模块基址=%p 大小=%ld 路径=%wZ\n",(PVOID)(((PLDR_DATA_TABLE_ENTRY)Module)->DllBase),
// 				(ULONG)(((PLDR_DATA_TABLE_ENTRY)Module)->SizeOfImage),&(((PLDR_DATA_TABLE_ENTRY)Module)->FullDllName));
//
// 			// if(RtlCompareUnicodeString(&((PLDR_DATA_TABLE_ENTRY)Module)->BaseDllName,
// 			// 	&kernel32,true)==0)
// 			// {
// 			// 	DbgPrint("%lu\n",((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
// 			// 	DbgPrint("%llu\n",((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
// 			// 	sprintf_s(g_buffer,sizeof(g_buffer),"%p",((PLDR_DATA_TABLE_ENTRY)Module)->DllBase);
// 			// 	break;
// 			// }
// 			Module = Module->Flink;
// 			//测试下一个模块信息的可读性
// 			ProbeForRead(Module, 80, 8);
// 		}
// 		KeUnstackDetachProcess(&KAPC);
// 		ObDereferenceObject(eprocess);
// 		return;
// 	}
// 	__except(EXCEPTION_EXECUTE_HANDLER)
// 	{
// 		DbgPrint("GetWow64Kernel32Address exception\n");
// 		KeUnstackDetachProcess(&KAPC);
// 		ObDereferenceObject(eprocess);
// 		return;
// 	}
// }
//
//
//
// NTSTATUS DispatchControl(PDEVICE_OBJECT DriverObject, IRP* irp)
// {
// 	NTSTATUS status = STATUS_SUCCESS;
// 	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
// 	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
// 	DbgPrint("code = %lu\n", code);
// 	ULONG in_buf_len = stack->Parameters.DeviceIoControl.InputBufferLength;
// 	ULONG out_buf_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
// 	PVOID buf = irp->AssociatedIrp.SystemBuffer;
// 	ULONG retn_size = 0;
//
//
//
//
// 	KeWaitForMutexObject(&Mutex, Executive, KernelMode, FALSE, NULL);
// 	switch (code)
// 	{
// 	case CTL_MSG_TO_R0:
// 		if(in_buf_len>sizeof(g_buffer))
// 		{
// 			retn_size=sizeof(g_buffer);
// 			status=STATUS_BUFFER_OVERFLOW;
// 		}
// 		else
// 		{
// 			retn_size=in_buf_len;
// 		}
// 		RtlCopyMemory(g_buffer, buf, retn_size);
// 		//DbgPrint("get input\ng_buffer = %s\nretn_size = %lu\n", g_buffer, retn_size);
// 		break;
// 	case CTL_MSG_FROM_R0:
// 		if(out_buf_len>sizeof(g_buffer))
// 		{
// 			retn_size=sizeof(g_buffer);
// 			status=STATUS_BUFFER_OVERFLOW;
// 		}
// 		else
// 		{
// 			retn_size=out_buf_len;
// 		}
// 		RtlCopyMemory(buf, g_buffer, retn_size);
// 		//DbgPrint("output g_buffer\ng_buffer = %s\nretn_size = %lu\n", g_buffer, retn_size);
// 		break;
// 	case CTL_REGISTER_CALLBACK:
// 		RegisterCallback();
// 		break;
// 	case CTL_UNREGISTER_CALLBACK:
// 		UnRegisterCallback();
// 		break;
// 	case CTL_READ:
// 		ReadProcessMemory();
// 		break;
// 	case CTL_WRITE:
// 		WriteProcessMemory();
// 		break;
// 	case CTL_MSG_TYPE_PID:
// 		pid = (HANDLE)atoi(g_buffer);
// 		DbgPrint("pid = %lu\n",pid);
// 		break;
// 	case CTL_MSG_TYPE_ADDRESS:
// 		sscanf_s(g_buffer,"%p",&address);
// 		DbgPrint("address = %p\n",address);
// 		break;
// 	case CTL_MSG_TYPE_LEN:
// 		len = atoi(g_buffer);
// 		DbgPrint("len = %lu\n",len);
// 		break;
// 	case CTL_MSG_TYPE_PROTECTPID:
// 		protect_pid = (HANDLE)atoi(g_buffer);
// 		DbgPrint("protect_pid = %lu\n",protect_pid);
// 		break;
// 	case CTL_MSG_TYPE_DBGPID:
// 		dbg_pid = (HANDLE)atoi(g_buffer);
// 		DbgPrint("dbg_pid = %lu\n",dbg_pid);
// 		break;
// 	case CTL_GET_STATISTIC:
// 		{
// 			
// 		}
// 		sprintf_s(g_buffer,"%d %d %d %d",cnt_read,cnt_write,cnt_callback_protect,cnt_callback_dbg);
// 		if(in_buf_len>strlen(g_buffer))
// 		{
// 			retn_size=sizeof(g_buffer);
// 			status=STATUS_BUFFER_OVERFLOW;
// 		}
// 		else
// 		{
// 			retn_size=in_buf_len;
// 		}
// 		if(out_buf_len>sizeof(g_buffer))
// 		{
// 			retn_size=sizeof(g_buffer);
// 			status=STATUS_BUFFER_OVERFLOW;
// 		}
// 		else
// 		{
// 			retn_size=out_buf_len;
// 		}
// 		RtlCopyMemory(buf, g_buffer, retn_size);
// 		break;
// 	default:
// 		status = STATUS_INVALID_PARAMETER;
// 		DbgPrint("invalid control code\n");
// 	}
// 	KeReleaseMutex(&Mutex, FALSE);
//
// 	irp->IoStatus.Status = status;
// 	irp->IoStatus.Information = retn_size;
// 	IoCompleteRequest(irp, IO_NO_INCREMENT);
// 	return STATUS_SUCCESS;
// }
//
// NTSTATUS DispatchRoutine(PDEVICE_OBJECT DriverObject, IRP* irp)
// {
// 	NTSTATUS status = STATUS_SUCCESS;
// 	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
// 	static char* irp_name[] =
// 	{ "IRP_MJ_CREATE					 ",
// 		"IRP_MJ_CREATE_NAMED_PIPE        ",
// 		 "IRP_MJ_CLOSE                   ",
// 		 "IRP_MJ_READ                    ",
// 		 "IRP_MJ_WRITE                   ",
// 		 "IRP_MJ_QUERY_INFORMATION       ",
// 		 "IRP_MJ_SET_INFORMATION         ",
// 		 "IRP_MJ_QUERY_EA                ",
// 		 "IRP_MJ_SET_EA                  ",
// 		 "IRP_MJ_FLUSH_BUFFERS           ",
// 		 "IRP_MJ_QUERY_VOLUME_INFORMATION",
// 		 "IRP_MJ_SET_VOLUME_INFORMATION  ",
// 		 "IRP_MJ_DIRECTORY_CONTROL       ",
// 		 "IRP_MJ_FILE_SYSTEM_CONTROL     ",
// 		 "IRP_MJ_DEVICE_CONTROL          ",
// 		 "IRP_MJ_INTERNAL_DEVICE_CONTROL ",
// 		 "IRP_MJ_SHUTDOWN                ",
// 		 "IRP_MJ_LOCK_CONTROL            ",
// 		 "IRP_MJ_CLEANUP                 ",
// 		 "IRP_MJ_CREATE_MAILSLOT         ",
// 		 "IRP_MJ_QUERY_SECURITY          ",
// 		 "IRP_MJ_SET_SECURITY            ",
// 		 "IRP_MJ_POWER                   ",
// 		 "IRP_MJ_SYSTEM_CONTROL          ",
// 		 "IRP_MJ_DEVICE_CHANGE           ",
// 		 "IRP_MJ_QUERY_QUOTA             ",
// 		 "IRP_MJ_SET_QUOTA               ",
// 		 "IRP_MJ_PNP                     ",
// 		 "IRP_MJ_PNP_POWER               ",
// 		 "IRP_MJ_MAXIMUM_FUNCTION		 "
// 	};
//
// 	DbgPrint("%s\n", irp_name[stack->MajorFunction]);
// 	irp->IoStatus.Status = status;
// 	irp->IoStatus.Information = 0;
// 	IoCompleteRequest(irp, IO_NO_INCREMENT);
// 	return STATUS_SUCCESS;
//
// }
//
// extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
// {
// 	NTSTATUS status = STATUS_SUCCESS;
// 	((PLDR_DATA)DriverObject->DriverSection)->Flags |= 0x20;    //绕过签名检测
// 	DriverObject->DriverUnload = DrvUnload;
// 	KeInitializeMutex(&Mutex, 0);
// 	UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\my_device");
// 	PDEVICE_OBJECT device_object;
// 	status = IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device_object);
// 	if (!NT_SUCCESS(status))
// 	{
// 		//设备已经存在
// 		if (status == STATUS_OBJECT_NAME_COLLISION)
// 		{
// 			DbgPrint("设备已经存在\n");
// 			return status;
// 		}
// 		else
// 		{
// 			DbgPrint("创建设备失败，status = %#x\n", status);
// 			return status;
// 		}
// 	}
// 	device_object->Flags |= DO_BUFFERED_IO;
// 	device_object->Flags &= ~DO_DEVICE_INITIALIZING;
//
// 	UNICODE_STRING symbolic_name = RTL_CONSTANT_STRING(L"\\??\\my_link");
// 	status = IoCreateSymbolicLink(&symbolic_name, &device_name);
// 	if (!NT_SUCCESS(status))
// 	{
// 		DbgPrint("创建符号链接失败，status = %#x\n", status);
// 		IoDeleteDevice(device_object);
// 		return status;
// 	}
// 	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
// 	{
// 		DriverObject->MajorFunction[i] = DispatchRoutine;
// 	}
// 	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchControl;
//
// 	DbgPrint("init finish\n");
// 	return STATUS_SUCCESS;
// }
//
