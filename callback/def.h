#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64	InLoadOrderLinks;
	LIST_ENTRY64	InMemoryOrderLinks;
	LIST_ENTRY64	InInitializationOrderLinks;
	PVOID			DllBase;
	PVOID			EntryPoint;
	ULONG			SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING 	BaseDllName;
	ULONG			Flags;
	USHORT			LoadCount;
	USHORT			TlsIndex;
	PVOID			SectionPointer;
	ULONG			CheckSum;
	PVOID			LoadedImports;
	PVOID			EntryPointActivationContext;
	PVOID			PatchInformation;
	LIST_ENTRY64	ForwarderLinks;
	LIST_ENTRY64	ServiceTagLinks;
	LIST_ENTRY64	StaticLinks;
	PVOID			ContextInformation;
	ULONG64			OriginalBase;
	LARGE_INTEGER	LoadTime;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA
{
	struct _LIST_ENTRY InLoadOrderLinks;
	struct _LIST_ENTRY InMemoryOrderLinks;
	struct _LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG32      SizeOfImage;
	UINT8        _PADDING0_[0x4];
	struct _UNICODE_STRING FullDllName;
	struct _UNICODE_STRING BaseDllName;
	ULONG32      Flags;
}LDR_DATA, * PLDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY32 HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;


typedef struct _OBJECT_HEADER {
    union {
        struct {
            ULONG_PTR PointerCount;
            union {
                ULONG_PTR HandleCount;
                void* NextToFree;
            };
        };
        void* VolatilePointer;
    };
    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;
    UCHAR TraceFlags;
    union {
        UCHAR DbgRefTrace : 1;
        UCHAR DbgTracePermanent : 1;
        UCHAR ReservedFlags : 6;
    };
    UCHAR InfoMask;
    union {
        UCHAR Flags;
        struct {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };
    union {
        void* ObjectCreateInfo;
        void* QuotaBlockCharged;
    };
    void* SecurityDescriptor;
    struct _QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;






typedef struct _HANDLE_TABLE {
   PVOID        p_hTable;
   PEPROCESS    QuotaProcess;
   PVOID        UniqueProcessId;
   //EX_PUSH_LOCK HandleTableLock [4];
   LIST_ENTRY   HandleTableList;
   //EX_PUSH_LOCK HandleContentionEvent;
   //PHANDLE_TRACE_DEBUG_INFO DebugInfo;
   DWORD64        ExtraInfoPages;
   DWORD64        FirstFree;
   DWORD64        LastFree;
   DWORD64        NextHandleNeedingPool;
   DWORD64        HandleCount;
   DWORD64        Flags;
}HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _HANDLE_TABLE_ENTRY {
    //
    // The pointer to the object overloaded with three ob attributes bits in
    // the lower order and the high bit to denote locked or unlocked entries
    //
    union {
        PVOID Object;
        ULONG ObAttributes;
        //PHANDLE_TABLE_ENTRY_INFO InfoTable;
        ULONG_PTR Value;
    };
    //
    // This field either contains the granted access mask for the handle or an
    // ob variation that also stores the same information. Or in the case of
    // a free entry the field stores the index for the next free entry in the
    // free list. This is like a FAT chain, and is used instead of pointers
    // to make table duplication easier, because the entries can just be
    // copied without needing to modify pointers.
    //
    union {
        union {
            ACCESS_MASK GrantedAccess;
            struct {
                USHORT GrantedAccessIndex;
                USHORT CreatorBackTraceIndex;
            };
        };
        LONG NextFreeTableEntry;
    };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef BOOLEAN (*EX_ENUMERATE_HANDLE_ROUTINE)(
PVOID HANDLE_TABLE,
PHANDLE_TABLE_ENTRY HandleTableEntry,
HANDLE Handle,
PVOID EnumParameter
);





extern "C" NTKERNELAPI CHAR* PsGetProcessImageFileName(PEPROCESS Process);
extern "C" NTKERNELAPI BOOLEAN ExEnumHandleTable (PVOID HandleTable,EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,PVOID EnumParameter,PHANDLE Handle);
extern "C" POBJECT_TYPE ObGetObjectType(PVOID Object);
extern "C" VOID ExfUnblockPushLock(__inout PEX_PUSH_LOCK PushLock,__inout_opt PVOID WaitBlock);
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);

typedef PVOID (__stdcall *pfn_PsGetProcessPeb)(PEPROCESS);
typedef NTKERNELAPI PVOID (NTAPI *pfn_PsGetProcessWow64Process)(PEPROCESS Process);
//NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
typedef NTSTATUS (NTAPI *pfn_MmCopyVirtualMemory)(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);


#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)




