#pragma once

extern "C"
{
#pragma pack(push, 1)
	// 定义 LDR_DATA_TABLE_ENTRY 结构体
	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG64 SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		SHORT LoadCount;
		SHORT TlsIndex;
		LIST_ENTRY HashLinks;
		PVOID SectionPointer;
		ULONG CheckSum;
		ULONG TimeDateStamp;
		PVOID LoadedImports;
		PVOID EntryPointActivationContext;
		PVOID PatchInformation;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemProcessInformation = 5,
		SystemModuleInformation = 11,
		SystemKernelDebuggerInformation = 35
	} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

	// 模块详细信息结构
	typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
		HANDLE Section;
		PVOID MappedBase;
		PCHAR Base;
		ULONG Size;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT PathLength;
		CHAR ImageName[256];
	} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

	typedef struct _SYSTEM_MODULE_INFO_LIST
	{
		ULONG_PTR ulCount;
		SYSTEM_MODULE_INFORMATION_ENTRY smi[1];
	} SYSTEM_MODULE_INFO_LIST, *PSYSTEM_MODULE_INFO_LIST;

	typedef struct _PEB_LDR_DATA                            // 9 elements, 0x58 bytes (sizeof) 
	{
		/*0x000*/     ULONG32      Length;
		/*0x004*/     UINT8        Initialized;
		/*0x005*/     UINT8        _PADDING0_[0x3];
		/*0x008*/     VOID*        SsHandle;
		/*0x010*/     LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof) 
		/*0x020*/     LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof) 
		/*0x030*/     LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof) 
		/*0x040*/     VOID*        EntryInProgress;
		/*0x048*/     UINT8        ShutdownInProgress;
		/*0x049*/     UINT8        _PADDING1_[0x7];
		/*0x050*/     VOID*        ShutdownThreadId;
	}PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _PEB_S                                                                                                                                                                                                                                                                                                                                                                                                                                 // 115 elements, 0x7C8 bytes (sizeof) 
	{
		/*0x000*/     UINT8        InheritedAddressSpace;
		/*0x001*/     UINT8        ReadImageFileExecOptions;
		/*0x002*/     UINT8        BeingDebugged;
		union                                                                                                                                                                                                                                                                                                                                                                                                                                           // 2 elements, 0x1 bytes (sizeof)     
		{
			/*0x003*/         UINT8        BitField;
			struct                                                                                                                                                                                                                                                                                                                                                                                                                                      // 8 elements, 0x1 bytes (sizeof)     
			{
				/*0x003*/             UINT8        ImageUsesLargePages : 1;                                                                                                                                                                                                                                                                                                                                                                                                   // 0 BitPosition                      
				/*0x003*/             UINT8        IsProtectedProcess : 1;                                                                                                                                                                                                                                                                                                                                                                                                    // 1 BitPosition                      
				/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;                                                                                                                                                                                                                                                                                                                                                                                           // 2 BitPosition                      
				/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1;                                                                                                                                                                                                                                                                                                                                                                                          // 3 BitPosition                      
				/*0x003*/             UINT8        IsPackagedProcess : 1;                                                                                                                                                                                                                                                                                                                                                                                                     // 4 BitPosition                      
				/*0x003*/             UINT8        IsAppContainer : 1;                                                                                                                                                                                                                                                                                                                                                                                                        // 5 BitPosition                      
				/*0x003*/             UINT8        IsProtectedProcessLight : 1;                                                                                                                                                                                                                                                                                                                                                                                               // 6 BitPosition                      
				/*0x003*/             UINT8        IsLongPathAwareProcess : 1;                                                                                                                                                                                                                                                                                                                                                                                                // 7 BitPosition                      
			};
		};
		/*0x004*/     UINT8        Padding0[4];
		/*0x008*/     VOID*        Mutant;
		/*0x010*/     VOID*        ImageBaseAddress;
		/*0x018*/     PEB_LDR_DATA* Ldr;
	}PEB_S, *PPEB_S;
#pragma pack(pop)

	/*
		内核未公开函数声明
	*/
	NTSTATUS ObReferenceObjectByName(
		__in PUNICODE_STRING ObjectName,
		__in ULONG Attributes,
		__in_opt PACCESS_STATE AccessState,
		__in_opt ACCESS_MASK DesiredAccess,
		__in POBJECT_TYPE ObjectType,
		__in KPROCESSOR_MODE AccessMode,
		__inout_opt PVOID ParseContext,
		__out PVOID *Object
	);

	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);

	// 获取 EPROCESS 结构中的 ImageFileName
	PCHAR PsGetProcessImageFileName(PEPROCESS Process);

	// 获取指定进程的 PEB
	PPEB PsGetProcessPeb(PEPROCESS Process);

	NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);
}