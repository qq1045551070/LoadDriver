#include "Loaddriver.h"
#include "sysfile.h"
#include "mm.h"
#include "pml4.h"
#include <ntimage.h>
#include <ntstrsafe.h>

#pragma pack(push, 1)
typedef struct _IMAGE_RELOC
{
	UINT16 Offset : 12;
	UINT16 Type : 4;
}IMAGE_RELOC, *PIMAGE_RELOC;

typedef struct _IMAGE_BASE_RELOCATION_S {
	ULONG   VirtualAddress;
	ULONG   SizeOfBlock;
	USHORT  TypeOffset[1];
}IMAGE_BASE_RELOCATION_S, *PIMAGE_BASE_RELOCATION_S;

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

typedef struct _PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
}PiDDBCacheEntry, *PPiDDBCacheEntry;
#pragma pack(pop)

extern "C"
{
	typedef VOID(NTAPI*pRtlInsertInvertedFunctionTable)(
		IN PVOID* InvertedTable,
		IN PVOID ImageBase,
		IN ULONG SizeOfImage);
	pRtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable = NULL;

	PIMAGE_LOAD_CONFIG_DIRECTORY RtlImageDirectoryEntryToData(PVOID BaseAddress, BOOLEAN MappedAsImage, USHORT Directory, PULONG Size);

	UCHAR* PeImage = NULL;
	PIMAGE_DOS_HEADER DosHeader = NULL;
	PIMAGE_NT_HEADERS NtHeader = NULL;
	PIMAGE_SECTION_HEADER SectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY DataDir = NULL;
	PDRIVER_INITIALIZE DriverEntryPointer = NULL;

	_Use_decl_annotations_
		PDRIVER_INITIALIZE LoadDriver::LoadDriverInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
	{
		Pml4::Pml4Init();

		DosHeader = (PIMAGE_DOS_HEADER)data;
		NtHeader = (PIMAGE_NT_HEADERS)(data + DosHeader->e_lfanew);
		SectionHeader = IMAGE_FIRST_SECTION(NtHeader);

		// 文件自删除
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		DeleteFile(&entry->FullDllName);

		// 清空注册表信息
		DeleteRegistry(RegPath);

		// Clear Current Driver PiDDBCache Table Information (注意目前只解决了Win7\Win10 1809硬编码)
		clearPiDDBCacheTableEntry(&entry->BaseDllName);
		// Clear Current Driver MmUnloadedDrivers Table Information
		clearUnloadTableEntry(DriverObject, entry->BaseDllName.Buffer);

		// 创建互斥体，防止多开
		UNICODE_STRING unEvEntName = {};
		HANDLE EventHandle = NULL;
		RtlInitUnicodeString(&unEvEntName, L"\\BaseNamedObjects\\SM0:4772:303:WilStaging_lg_p0");
		OBJECT_ATTRIBUTES objAttr = {};
		InitializeObjectAttributes(&objAttr, &unEvEntName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		NTSTATUS NtStatus = ZwCreateEvent(&EventHandle, EVENT_ALL_ACCESS, &objAttr, NotificationEvent, FALSE);
		if (!NT_SUCCESS(NtStatus))
		{
			return NULL;
		}

		// 拉伸PE
		PeImage = UnFoldPE(data);
		if (PeImage == NULL)
			return NULL;

		// 修复重定位
		FixBaseRelocTable(PeImage);

		//if (UpdateReloc() == false)
		//	return;

		// 修复IAT
		if (UpdateIat() == false)
			return NULL;
		
		ULONG retSize = 0;
		// 解决 __security_cookie 问题
		PIMAGE_LOAD_CONFIG_DIRECTORY loadDir = RtlImageDirectoryEntryToData(PeImage, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &retSize);
		*(PULONG64)loadDir->SecurityCookie += 100;

		// 注册异常处理函数 (注意目前只解决了Win7)
		RegistryException(PeImage, NtHeader->OptionalHeader.SizeOfImage);

		// 清除ShellCode Driver PE头
		memset(PeImage, 0xCC/*0xF1*/, NtHeader->OptionalHeader.SizeOfHeaders);

		return DriverEntryPointer ? DriverEntryPointer : NULL;
	}

	PHYSICAL_ADDRESS phyLow = {};
	PHYSICAL_ADDRESS phyHigh = {};
	_Use_decl_annotations_
		UCHAR* LoadDriver::UnFoldPE(UCHAR* PeFile)
	{
		UCHAR* file_pointer = PeFile; 
		UCHAR* image_pointer = NULL;
		ULONG file_size = sizeof(PeFile);
		phyLow.QuadPart = 0;
		phyHigh.QuadPart = -1;

		int cout_max = 3;
		do
		{
			// 此处不能用 ExAllocatePool 申请内存, 其是从内存池中获取内存, 会被 ZwQuerySystemInformation 检测到
			// MmAllocateContiguousMemorySpecifyCache 自建内存页
			image_pointer = 
						(PUCHAR)MmAllocateContiguousMemorySpecifyCache(NtHeader->OptionalHeader.SizeOfImage, phyLow, phyHigh, phyLow, MmCached);
			if (image_pointer) break;
		} while (cout_max--);
		
		if (!image_pointer) return NULL;

		// 拷贝PE头
		memcpy(image_pointer, file_pointer, NtHeader->OptionalHeader.SizeOfHeaders);
		// 拷贝节
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		{
			memcpy(image_pointer + SectionHeader->VirtualAddress, file_pointer + SectionHeader->PointerToRawData, 
				SectionHeader->SizeOfRawData);

			SectionHeader++;
		}

		DriverEntryPointer = (PDRIVER_INITIALIZE)(NtHeader->OptionalHeader.AddressOfEntryPoint + image_pointer);

		return image_pointer;
	}

	_Use_decl_annotations_
		void LoadDriver::FixBaseRelocTable(PVOID pNewImage)
	{
		ULONG                   uIndex;
		ULONG                   uRelocTableSize;
		ULONG_PTR				OriginalImageBase;
		ULONG                   Type;
		ULONG_PTR               *uRelocAddress;
		PIMAGE_DOS_HEADER       pImageDosHeader;
		PIMAGE_NT_HEADERS64     pImageNtHeader;
		IMAGE_DATA_DIRECTORY    ImageDataDirectory;
		IMAGE_BASE_RELOCATION_S *pImageBaseRelocation;
		//将新内核地址作为一个PE文件头，依次向下，目的是寻找重定位表结构
		pImageDosHeader = (PIMAGE_DOS_HEADER)pNewImage;
		//定位到IMAGE_NT_HEADER
		pImageNtHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pNewImage + pImageDosHeader->e_lfanew);
		//获取内核文件的imagebase，以便后面做偏移修改。
		OriginalImageBase = pImageNtHeader->OptionalHeader.ImageBase;
		//定位到数据目录
		ImageDataDirectory = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		//定位到重定位表结构
		pImageBaseRelocation = (PIMAGE_BASE_RELOCATION_S)(ImageDataDirectory.VirtualAddress + (ULONG_PTR)pNewImage);
		if (pImageBaseRelocation == NULL)
		{
			return;
		}
		while (pImageBaseRelocation->SizeOfBlock)
		{   //计算需要修改的地址的个数
			uRelocTableSize = (pImageBaseRelocation->SizeOfBlock - 8) / 2;
			//循环遍历
			for (uIndex = 0; uIndex < uRelocTableSize; uIndex++)
			{//判断高4位是否等于3
				Type = pImageBaseRelocation->TypeOffset[uIndex] >> 12;
				if (Type == IMAGE_REL_BASED_DIR64)
				{
					//修改地址，相对地址加上一个新内核地址，使其成为一个实际地址
					uRelocAddress = (ULONG64 *)((ULONG64)(pImageBaseRelocation->TypeOffset[uIndex] & 0x0fff) + pImageBaseRelocation->VirtualAddress + (ULONG64)pNewImage);
					//再加上内核首地址到imagebase的偏移
					*uRelocAddress = *uRelocAddress + ((ULONG64)PeImage - OriginalImageBase);
				}
			}
			//进行下一个重定位表的修改
			pImageBaseRelocation = (IMAGE_BASE_RELOCATION_S *)((ULONG64)pImageBaseRelocation + pImageBaseRelocation->SizeOfBlock);
		}
	}

	_Use_decl_annotations_
		NTSTATUS LoadDriver::clearUnloadTableEntry(PDRIVER_OBJECT driver, wchar_t* driverName)
	{
		__try
		{
			PLDR_DATA_TABLE_ENTRY currentEntry = (PLDR_DATA_TABLE_ENTRY)(driver->DriverSection);
			PLDR_DATA_TABLE_ENTRY BeginningEntry = currentEntry;

			while ((PLDR_DATA_TABLE_ENTRY)(currentEntry->InLoadOrderLinks.Flink) != BeginningEntry)
			{
				if (!(ULONG)currentEntry->EntryPoint > MmUserProbeAddress)
				{
					currentEntry = (PLDR_DATA_TABLE_ENTRY)(currentEntry->InLoadOrderLinks.Flink);
					continue;
				}
				if (wcsstr(currentEntry->BaseDllName.Buffer, driverName)) {
					//matched, set basedllname.length to 0
					//MiRememberUnloadedDriver wont add to MmUnloadedDrivers if the name length is <= 0
					currentEntry->BaseDllName.Length = 0;
					return STATUS_SUCCESS;
				}
				currentEntry = (PLDR_DATA_TABLE_ENTRY)(currentEntry->InLoadOrderLinks.Flink);
			}
			return STATUS_UNSUCCESSFUL;
		}
		__except
			(1)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	_Use_decl_annotations_
		NTSTATUS LoadDriver::clearPiDDBCacheTableEntry(PUNICODE_STRING	DriverName)
	{
		// first locate required variables
		PERESOURCE PiDDBLock = NULL; PRTL_AVL_TABLE PiDDBCacheTable = NULL;
		LARGE_INTEGER uTemp = {};
		UCHAR* shellcode1 = NULL;
		UCHAR* shellcode2 = NULL;
		UCHAR* shellcode3 = NULL;
		UCHAR* shellcode4 = NULL;
		ULONG64 PpReleaseBootDDB_Ptr = NULL;
		ULONG64 PiLookupInDDBCache_Ptr = NULL;

		if (Pml4::GetWindowsVersion() == WIN7)
		{
			shellcode1 = (UCHAR*)"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20";	//win7:0x1A
			shellcode2 = (UCHAR*)"\x66\xff\x88\xc4\x01\x00\x00\x48\x8d\x0d";	//
			shellcode3 = (UCHAR*)"\x48\x8d\x0d****\x49\x8b\xe9";				//10
			shellcode4 = (UCHAR*)"\xff\xf3\x55\x56\x57\x41\x54\x48\x83\xec\x60"; //11
			PpReleaseBootDDB_Ptr = Mm::MmSearch(shellcode1, shellcode2, 0x13, 10, 10); // PpReleaseBootDDB
			PiLookupInDDBCache_Ptr = Mm::MmSearch(shellcode3, shellcode4, -0x25, 10, 11); // PiLookupInDDBCache
			if (!PpReleaseBootDDB_Ptr || !PiLookupInDDBCache_Ptr)
				return STATUS_UNSUCCESSFUL;
			uTemp.QuadPart = PpReleaseBootDDB_Ptr + 0x1A + 0x7;
			uTemp.LowPart += *(ULONG*)(PpReleaseBootDDB_Ptr + 0x1A + 0x3);
			PiDDBLock = (PERESOURCE)(uTemp.QuadPart);
			uTemp.QuadPart = PiLookupInDDBCache_Ptr + 0x7;
			uTemp.LowPart += *(ULONG*)(PiLookupInDDBCache_Ptr + 0x3);
			PiDDBCacheTable = (PRTL_AVL_TABLE)(uTemp.QuadPart);
		}
		else if (Pml4::GetWindowsVersion() == WIN10)
		{
			// 针对1809
			shellcode1 = (UCHAR*)"\x40\x53\x48\x83\xec\x20";				//win10 1809:0x18
			shellcode2 = (UCHAR*)"\x66\xff\x88\xe4\x01\x00\x00\xb2\x01";	//
			PpReleaseBootDDB_Ptr = Mm::MmSearch(shellcode1, shellcode2, 0xF, 6, 9); // PpReleaseBootDDB
			if (!PpReleaseBootDDB_Ptr)
				return STATUS_UNSUCCESSFUL;
			uTemp.QuadPart = PpReleaseBootDDB_Ptr + 0x18 + 0x7;
			uTemp.LowPart += *(ULONG*)(PpReleaseBootDDB_Ptr + 0x18 + 0x3);
			PiDDBLock = (PERESOURCE)(uTemp.QuadPart);
			PiDDBCacheTable = (PRTL_AVL_TABLE)(uTemp.QuadPart + 0x53A410);
		}

		if (!PiDDBLock || !PiDDBCacheTable)
			return STATUS_UNSUCCESSFUL;

		// get the nt headers of the current driver
		auto pNtHeaders = NtHeader;

		// build a lookup entry
		PiDDBCacheEntry lookupEntry = { };
		lookupEntry.DriverName = *DriverName;
		lookupEntry.TimeDateStamp = pNtHeaders->FileHeader.TimeDateStamp;

		// acquire the ddb resource lock
		ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

		// search our entry in the table
		auto pFoundEntry = (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
		if (pFoundEntry == nullptr)
		{
			// release the ddb resource lock
			ExReleaseResourceLite(PiDDBLock);

			return STATUS_UNSUCCESSFUL;
		}

		// first, unlink from the list
		RemoveEntryList(&pFoundEntry->List);
		// then delete the element from the avl table
		RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);

		// release the ddb resource lock
		ExReleaseResourceLite(PiDDBLock);

		return STATUS_SUCCESS;
	}

	PIMAGE_DATA_DIRECTORY ImportDir = NULL;
	UNICODE_STRING uFuncName = {};
	ANSI_STRING aFuncName = {};
	_Use_decl_annotations_
		bool LoadDriver::UpdateIat()
	{
		ImportDir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		PIMAGE_THUNK_DATA pNames = NULL;
		PIMAGE_THUNK_DATA pFuncPointer = NULL;
		PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(PeImage + ImportDir->VirtualAddress);

		ULONG NtStatus = STATUS_UNSUCCESSFUL;
		PUCHAR DllName = NULL;
		PIMAGE_IMPORT_BY_NAME name = NULL;
		ULONG64 func = 0; ULONG oA = 0;	

		for (; ImportDesc->Name; ImportDesc++)
		{
			DllName = ImportDesc->Name + PeImage;

			pNames = (PIMAGE_THUNK_DATA)(PeImage + ImportDesc->OriginalFirstThunk);
			pFuncPointer = (PIMAGE_THUNK_DATA)(PeImage + ImportDesc->FirstThunk);

			for (; pNames->u1.ForwarderString; pNames++, pFuncPointer++)
			{
				name = (PIMAGE_IMPORT_BY_NAME)(pNames->u1.AddressOfData + PeImage);
				RtlInitAnsiString(&aFuncName, name->Name);
				NtStatus = RtlAnsiStringToUnicodeString(&uFuncName, &aFuncName, TRUE);
				if (NT_SUCCESS(NtStatus))
				{
					func = (ULONG64)MmGetSystemRoutineAddress(&uFuncName);

					if (func)
					{
						pFuncPointer->u1.Function = func;
					}
					else
					{
						KdBreakPoint(); return false;
					}
					RtlFreeUnicodeString(&uFuncName);
				}
				else {
					KdBreakPoint(); return false;
				}		
			}

		}

		return true;
	}
	
	_Use_decl_annotations_
		bool LoadDriver::DeleteFile(PUNICODE_STRING Path)
	{
		HANDLE hFile = NULL;
		OBJECT_ATTRIBUTES obj = { 0 };
		IO_STATUS_BLOCK IoStatck = { 0 };
		InitializeObjectAttributes(&obj, Path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		// 获取文件句柄
		NTSTATUS NtStatus = NtCreateFile(&hFile, FILE_READ_ACCESS, &obj, &IoStatck, NULL,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
		if (!NT_SUCCESS(NtStatus)) 
			return FALSE;
		// 获取文件对象
		PFILE_OBJECT FileObject = NULL;
		NtStatus = ObReferenceObjectByHandle(hFile, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
		if (!NT_SUCCESS(NtStatus)) {
			ZwClose(hFile);
			return FALSE;
		}
		ZwClose(hFile);
		// 这里采用文件强制删除的方式
		FileObject->DeletePending = 0;
		FileObject->DeleteAccess = 1;
		FileObject->SharedDelete = 1;
		FileObject->SectionObjectPointer->DataSectionObject = NULL;
		FileObject->SectionObjectPointer->ImageSectionObject = NULL;
		FileObject->SectionObjectPointer->SharedCacheMap = NULL;
		NtStatus = ZwDeleteFile(&obj);
		ObDereferenceObject(FileObject);
		if (!NT_SUCCESS(NtStatus))
		{
			
			return FALSE;
		}
		return TRUE;
	}

	_Use_decl_annotations_
		bool LoadDriver::DeleteRegistry(PUNICODE_STRING pReg)
	{
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"DisplayName");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"ErrorControl");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"ImagePath");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"Start");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, pReg->Buffer, L"Type");

		wchar_t path_buffer[256] = { 0 };
		RtlStringCbPrintfW(path_buffer, 512, L"%ws\\%s", pReg->Buffer, L"Enum");

		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, path_buffer, L"Count");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, path_buffer, L"INITSTARTFAILED");
		RtlDeleteRegistryValue(RTL_REGISTRY_ABSOLUTE, path_buffer, L"NextInstance");

		HANDLE hKey = NULL;
		OBJECT_ATTRIBUTES keyObjAttr = {};
		UNICODE_STRING unEnumName = {};
		RtlInitUnicodeString(&unEnumName, path_buffer);
		InitializeObjectAttributes(&keyObjAttr, &unEnumName, OBJ_CASE_INSENSITIVE, NULL, NULL);
		NTSTATUS NtStatus = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &keyObjAttr);
		if (NtStatus != STATUS_SUCCESS) return false;
		ZwDeleteKey(hKey);
		ZwClose(hKey);
		
		HANDLE hKey2 = NULL;
		OBJECT_ATTRIBUTES keyObjAttr2 = {};
		InitializeObjectAttributes(&keyObjAttr2, pReg, OBJ_CASE_INSENSITIVE, NULL, NULL);
		NtStatus = ZwOpenKey(&hKey2, KEY_ALL_ACCESS, &keyObjAttr2);
		if (NtStatus != STATUS_SUCCESS) return false;
		ZwDeleteKey(hKey2);
		ZwClose(hKey2);
	}

	_Use_decl_annotations_
		bool LoadDriver::RegistryException(PVOID MoudleBase, ULONG MoudleSize)
	{
		if (Pml4::GetWindowsVersion() == WIN7)
		{
			// 采用 RtlInsertInvertedFunctionTable 注册异常函数(Ps: Win10 会引发PG)
			UCHAR* shellcode1 = (UCHAR*)"\x48\x89\x5c\x24\x10\x48\x89\x4c\x24\x08";
			UCHAR* shellcode2 = (UCHAR*)"\x48\x8b\x5c\x24\x48\x48\x83\xc4\x20";
			RtlInsertInvertedFunctionTable = (pRtlInsertInvertedFunctionTable)Mm::MmSearch(shellcode1, shellcode2,
				0xB4/*shellcode1 + 0xB4 = shellcode2*/, 10, 9);
			if (!RtlInsertInvertedFunctionTable || !MoudleBase || !MoudleSize) {
				return false;
			}

			PVOID unKnow = NULL;
			RtlInsertInvertedFunctionTable(&unKnow, MoudleBase, MoudleSize);
		}

		return true;
	}
}

