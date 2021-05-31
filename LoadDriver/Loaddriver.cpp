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

// ���� LDR_DATA_TABLE_ENTRY �ṹ��
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

		// �ļ���ɾ��
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		DeleteFile(&entry->FullDllName);

		// ���ע�����Ϣ
		DeleteRegistry(RegPath);

		// Clear Current Driver PiDDBCache Table Information (ע��Ŀǰֻ�����Win7\Win10 1809Ӳ����)
		clearPiDDBCacheTableEntry(&entry->BaseDllName);
		// Clear Current Driver MmUnloadedDrivers Table Information
		clearUnloadTableEntry(DriverObject, entry->BaseDllName.Buffer);

		// ���������壬��ֹ�࿪
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

		// ����PE
		PeImage = UnFoldPE(data);
		if (PeImage == NULL)
			return NULL;

		// �޸��ض�λ
		FixBaseRelocTable(PeImage);

		//if (UpdateReloc() == false)
		//	return;

		// �޸�IAT
		if (UpdateIat() == false)
			return NULL;
		
		ULONG retSize = 0;
		// ��� __security_cookie ����
		PIMAGE_LOAD_CONFIG_DIRECTORY loadDir = RtlImageDirectoryEntryToData(PeImage, TRUE, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &retSize);
		*(PULONG64)loadDir->SecurityCookie += 100;

		// ע���쳣������ (ע��Ŀǰֻ�����Win7)
		RegistryException(PeImage, NtHeader->OptionalHeader.SizeOfImage);

		// ���ShellCode Driver PEͷ
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
			// �˴������� ExAllocatePool �����ڴ�, ���Ǵ��ڴ���л�ȡ�ڴ�, �ᱻ ZwQuerySystemInformation ��⵽
			// MmAllocateContiguousMemorySpecifyCache �Խ��ڴ�ҳ
			image_pointer = 
						(PUCHAR)MmAllocateContiguousMemorySpecifyCache(NtHeader->OptionalHeader.SizeOfImage, phyLow, phyHigh, phyLow, MmCached);
			if (image_pointer) break;
		} while (cout_max--);
		
		if (!image_pointer) return NULL;

		// ����PEͷ
		memcpy(image_pointer, file_pointer, NtHeader->OptionalHeader.SizeOfHeaders);
		// ������
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
		//�����ں˵�ַ��Ϊһ��PE�ļ�ͷ���������£�Ŀ����Ѱ���ض�λ��ṹ
		pImageDosHeader = (PIMAGE_DOS_HEADER)pNewImage;
		//��λ��IMAGE_NT_HEADER
		pImageNtHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pNewImage + pImageDosHeader->e_lfanew);
		//��ȡ�ں��ļ���imagebase���Ա������ƫ���޸ġ�
		OriginalImageBase = pImageNtHeader->OptionalHeader.ImageBase;
		//��λ������Ŀ¼
		ImageDataDirectory = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		//��λ���ض�λ��ṹ
		pImageBaseRelocation = (PIMAGE_BASE_RELOCATION_S)(ImageDataDirectory.VirtualAddress + (ULONG_PTR)pNewImage);
		if (pImageBaseRelocation == NULL)
		{
			return;
		}
		while (pImageBaseRelocation->SizeOfBlock)
		{   //������Ҫ�޸ĵĵ�ַ�ĸ���
			uRelocTableSize = (pImageBaseRelocation->SizeOfBlock - 8) / 2;
			//ѭ������
			for (uIndex = 0; uIndex < uRelocTableSize; uIndex++)
			{//�жϸ�4λ�Ƿ����3
				Type = pImageBaseRelocation->TypeOffset[uIndex] >> 12;
				if (Type == IMAGE_REL_BASED_DIR64)
				{
					//�޸ĵ�ַ����Ե�ַ����һ�����ں˵�ַ��ʹ���Ϊһ��ʵ�ʵ�ַ
					uRelocAddress = (ULONG64 *)((ULONG64)(pImageBaseRelocation->TypeOffset[uIndex] & 0x0fff) + pImageBaseRelocation->VirtualAddress + (ULONG64)pNewImage);
					//�ټ����ں��׵�ַ��imagebase��ƫ��
					*uRelocAddress = *uRelocAddress + ((ULONG64)PeImage - OriginalImageBase);
				}
			}
			//������һ���ض�λ����޸�
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
			// ���1809
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
		// ��ȡ�ļ����
		NTSTATUS NtStatus = NtCreateFile(&hFile, FILE_READ_ACCESS, &obj, &IoStatck, NULL,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
		if (!NT_SUCCESS(NtStatus)) 
			return FALSE;
		// ��ȡ�ļ�����
		PFILE_OBJECT FileObject = NULL;
		NtStatus = ObReferenceObjectByHandle(hFile, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
		if (!NT_SUCCESS(NtStatus)) {
			ZwClose(hFile);
			return FALSE;
		}
		ZwClose(hFile);
		// ��������ļ�ǿ��ɾ���ķ�ʽ
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
			// ���� RtlInsertInvertedFunctionTable ע���쳣����(Ps: Win10 ������PG)
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

