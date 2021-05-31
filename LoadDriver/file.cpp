#include "file.h"
#include <ntimage.h>

#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(unsigned __int64 *)(name)
#define DEREF_32( name )*(unsigned long *)(name)
#define DEREF_16( name )*(unsigned short *)(name)
#define DEREF_8( name )*(UCHAR *)(name)

extern "C"
{
	_Use_decl_annotations_
		bool File::LockFile(IN wchar_t* FilePath)
	{
		HANDLE hFile = NULL;
		OBJECT_ATTRIBUTES obj = { 0 };
		UNICODE_STRING uFileName = { 0 };
		RtlInitUnicodeString(&uFileName, FilePath);
		IO_STATUS_BLOCK ioStatck = { 0 };
		InitializeObjectAttributes(&obj, &uFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		NTSTATUS NtStatus =
			NtCreateFile(&hFile, FILE_READ_ACCESS, &obj, &ioStatck, NULL,
				FILE_ATTRIBUTE_NORMAL, NULL/*独占方式打开*/, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);

		if (!NT_SUCCESS(NtStatus)){
			KdPrintEx((77, 0, "NtCreateFile失败:%x \n", NtStatus));
			return false;
		}
		else
			return true;
	}

	/*
		from google
	*/
	ULONG_PTR File::GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module)
	{
		UINT_PTR uiLibraryAddress = 0;
		ULONG_PTR fpResult = NULL;
		if (hModule == NULL)
			return NULL;
		// a module handle is really its base address
		uiLibraryAddress = (UINT_PTR)hModule;
		__try
		{
			UINT_PTR uiAddressArray = 0;
			UINT_PTR uiNameArray = 0;
			UINT_PTR uiNameOrdinals = 0;
			PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
			PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;
			PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
			PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

			// get the VA of the modules NT Header
			pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
			pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
			if (x64Module)
			{
				pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			}
			else
			{
				pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			}


			// get the VA of the export directory
			pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

			// get the VA for the array of addresses
			uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

			// get the VA for the array of name pointers
			uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

			// get the VA for the array of name ordinals
			uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

			// test if we are importing by name or by ordinal...
			if ((PtrToUlong(lpProcName) & 0xFFFF0000) == 0x00000000)
			{
				// import by ordinal...

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ((IMAGE_ORDINAL(PtrToUlong(lpProcName)) - pExportDirectory->Base) * sizeof(unsigned long));

				// resolve the address for this imported function
				fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				// import by name...
				unsigned long dwCounter = pExportDirectory->NumberOfNames;
				while (dwCounter--)
				{
					char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

					// test if we have a match...
					if (strcmp(cpExportedFunctionName, lpProcName) == 0)
					{
						// use the functions name ordinal as an index into the array of name pointers
						uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(unsigned long));

						// calculate the virtual address for the function
						fpResult = (ULONG_PTR)(uiLibraryAddress + DEREF_32(uiAddressArray));

						// finish...
						break;
					}

					// get the next exported function name
					uiNameArray += sizeof(unsigned long);

					// get the next exported function name ordinal
					uiNameOrdinals += sizeof(unsigned short);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			fpResult = NULL;
		}
		return fpResult;
	}
}


