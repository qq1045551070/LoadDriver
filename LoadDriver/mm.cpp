#include "mm.h"
#include "kernel.h"
#include "pml4.h"
#include <ntimage.h>

extern "C"
{
	/*
		from  windows explorer
	*/
	_Use_decl_annotations_
		bool Mm::_memcpy(IN PVOID address, IN PVOID target_address, IN ULONG length)
	{
		bool result = false;
		PHYSICAL_ADDRESS physicial_address;
		physicial_address = MmGetPhysicalAddress(address);
		if (physicial_address.QuadPart)
		{
			PVOID maped_mem = MmMapIoSpace(physicial_address, length, MmNonCached);
			if (maped_mem)
			{
				memcpy(maped_mem, target_address, length);
				MmUnmapIoSpace(maped_mem, length);
				result = true;
			}
		}
		return result;
	}

	_Use_decl_annotations_
		uintptr_t Mm::get_free_speace(IN uintptr_t base, IN size_t size, IN size_t need_size)
	{
		size_t return_length;
		NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
		bool is_good = true;
		uintptr_t count = 0;
		UCHAR* check_ptr = NULL;
		PULONG64 ppte		    = NULL;
		ULONG64  pte		    = NULL;
		PULONG64 ppde			= NULL;
		ULONG64  pde		    = NULL;
		//CHAR TestRead[4] = { 0 };
		
		// ����PEģ����ҿɲ���shellcode���ڴ�
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)base;
		PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(base + DosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		{
			// ����Ϥ����Ϊ��ִ�С��ɶ�
			if (SectionHeader->Characteristics & 60000000)
				continue;

			for (UCHAR* address = (UCHAR*)base + SectionHeader->VirtualAddress + SectionHeader->SizeOfRawData;
				(uintptr_t)address >= (uintptr_t)base + SectionHeader->VirtualAddress;
				address -= sizeof(uintptr_t))
			{
				// �ж�Ŀ���ַ�Ƿ�ɶ�
				//NtStatus = MmReadVirtualMemory(IoGetCurrentProcess(), TestRead,(PVOID)address, 0x4); //��ֹ����ҳ����
				if (!MmIsAddressValid(address))
					continue;

				// ��Լ����
				if (*(ULONG64*)address != 0x0 && *(ULONG64*)address != 0x9090909090909090) {
					continue;
				}

				is_good = true;
				count = 0;
				for (; count < need_size && is_good; count += sizeof(UCHAR))
				{
					check_ptr = (UCHAR*)((PUCHAR)address + count);
					if (*check_ptr != 0x0 && *check_ptr != 0x90)
					{
						is_good = false;
						break;
					}
				}

				if (is_good) {
					// ���˺��ж����Ƿ��ִ��
					ppte = (PULONG64)Pml4::GetPteAddress((PVOID)address);
					pte = *ppte; // ��ȡ pte
					ppde = (PULONG64)Pml4::GetPdeAddress((PVOID)address);
					pde = *ppde; // ��ȡ pde

					if (pte & 1) {
						if ((pte & 0x8000000000000000) != 0) {
							// ���ڲ���ִ��ҳ��ɾ������ִ�б�־(���ܻᵼ�²��ȶ�)
							pte &= (~0x8000000000000000);
							*ppte = pte;	
						}
						return (uintptr_t)address;
					}
					else if (pde & 0x80) {
						// ���Ϊ��ҳ
						if (pde & 1) {
							if ((pde & 0x8000000000000000) != 0)
							{
								pde &= (~0x8000000000000000);
								*ppde = pde;	
							}
							return (uintptr_t)address;
						}
					}
				}

				is_good = true;
			}
			SectionHeader++;
		}

		return NULL;
	}
	
	_Use_decl_annotations_
		NTSTATUS Mm::MmReadVirtualMemory(IN PEPROCESS Process, IN PVOID Source, IN PVOID Target, IN SIZE_T Size)
	{
		SIZE_T Result;
		return MmCopyVirtualMemory(Process, Source, PsGetCurrentProcess(), Target, Size, KernelMode, &Result);
	}

	_Use_decl_annotations_
		NTSTATUS Mm::MmWriteVirtualMemory(IN PEPROCESS Process, IN PVOID Source, IN PVOID Target, IN SIZE_T Size)
	{
		SIZE_T Result;
		return MmCopyVirtualMemory(PsGetCurrentProcess(), Source, Process, Target, Size, KernelMode, &Result);
	}

	_Use_decl_annotations_
		uintptr_t Mm::MmSearch(IN UCHAR* cShellCode1, IN UCHAR* cShellCode2, IN LONG offset, IN ULONG cCode1Size, IN ULONG cCode2Size)
	{
		ULONG64 uKernelBase;
		ULONG	uKernelSize;
		UCHAR*  uReadPointer;
		ULONG	uReadCout;
		bool isOk1, isOk2;
		uKernelBase = uKernelSize = uReadCout = 0;
		Pml4::GetNtInformation(&uKernelBase, &uKernelSize);
		uReadPointer = (UCHAR*)uKernelBase;
		isOk1 = isOk2 = false;

		for (ULONG x = 0; x < uKernelSize; x++) {
			isOk1 = isOk2 = false;
			uReadCout = 0;

			if (!MmIsAddressValid(&uReadPointer[x]) || !MmIsAddressValid(&uReadPointer[x + cCode1Size])) {
				continue;
			}

			for (ULONG y = 0; y < cCode1Size; y++) {
				if (cShellCode1[y] == '*' || cShellCode1[y] == '?') {
					uReadCout++;
					continue;
				}

				if (cShellCode1[y] == uReadPointer[x + y]) {
					uReadCout++;
				}

				if (uReadCout == cCode1Size) {
					isOk1 = true;
					break;
				}
			}

			if (!isOk1) continue;

			if (!MmIsAddressValid(&uReadPointer[x + offset]) || !MmIsAddressValid(&uReadPointer[x + offset + cCode2Size])) {
				continue;
			}

			uReadCout = 0;
			for (ULONG z = 0; z < cCode2Size; z++) {
				if (cShellCode2[z] == '*' || cShellCode2[z] == '?') {
					uReadCout++;
					continue;
				}

				if (cShellCode2[z] == uReadPointer[x + offset + z]) {
					uReadCout++;
				}

				if (uReadCout == cCode2Size) {
					isOk2 = true;
					break;
				}
			}

			if (isOk1 && isOk2) return (uintptr_t)&uReadPointer[x];
		}

		return NULL;
	}
}

