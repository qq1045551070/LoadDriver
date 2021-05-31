#include "pml4.h"
#include "kernel.h"

extern "C"
{
	ULONG64 g_NT_BASE;
	ULONG64 g_NT_SIZE;
	ULONG64 g_PTE_BASE;
	ULONG64 g_PDE_BASE;
	ULONG64 g_PPE_BASE;
	ULONG64 g_PXE_BASE;

	_Use_decl_annotations_
		PULONG64 Pml4::GetPxeAddress(IN PVOID addr)
	{
		// 1个 PXE 对应 512 GB
		return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 39) << 3) + g_PXE_BASE);
	}
	
	_Use_decl_annotations_
		PULONG64 Pml4::GetPpeAddress(IN PVOID addr)
	{
		// 1个 PDPTE 对应 1 GB
		return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 30) << 3) + g_PPE_BASE);
	}
	
	_Use_decl_annotations_
		PULONG64 Pml4::GetPdeAddress(IN PVOID addr)
	{
		// 1个 PDE 对应 2 MB
		return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 21) << 3) + g_PDE_BASE);
	}
	
	_Use_decl_annotations_
		PULONG64 Pml4::GetPteAddress(IN PVOID addr)
	{
		// 1个 PTE 对应 4KB
		return (PULONG64)(((((ULONG64)addr & 0xFFFFFFFFFFFF) >> 12) << 3) + g_PTE_BASE);
	}

	_Use_decl_annotations_
		ULONG Pml4::GetWindowsVersion()
	{
		RTL_OSVERSIONINFOW lpVersionInformation = { sizeof(RTL_OSVERSIONINFOW) };
		if (NT_SUCCESS(RtlGetVersion(&lpVersionInformation)))
		{
			ULONG dwMajorVersion = lpVersionInformation.dwMajorVersion;
			ULONG dwMinorVersion = lpVersionInformation.dwMinorVersion;
			if (dwMajorVersion == 5 && dwMinorVersion == 1)
			{
				return WINXP;
			}
			else if (dwMajorVersion == 6 && dwMinorVersion == 1)
			{
				return WIN7;
			}
			else if (dwMajorVersion == 6 && dwMinorVersion == 2)
			{
				return WIN8;
			}
			else if (dwMajorVersion == 10 && dwMinorVersion == 0)
			{
				return WIN10;
			}
		}
		return -1;
	}

	_Use_decl_annotations_
		bool Pml4::GetNtInformation(OUT ULONG64* pkernel_base, OUT ULONG* pkernel_size)
	{
		if (pkernel_base && pkernel_size && g_NT_BASE && g_NT_SIZE) {
			*pkernel_base = g_NT_BASE;
			*pkernel_size = g_NT_SIZE;
			return true;
		}
		else
			return false;
	}

	_Use_decl_annotations_
		bool Pml4::GetNtInformationEx()
	{
		size_t dwIndex = 0;;
		ULONG dwNeedLen = 0;
		SYSTEM_MODULE_INFO_LIST* pSysModuleInfoList = NULL;
		PCHAR dwKernelBase = NULL;
		ULONG dwKernelBaseSize = 0;

		// 功能号为11，先获取所需的缓冲区大小
		ZwQuerySystemInformation(SystemModuleInformation, NULL, dwNeedLen, &dwNeedLen);
		// 申请内存
		pSysModuleInfoList = (SYSTEM_MODULE_INFO_LIST*)ExAllocatePoolWithTag(NonPagedPool, dwNeedLen, 'ioMm');
		// 再次调用
		ZwQuerySystemInformation(SystemModuleInformation, pSysModuleInfoList, dwNeedLen, &dwNeedLen);

		if (strstr(_strlwr(pSysModuleInfoList->smi[0].ImageName), "nt") != NULL)
		{
			// 获取内核模块基地址
			g_NT_BASE = (ULONG64)pSysModuleInfoList->smi[0].Base;
			g_NT_SIZE = pSysModuleInfoList->smi[0].Size;
		}

		ExFreePoolWithTag(pSysModuleInfoList, 'ioMm');

		return (g_NT_BASE && g_NT_SIZE) ? true : false;
	}

	_Use_decl_annotations_
		VOID Pml4::Pml4Init()
	{
		// 获取PML4信息
		if (GetWindowsVersion() == WIN7) // 判断系统版本
		{
			// Win7 的页目录随机基址是固定的
			g_PTE_BASE = 0xFFFFF68000000000;
			g_PDE_BASE = 0xFFFFF6FB40000000;
			g_PPE_BASE = 0xFFFFF6FB7DA00000;
			g_PXE_BASE = 0xFFFFF6FB7DBED000;
		}
		else if (GetWindowsVersion() == WIN10) {
			// Win10需要动态获取
			g_PTE_BASE = *(PULONG64)((ULONG64)MmGetVirtualForPhysical + 0x22);
			g_PDE_BASE = (g_PTE_BASE + ((g_PTE_BASE & 0xffffffffffff) >> 9));
			g_PPE_BASE = (g_PTE_BASE + ((g_PDE_BASE & 0xffffffffffff) >> 9));
			g_PXE_BASE = (g_PTE_BASE + ((g_PPE_BASE & 0xffffffffffff) >> 9));
		}
		// 获取内核信息
		if (!GetNtInformationEx())
			KdBreakPoint();
	}
}


