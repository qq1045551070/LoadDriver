#pragma once
#ifndef _PML4_
#define _PML4_

#include <ntifs.h>

// 定义操作系统版本
#define WINXP 51
#define WIN7  61
#define WIN8  62
#define WIN10 100

extern "C"
{
	namespace Pml4
	{
		// 初始化函数
		VOID Pml4Init();
		// 获取PML4E
		PULONG64 GetPxeAddress(IN PVOID addr);
		// 获取PDPTE
		PULONG64 GetPpeAddress(IN PVOID addr);
		// 获取PDE
		PULONG64 GetPdeAddress(IN PVOID addr);
		// 获取PTE
		PULONG64 GetPteAddress(IN PVOID addr);
		// 获取系统版本
		ULONG GetWindowsVersion();
		// 获取内核信息
		bool GetNtInformation(OUT ULONG64* pkernel_base, OUT ULONG* pkernel_size);
		// 获取内核信息Ex
		bool GetNtInformationEx();
	}
}

#endif

