#pragma once
#ifndef _PML4_
#define _PML4_

#include <ntifs.h>

// �������ϵͳ�汾
#define WINXP 51
#define WIN7  61
#define WIN8  62
#define WIN10 100

extern "C"
{
	namespace Pml4
	{
		// ��ʼ������
		VOID Pml4Init();
		// ��ȡPML4E
		PULONG64 GetPxeAddress(IN PVOID addr);
		// ��ȡPDPTE
		PULONG64 GetPpeAddress(IN PVOID addr);
		// ��ȡPDE
		PULONG64 GetPdeAddress(IN PVOID addr);
		// ��ȡPTE
		PULONG64 GetPteAddress(IN PVOID addr);
		// ��ȡϵͳ�汾
		ULONG GetWindowsVersion();
		// ��ȡ�ں���Ϣ
		bool GetNtInformation(OUT ULONG64* pkernel_base, OUT ULONG* pkernel_size);
		// ��ȡ�ں���ϢEx
		bool GetNtInformationEx();
	}
}

#endif

