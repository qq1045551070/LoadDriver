#pragma once
#ifndef _MM_
#define _MM_

#include <ntifs.h>

extern "C"
{
	namespace Mm
	{
		// 物理页 MmMapIoSpace 映射拷贝
		bool _memcpy(IN PVOID address, IN PVOID target_address, IN ULONG length);

		// 根据需要大小获取模块空白空间
		_IRQL_requires_max_(PASSIVE_LEVEL)
		uintptr_t get_free_speace(IN uintptr_t base, IN size_t size, IN size_t need_size);

		// MmCopyVirtualMemory 读取
		_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS MmReadVirtualMemory(IN PEPROCESS Process, IN PVOID Source, IN PVOID Target, IN SIZE_T Size);

		// MmCopyVirtualMemory 写入
		_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS MmWriteVirtualMemory(IN PEPROCESS Process, IN PVOID Source, IN PVOID Target, IN SIZE_T Size);

		// 内存搜索
		uintptr_t MmSearch(IN UCHAR* cShellCode1, IN UCHAR* cShellCode2, IN LONG offset, IN ULONG cCode1Size, IN ULONG cCode2Size);
	}
}

#endif

