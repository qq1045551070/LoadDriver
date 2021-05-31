#pragma once
#ifndef _LOAD_DRIVER_
#define _LOAD_DRIVER_

#include <ntifs.h>

extern "C"
{
	namespace LoadDriver
	{
		// 初始化函数
		PDRIVER_INITIALIZE LoadDriverInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING pReg);

		// 拉伸PE
		UCHAR* UnFoldPE(UCHAR* PeFile);
		// 修复重定位
		void FixBaseRelocTable(PVOID pNewImage);
		// Clear Current Driver MmUnloadedDrivers Table Information
		NTSTATUS clearUnloadTableEntry(PDRIVER_OBJECT driver, wchar_t* driverName);
		// Clear Current Driver PiDDBCache Table Information (注意目前只解决了Win7\Win10 1809硬编码)
		NTSTATUS clearPiDDBCacheTableEntry(PUNICODE_STRING	DriverName);
		// 修复IAT
		bool UpdateIat();
		// 修复版本差异
		// 找到入口点
		// 注册异常处理函数(让我们可以使用__try_except)
		bool RegistryException(PVOID ImageBase, ULONG ImageSize);
		// 文件自删除
		bool DeleteFile(PUNICODE_STRING Path);
		// 注册表痕迹删除
		bool DeleteRegistry(PUNICODE_STRING pReg);
		// 防止二次加载(设置同步对象)
		
	}
}
#endif

