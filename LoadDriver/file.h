#pragma once
#ifndef _FILE_
#define _FILE_

#include <ntifs.h>

extern "C"
{
	namespace File
	{
		// ��ס�ļ�����ֹ�ļ�У��
		_IRQL_requires_max_(PASSIVE_LEVEL)
		bool LockFile(IN wchar_t* FilePath);

		// ��ȡָ��ģ��ĺ���
		_IRQL_requires_max_(PASSIVE_LEVEL)
		ULONG_PTR GetProcAddressR(ULONG_PTR hModule, const char* lpProcName, BOOLEAN x64Module);
	}
}

#endif // !_FILE_


