#pragma once
#ifndef _HIDE_
#define _HIDE_

#include <ntifs.h>

extern "C"
{
	namespace Hide
	{
		// ����������ʼ��
		VOID Init(PDRIVER_OBJECT HideDriverObject);
	}
}

#endif

