#pragma once
#ifndef _HIDE_
#define _HIDE_

#include <ntifs.h>

extern "C"
{
	namespace Hide
	{
		// Òþ²ØÇý¶¯³õÊ¼»¯
		VOID Init(PDRIVER_OBJECT HideDriverObject);
	}
}

#endif

