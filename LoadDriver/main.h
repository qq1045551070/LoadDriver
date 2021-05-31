#pragma once
#ifndef _MAIN_
#define _MAIN_

#include <ntifs.h>

extern "C"
{
	_IRQL_requires_max_(PASSIVE_LEVEL)
		NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);

	_IRQL_requires_max_(PASSIVE_LEVEL)
		VOID DriverUnload(PDRIVER_OBJECT DriverObject);
}

#endif

