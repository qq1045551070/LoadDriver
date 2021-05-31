#include "main.h"
#include "Loaddriver.h"

extern "C"
{
	_Use_decl_annotations_
		NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
	{
		UNREFERENCED_PARAMETER(DriverObject);
		UNREFERENCED_PARAMETER(RegPath);
		DriverObject->DriverUnload = NULL;
		
		PDRIVER_INITIALIZE EntryPointer = LoadDriver::LoadDriverInit(DriverObject, RegPath);
		if (EntryPointer)
			NTSTATUS NtStatus = EntryPointer(NULL, NULL);
		else
			return STATUS_INVALID_PARAMETER;

		return STATUS_UNSUCCESSFUL;
	}

	_Use_decl_annotations_
		VOID DriverUnload(PDRIVER_OBJECT DriverObject)
	{
		
	}
}