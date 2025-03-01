#include <stdio.h>
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>

// For the linker
#pragma comment(lib, "tdh.lib")

#define LOGFILE_PATH L"C:\\Users\\std\\Desktop\\DumbETW.etl" // <- Change this

//------------------------------------------ Some definitions
typedef ULONG64 PROCESSTRACE_HANDLE;
DWORD WINAPI ConsumerThreadProc(PTRACEHANDLE lpParam);

//------------------------------------------//
		
// Microsoft-Windows-Kernel-Process			{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} 
// Microsoft-Windows-DotNETRuntime			{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
// Microsoft-Windows-Security-Auditing      {54849625-5478-4994-A5BA-3E3B0328C30D}
// Microsoft-Antimalware-Scan-Interface		{2A576B87-09A7-520E-C21A-4942F0271D67}

const GUID				g_ProviderGuid		= { 0x2A576B87, 0x09A7, 0x520E, { 0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67 } };		// GUID of the provider we want to use, which is currently set to "Microsoft-Antimalware-Scan-Interfaces"
const GUID				g_GUID				= { 0xbee742bd, 0xcb04, 0x4a3f, 0x937d, 0x0eb7539e575c };									// Custom GUID for our trace session. Generated via powershell "[guid]::NewGuid()"
WCHAR					g_LoggerName[]		= L"DumbETWTraceSession";																	// Name of the tracing session

// Callback invoked for each incoming event
// Taken and modified from the book "Evading EDR" by Matt Hand
static VOID WINAPI cEventRecordCallback(PEVENT_RECORD pEventRecord)
{

	ULONG				uBuffer						= 0,
						uStatus						= 0;

	BOOL				bFound						= FALSE;
	WCHAR				pszValue[512];
	USHORT				uPropertyLength				= 0,
						uUserDataLength				= pEventRecord->UserDataLength;
	ULONG				uPointerSize				= (pEventRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
	PBYTE				pUserData					= (PBYTE)pEventRecord->UserData;

	// This will fail. Standard trick to get the needed size first
	uStatus = TdhGetEventInformation(pEventRecord, NULL, NULL, NULL, &uBuffer);
	if (uStatus != ERROR_INSUFFICIENT_BUFFER)
		return;

	// Allocating memory for the event info struct
	PTRACE_EVENT_INFO pEventInfo = (PTRACE_EVENT_INFO)malloc(uBuffer);
	if (!pEventInfo)
		return;

	// Safety zeroing out
	RtlZeroMemory(pEventInfo, uBuffer);

	// Now that we get the buffer size, we can make the real call
	uStatus = TdhGetEventInformation(pEventRecord, NULL, NULL, pEventInfo, &uBuffer);
	if (uStatus != ERROR_SUCCESS)
	{
		free(pEventInfo);
		return;
	}

	// Now we need to iterate through the struct
	for (ULONG i = 0; i < pEventInfo->TopLevelPropertyCount; i++)
	{

		// Now we can check the EventPropertyInfoArray, which contains a EVENT_PROPERTY struct for each event
		EVENT_PROPERTY_INFO		epPropertyInfo				= pEventInfo->EventPropertyInfoArray[i];
		PCWSTR					pwsPropName					= (PCWSTR)((BYTE*)pEventInfo + epPropertyInfo.NameOffset);

		uPropertyLength = epPropertyInfo.length;

		// Here we check if the property flag is a struct or a parametercount. If the result is non zero, at least one bit is set so we return
		if ((epPropertyInfo.Flags & (PropertyStruct | PropertyParamCount)) != 0)
			return;

		PEVENT_MAP_INFO			pmMapInfo					= NULL;
		PWSTR					stMapName					= NULL;

		if (epPropertyInfo.nonStructType.MapNameOffset)
		{

			ULONG ulMapSize = 0;
			stMapName = (PWSTR)((BYTE*)pEventInfo + epPropertyInfo.nonStructType.MapNameOffset);

			uStatus = TdhGetEventMapInformation(pEventRecord, stMapName, pmMapInfo, &ulMapSize);
			if (uStatus == ERROR_INSUFFICIENT_BUFFER)
			{
				// We allocate and retry
				pmMapInfo = (PEVENT_MAP_INFO)malloc(ulMapSize);
				uStatus = TdhGetEventMapInformation(pEventRecord, stMapName, pmMapInfo, &ulMapSize);

				if (uStatus != ERROR_SUCCESS)
					pmMapInfo = NULL;

			}

		}

		ULONG	ulBufferSize = sizeof(pszValue);
		USHORT	wSizeConsumed = 0;

		uStatus = TdhFormatProperty(
			pEventInfo, 
			pmMapInfo, 
			uPointerSize, 
			epPropertyInfo.nonStructType.InType, 
			epPropertyInfo.nonStructType.OutType, 
			uPropertyLength, 
			uUserDataLength, 
			pUserData, 
			&ulBufferSize, 
			pszValue,
			&wSizeConsumed);

		
		if (uStatus == ERROR_SUCCESS)
		{
			wprintf(L"[i] Event Received:\tID = %u, PID = %u, TID = %u\n", pEventRecord->EventHeader.EventDescriptor.Id, pEventRecord->EventHeader.ProcessId, pEventRecord->EventHeader.ThreadId);
			wprintf(L"    Property:\t\t%s\n    Value: \t\t%s\n\n", pwsPropName, pszValue);
		}
			
		else
			wprintf(L"[%s] TdhFormatProperty failed: %lu\n", pwsPropName, uStatus);
		

		if (pmMapInfo)
		{
			free(pmMapInfo);
			pmMapInfo = NULL;
		}
			
	}

	// Cleanup
	if (pEventInfo)
		free(pEventInfo); 
	
}

DWORD WINAPI ConsumerThreadProc(PTRACEHANDLE lpParam)
{

	ULONG status = ProcessTrace(lpParam, 1, NULL, NULL);
	if (status != ERROR_SUCCESS)
		wprintf(L"[-] ProcessTrace failed: %lu\n", status);
	else
		wprintf(L"[i] ProcessTrace finished.\n");
	return 0;
}

int main() {


	SIZE_T					szCharCount		= wcslen(g_LoggerName) + 1; // +1 for the null terminator
	SIZE_T					szFileCount		= wcslen(LOGFILE_PATH) + 1;
	SIZE_T					szTotalChars	= szCharCount + szFileCount;
	SIZE_T					szTotalSize		= sizeof(EVENT_TRACE_PROPERTIES) + (szTotalChars * sizeof(WCHAR));
	DWORD					dwStatus		= 0;
	PROCESSTRACE_HANDLE		phTrace			= NULL;
	TRACEHANDLE				hSession		= NULL;
	HANDLE					hThread			= NULL;
	
	// Allocating enough size
	EVENT_TRACE_PROPERTIES* etHeaderStruct	= (EVENT_TRACE_PROPERTIES*)malloc(szTotalSize);
	if (etHeaderStruct == NULL)
		return -1;

	// Zeroing out
	RtlZeroMemory(etHeaderStruct, szTotalSize);

	printf("[i] Pointer to the allocated ETW struct: 0x%p\n", etHeaderStruct);

	// Filling out the struct
	etHeaderStruct->Wnode.BufferSize		= (ULONG)szTotalSize;
	etHeaderStruct->Wnode.Guid				= g_GUID;
	etHeaderStruct->Wnode.Flags				= WNODE_FLAG_TRACED_GUID;
	etHeaderStruct->Wnode.ClientContext		= 1;																// Set to QPC clock resolution
	etHeaderStruct->LogFileMode				= EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_REAL_TIME_MODE;
	etHeaderStruct->MinimumBuffers			= 0;																// Minimum buffer size for memory usage
	etHeaderStruct->MaximumBuffers			= 0;																// "If this value is less than the adjusted value of MinimumBuffers, ETW may increase it to a suitable value equal to or larger than MinimumBuffers.". Ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	etHeaderStruct->LoggerNameOffset		= sizeof(EVENT_TRACE_PROPERTIES);
	etHeaderStruct->LogFileNameOffset		= (ULONG)(etHeaderStruct->LoggerNameOffset + (szCharCount * sizeof(WCHAR)));
	
	// Copying each string to its correct spot
	wcscpy_s((PWCHAR)((PBYTE)etHeaderStruct + etHeaderStruct->LoggerNameOffset), szCharCount, g_LoggerName);
	wcscpy_s((PWCHAR)((PBYTE)etHeaderStruct + etHeaderStruct->LogFileNameOffset), szFileCount, LOGFILE_PATH);

	printf("[i] Preparing provider ..\n");

	// Starting the Trace
	dwStatus = StartTraceW(&phTrace, g_LoggerName, etHeaderStruct);

	if (dwStatus == ERROR_ALREADY_EXISTS)
	{

		printf("[-] Trace Session already exists !\n");
		ControlTraceW(phTrace, g_LoggerName, etHeaderStruct, EVENT_TRACE_CONTROL_STOP); // Stopping the session

	}

	// If the function succeeds
	if (dwStatus != ERROR_SUCCESS)
		return dwStatus;

	else
	{

		// Now we need to "subscribe" to a provider
		printf("[i] Enabling provider..\n");
		dwStatus = EnableTraceEx2(

			phTrace,
			&g_ProviderGuid,						// Provider GUID
			EVENT_CONTROL_CODE_ENABLE_PROVIDER,		// Enabling the provider
			TRACE_LEVEL_INFORMATION,				// Logging Level
			0xFFFFFFFFFFFFFFFFULL,
			NULL,
			NULL,
			NULL

		);

		if (dwStatus != ERROR_SUCCESS)
			goto _CLEANUP;

		// Startin the tracing session for real
		EVENT_TRACE_LOGFILEW etLogFile	= { 0 };

		etLogFile.LoggerName			= g_LoggerName;
		etLogFile.ProcessTraceMode		= PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
		etLogFile.EventRecordCallback	= cEventRecordCallback;


		printf("[i] Starting the trace session: %ws\n", etLogFile.LoggerName);
		
		hSession = OpenTrace(&etLogFile);
		if (hSession == INVALID_PROCESSTRACE_HANDLE)		
			goto _CLEANUP;
		
		printf("[+] Session has started..\n");
		printf("[i] Press a Ctrl + C to stop the tracing...\n");
		Sleep(5000);

		hThread = CreateThread(NULL, 0, ConsumerThreadProc, &hSession, 0, NULL);
		if (!hThread)
			goto _CLEANUP;
		
		getchar(); // very lazy way to simulate a loop lol

	}

_CLEANUP:
	if (phTrace)
		ControlTraceW(phTrace, g_LoggerName, etHeaderStruct, EVENT_TRACE_CONTROL_STOP);	

	if (hSession)
		CloseTrace(hSession);

	if (hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}

	if (hSession && hSession != INVALID_PROCESSTRACE_HANDLE)
		CloseTrace(hSession);

	free(etHeaderStruct);
	return 0;

}