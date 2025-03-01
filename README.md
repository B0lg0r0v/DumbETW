# DumbETW

Just a dumb project I messed around with to understand more about ETW and generally querying ETW providers while also parsing the events. This is more of a proof of concept than production ready code, but it could serve as a baseline I guess. 

## Modifications

If you want to test this out, you'll need to change at least ONE line in the source code:

```c
#define LOGFILE_PATH L"C:\\Users\\std\\Desktop\\DumbETW.etl" // <- Change this
```

You need to specify a valid path where to save the log file.

You could also change the provider as you whish:

```c
// Microsoft-Windows-Kernel-Process			  {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} 
// Microsoft-Windows-DotNETRuntime			  {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
// Microsoft-Windows-Security-Auditing    {54849625-5478-4994-A5BA-3E3B0328C30D}
// Microsoft-Antimalware-Scan-Interface	  {2A576B87-09A7-520E-C21A-4942F0271D67}

const GUID				g_ProviderGuid		= { 0x2A576B87, 0x09A7, 0x520E, { 0xC2, 0x1A, 0x49, 0x42, 0xF0, 0x27, 0x1D, 0x67 } };		// GUID of the provider we want to use, which is currently set to "Microsoft-Antimalware-Scan-Interfaces"
```

Keep in mind that I have not implemented consuming kernel level events. Too lazy for that tbh. 

## How to open an .etl file ?

Just use the EventViewer from Windows.

![image](https://github.com/user-attachments/assets/92ac836b-e51a-4c05-a40c-fe79e1f7116a)

## Credits - References 

- "Evading EDR" by Matt Hand
- This whole mess from Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/_etw/
- https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101
