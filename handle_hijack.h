#include <Windows.h> 
#include <iostream>
#include <TlHelp32.h>
#include <string>

// macros we use. Some can be found in wintrnl.h
#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7
#define SystemHandleInformation 16 

/*
STRUCTURES NEEDED FOR NTOPENPROCESS:
*/
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

/*
STRUCTURES NEEDED FOR HANDLE INFORMATION:
*/

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE; //i shortened it to SYSTEM_HANDLE for the sake of typing

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

/*
FUNCTION PROTOTYPES:
*/
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(
	ULONG Privilege,
	BOOLEAN Enable,
	BOOLEAN CurrentThread,
	PBOOLEAN Enabled
	);

typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass, //your supposed to supply the whole class but microsoft kept the enum mostly empty so I just passed 16 instead for handle info. Thats why you get a warning in your code btw
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

inline SYSTEM_HANDLE_INFORMATION* hInfo; //holds the handle information

//the handles we will need to use later on

namespace hj
{
    inline HANDLE procHandle = NULL;
    inline HANDLE hProcess = NULL;
    inline HANDLE HijackedHandle = NULL;

    inline OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security)
    {
        OBJECT_ATTRIBUTES object;
        object.Length = sizeof(OBJECT_ATTRIBUTES);
        object.ObjectName = name;
        object.Attributes = attributes;
        object.RootDirectory = hRoot;
        object.SecurityDescriptor = security;
        return object;
    }

    inline bool IsHandleValid(HANDLE handle)
    {
        return (handle && handle != INVALID_HANDLE_VALUE);
    }

    inline HANDLE HijackExistingHandle(DWORD dwTargetProcessId)
    {
        std::cerr << "HijackExistingHandle called with Process ID: " << dwTargetProcessId << std::endl;

        HMODULE Ntdll = GetModuleHandleA("ntdll");
        if (!Ntdll) {
            std::cerr << "Failed to get ntdll module handle." << std::endl;
            return nullptr;
        }

        _RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(Ntdll, "RtlAdjustPrivilege");
        if (!RtlAdjustPrivilege) {
            std::cerr << "Failed to get address of RtlAdjustPrivilege." << std::endl;
            return nullptr;
        }

        BOOLEAN OldPriv;
        RtlAdjustPrivilege(SeDebugPriv, TRUE, FALSE, &OldPriv);

        _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(Ntdll, "NtQuerySystemInformation");
        if (!NtQuerySystemInformation) {
            std::cerr << "Failed to get address of NtQuerySystemInformation." << std::endl;
            return nullptr;
        }

        _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(Ntdll, "NtDuplicateObject");
        _NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(Ntdll, "NtOpenProcess");

        OBJECT_ATTRIBUTES Obj_Attribute = InitObjectAttributes(NULL, NULL, NULL, NULL);
        CLIENT_ID clientID = { 0 };

        DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
        SYSTEM_HANDLE_INFORMATION* hInfo = (SYSTEM_HANDLE_INFORMATION*) new byte[size];
        ZeroMemory(hInfo, size);

        NTSTATUS NtRet = NULL;
        do
        {
            delete[] hInfo;
            size *= 1.5;
            try
            {
                hInfo = (PSYSTEM_HANDLE_INFORMATION) new byte[size];
            }
            catch (std::bad_alloc)
            {
                procHandle ? CloseHandle(procHandle) : 0;
                std::cerr << "Memory allocation failed." << std::endl;
                return nullptr;
            }
            Sleep(1);

        } while ((NtRet = NtQuerySystemInformation(SystemHandleInformation, hInfo, size, NULL)) == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(NtRet)) {
            std::cerr << "NtQuerySystemInformation failed with status: " << NtRet << std::endl;
            procHandle ? CloseHandle(procHandle) : 0;
            return nullptr;
        }

        for (unsigned int i = 0; i < hInfo->HandleCount; ++i)
        {
            std::cerr << "Processing handle #" << i << std::endl;

            DWORD NumOfOpenHandles;
            GetProcessHandleCount(GetCurrentProcess(), &NumOfOpenHandles);
            std::cerr << "Current open handles: " << NumOfOpenHandles << std::endl;

            // Increase the limit to see if this resolves the issue
            if (NumOfOpenHandles > 1000) {
                std::cerr << "Too many open handles, exiting." << std::endl;
                procHandle ? CloseHandle(procHandle) : 0;
                break;
            }

            if (!IsHandleValid((HANDLE)hInfo->Handles[i].Handle))
                continue;

            if (hInfo->Handles[i].ObjectTypeNumber != ProcessHandleType)
                continue;

            clientID.UniqueProcess = (DWORD*)hInfo->Handles[i].ProcessId;

            if (procHandle)
                CloseHandle(procHandle);

            NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE, &Obj_Attribute, &clientID);
            if (!IsHandleValid(procHandle) || !NT_SUCCESS(NtRet)) {
                std::cerr << "NtOpenProcess failed with status: " << NtRet << std::endl;
                continue;
            }

            NtRet = NtDuplicateObject(procHandle, (HANDLE)hInfo->Handles[i].Handle, NtCurrentProcess, &HijackedHandle, PROCESS_ALL_ACCESS, 0, 0);
            if (!IsHandleValid(HijackedHandle) || !NT_SUCCESS(NtRet)) {
                std::cerr << "NtDuplicateObject failed with status: " << NtRet << std::endl;
                continue;
            }

            if (GetProcessId(HijackedHandle) != dwTargetProcessId) {
                std::cerr << "Process ID mismatch, expected: " << dwTargetProcessId << ", got: " << GetProcessId(HijackedHandle) << std::endl;
                CloseHandle(HijackedHandle);
                continue;
            }

            hProcess = HijackedHandle;
            break;
        }

        procHandle ? CloseHandle(procHandle) : 0;

        if (!hProcess) {
            std::cerr << "Failed Handle Hijacking." << std::endl;
        }
        else {
            std::cerr << "Handle Hijacking successful" << std::endl;
        }

        delete[] hInfo; // Free the allocated memory

        return hProcess;
    }
}
