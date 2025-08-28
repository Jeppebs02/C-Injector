#pragma once
// ntdll_ext.h
#include <windows.h>
#include <winternl.h>

typedef _Return_type_success_(return >= 0) long NTSTATUS;


#ifndef _NTINTSAFE_H_INCLUDED_
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP | WINAPI_PARTITION_SYSTEM | WINAPI_PARTITION_GAMES)

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

#endif
#endif




typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;



typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID        ClientId);

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE                  SectionHandle,
    HANDLE                  ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR                ZeroBits,
    SIZE_T                   CommitSize,
    PLARGE_INTEGER           SectionOffset,
    PSIZE_T                  ViewSize,
    DWORD                    InheritDisposition,
    ULONG                    AllocationType,
    ULONG                    Win32Protect);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE                ThreadHandle,
    ACCESS_MASK            DesiredAccess,
    POBJECT_ATTRIBUTES     ObjectAttributes,
    HANDLE                 ProcessHandle,
    PVOID                  StartRoutine,
    PVOID                  Argument,
    ULONG                  CreateFlags,
    SIZE_T                 ZeroBits,
    SIZE_T                 StackSize,
    SIZE_T                 MaximumStackSize,
    PVOID                  AttributeList);
