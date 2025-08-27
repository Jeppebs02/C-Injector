#pragma once
// ntdll_ext.h
#include <windows.h>
#include <winternl.h>

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


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
