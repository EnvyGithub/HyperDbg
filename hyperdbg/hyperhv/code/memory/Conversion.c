/**
 * @file Conversion.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Functions for memory conversions
 *
 * @version 0.2
 * @date 2023-04-27
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

//
// [DOWNSTREAM] 在 VMX non-root 切换 CR3 期间禁止抢占。Windows 只在下一个线程属于另一个
// 进程时重载 CR3；线程在两次 CpuWriteCr3 之间被抢占时，外来 CR3 留在该处理器上，本进程
// 下一个在此运行的线程会以外来页表返回用户态（#39）。提升到 DISPATCH_LEVEL 后线程不会被
// 切走，中断处理只访问内核地址。VMX root 已关中断，不改 IRQL。
//
static BOOLEAN
ConversionHoldForeignLayout(KIRQL * OldIrql)
{
#ifdef HYPERDBG_ENV_WINDOWS
    if (VmxGetCurrentExecutionMode() == VmxExecutionModeRoot || KeGetCurrentIrql() >= DISPATCH_LEVEL)
    {
        return FALSE;
    }
    *OldIrql = PlatformIrqlRaiseToDpcLevel();
    return TRUE;
#else
    UNREFERENCED_PARAMETER(OldIrql);
    return FALSE;
#endif
}

static VOID
ConversionReleaseForeignLayout(BOOLEAN Held, KIRQL OldIrql)
{
    if (Held)
    {
        PlatformIrqlLower(OldIrql);
    }
}

/**
 * @brief Converts Physical Address to Virtual Address
 *
 * @param PhysicalAddress The target physical address
 * @return UINT64 Returns the virtual address
 */
_Use_decl_annotations_
UINT64
PhysicalAddressToVirtualAddress(UINT64 PhysicalAddress)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = PhysicalAddress;

    return (UINT64)PlatformMemGetVirtualForPhysical(PhysicalAddr);
}

/**
 * @brief Converts Physical Address to Virtual Address based
 * on a specific process id
 *
 * @details this function should NOT be called from vmx-root mode
 *
 * @param PhysicalAddress The target physical address
 * @param ProcessId The target's process id
 * @return UINT64 Returns the virtual address
 */
_Use_decl_annotations_
UINT64
PhysicalAddressToVirtualAddressByProcessId(PVOID PhysicalAddress, UINT32 ProcessId)
{
    PEPROCESS TargetEprocess;
    CR3_TYPE  TargetCr3;
    UINT64    VirtualAddress;

    //
    // [DOWNSTREAM] Look the process up before the IRQL is raised, and keep the
    // reference until its directory table base is no longer loaded.
    //
    if (PlatformProcessLookupByProcessId((HANDLE)ProcessId, &TargetEprocess) != STATUS_SUCCESS)
    {
        //
        // Pid is invalid
        //
        return NULL64_ZERO;
    }

    TargetCr3.Flags = ((NT_KPROCESS *)TargetEprocess)->DirectoryTableBase;
    VirtualAddress  = PhysicalAddressToVirtualAddressByCr3(PhysicalAddress, TargetCr3);

    PlatformObjectDereference(TargetEprocess);

    return VirtualAddress;
}

/**
 * @brief Converts Physical Address to Virtual Address based
 * on a specific process's kernel cr3
 *
 * @details this function should NOT be called from vmx-root mode
 *
 * @param PhysicalAddress The target physical address
 * @param TargetCr3 The target's process cr3
 * @return UINT64 Returns the virtual address
 */
_Use_decl_annotations_
UINT64
PhysicalAddressToVirtualAddressByCr3(PVOID PhysicalAddress, CR3_TYPE TargetCr3)
{
    CR3_TYPE         CurrentProcessCr3;
    UINT64           VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddr;
    KIRQL            OldIrql = 0;
    BOOLEAN          Held;

    Held = ConversionHoldForeignLayout(&OldIrql);

    //
    // Switch to new process's memory layout
    //
    CurrentProcessCr3 = SwitchToProcessMemoryLayoutByCr3(TargetCr3);

    //
    // Validate if process id is valid
    //
    if (CurrentProcessCr3.Flags == NULL64_ZERO)
    {
        //
        // Pid is invalid
        //
        ConversionReleaseForeignLayout(Held, OldIrql);
        return NULL64_ZERO;
    }

    //
    // Read the virtual address based on new cr3
    //
    PhysicalAddr.QuadPart = (LONGLONG)PhysicalAddress;
    VirtualAddress        = (UINT64)PlatformMemGetVirtualForPhysical(PhysicalAddr);

    //
    // Restore the original process
    //
    SwitchToPreviousProcess(CurrentProcessCr3);
    ConversionReleaseForeignLayout(Held, OldIrql);

    return VirtualAddress;
}

/**
 * @brief Converts Physical Address to Virtual Address based
 * on current process's kernel cr3
 *
 * @details this function should NOT be called from vmx-root mode
 *
 * @param PhysicalAddress The target physical address
 * @return UINT64 Returns the virtual address
 */
_Use_decl_annotations_
UINT64
PhysicalAddressToVirtualAddressOnTargetProcess(PVOID PhysicalAddress)
{
    CR3_TYPE GuestCr3;

    GuestCr3.Flags = LayoutGetCurrentProcessCr3().Flags;

    return PhysicalAddressToVirtualAddressByCr3(PhysicalAddress, GuestCr3);
}

/**
 * @brief Converts Virtual Address to Physical Address
 *
 * @param VirtualAddress The target virtual address
 * @return UINT64 Returns the physical address
 */
_Use_decl_annotations_
UINT64
VirtualAddressToPhysicalAddress(_In_ PVOID VirtualAddress)
{
    return PlatformMemGetPhysicalAddress(VirtualAddress).QuadPart;
}

/**
 * @brief Converts Virtual Address to Physical Address based
 * on a specific process id's kernel cr3
 *
 * @details this function should NOT be called from vmx-root mode
 *
 * @param VirtualAddress The target virtual address
 * @param ProcessId The target's process id
 * @return UINT64 Returns the physical address
 */
_Use_decl_annotations_
UINT64
VirtualAddressToPhysicalAddressByProcessId(PVOID VirtualAddress, UINT32 ProcessId)
{
    PEPROCESS TargetEprocess;
    CR3_TYPE  TargetCr3;
    UINT64    PhysicalAddress;

    //
    // [DOWNSTREAM] Look the process up before the IRQL is raised, and keep the
    // reference until its directory table base is no longer loaded.
    //
    if (PlatformProcessLookupByProcessId((HANDLE)ProcessId, &TargetEprocess) != STATUS_SUCCESS)
    {
        //
        // Pid is invalid
        //
        return NULL64_ZERO;
    }

    TargetCr3.Flags = ((NT_KPROCESS *)TargetEprocess)->DirectoryTableBase;
    PhysicalAddress = VirtualAddressToPhysicalAddressByProcessCr3(VirtualAddress, TargetCr3);

    PlatformObjectDereference(TargetEprocess);

    return PhysicalAddress;
}

/**
 * @brief Converts Virtual Address to Physical Address based
 * on a specific process's kernel cr3
 *
 * @param VirtualAddress The target virtual address
 * @param TargetCr3 The target's process cr3
 * @return UINT64 Returns the physical address
 */
_Use_decl_annotations_
UINT64
VirtualAddressToPhysicalAddressByProcessCr3(PVOID VirtualAddress, CR3_TYPE TargetCr3)
{
    CR3_TYPE CurrentProcessCr3;
    UINT64   PhysicalAddress;
    KIRQL    OldIrql = 0;
    BOOLEAN  Held;

    Held = ConversionHoldForeignLayout(&OldIrql);

    //
    // Switch to new process's memory layout
    //
    CurrentProcessCr3 = SwitchToProcessMemoryLayoutByCr3(TargetCr3);

    //
    // Validate if process id is valid
    //
    if (CurrentProcessCr3.Flags == NULL64_ZERO)
    {
        //
        // Pid is invalid
        //
        ConversionReleaseForeignLayout(Held, OldIrql);
        return NULL64_ZERO;
    }

    //
    // Read the physical address based on new cr3
    //
    PhysicalAddress = PlatformMemGetPhysicalAddress(VirtualAddress).QuadPart;

    //
    // Restore the original process
    //
    SwitchToPreviousProcess(CurrentProcessCr3);
    ConversionReleaseForeignLayout(Held, OldIrql);

    return PhysicalAddress;
}

/**
 * @brief Converts Virtual Address to Physical Address based
 * on the current process's kernel cr3
 *
 * @param VirtualAddress The target virtual address
 * @return UINT64 Returns the physical address
 */
_Use_decl_annotations_
UINT64
VirtualAddressToPhysicalAddressOnTargetProcess(PVOID VirtualAddress)
{
    CR3_TYPE GuestCr3;

    GuestCr3.Flags = LayoutGetCurrentProcessCr3().Flags;

    return VirtualAddressToPhysicalAddressByProcessCr3(VirtualAddress, GuestCr3);
}
