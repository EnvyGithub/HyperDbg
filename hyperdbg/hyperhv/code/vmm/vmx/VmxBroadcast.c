/**
 * @file VmxBroadcast.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Broadcast mechanism in vmx-root
 * @details
 * @version 0.1
 * @date 2021-12-31
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

static VOID VmxBroadcastCaptureApic(PKDPC Dpc,PVOID Context,PVOID A,PVOID B)
{
    UNREFERENCED_PARAMETER(Dpc);UNREFERENCED_PARAMETER(Context);
    g_GuestState[PlatformCpuGetCurrentProcessorNumber()].NmiApicId=ApicReadLocalId();
    PlatformBroadcastSynchronizeEndOfRoutine(A,B);
}
VOID VmxBroadcastKickCpu(VIRTUAL_MACHINE_STATE *Cpu)
{
    if(CpuInterlockedCompareExchange(&Cpu->NmiIpiPending,1,0)==0)ApicTriggerDirectedNmi(Cpu->NmiApicId);
}


/**
 * @brief Initialize the VMX Broadcast mechanism
 *
 * @return VOID
 */
VOID
VmxBroadcastInitialize()
{
    if(g_NmiBroadcastingInitialized)return;
    //
    // *** Initialize NMI broadcasting mechanism ***
    //

    //
    // Initialize APIC
    //
    if(!ApicInitialize())return;
    PlatformDpcGenericCall(VmxBroadcastCaptureApic,NULL);

#if USE_DEFAULT_OS_IDT_AS_HOST_IDT == TRUE

    //
    // Register NMI handler for vmx-root
    //
    g_NmiHandlerForKeDeregisterNmiCallback = KeRegisterNmiCallback(&VmxBroadcastHandleNmiCallback, NULL);

#endif //  USE_DEFAULT_OS_IDT_AS_HOST_IDT == TRUE

    //
    // Broadcast on all core to cause exit for NMIs
    //
    BroadcastEnableNmiExitingAllCores();

    //
    // Indicate that NMI broadcasting is initialized
    //
    g_NmiBroadcastingInitialized = TRUE;
}

/**
 * @brief Uninitialize the VMX Broadcast mechanism
 *
 * @return VOID
 */
VOID
VmxBroadcastUninitialize()
{
    if(!g_NmiBroadcastingInitialized)return;
    // 控制面已停止新 coherence 事务。未消费的 IPI 不能留到 VMXOFF 或释放 GuestState 之后。
    BOOLEAN Pending=FALSE;
    for(UINT32 Attempt=0;Attempt<65536;Attempt++)
    {
        Pending=FALSE;
        for(UINT32 i=0;i<PlatformCpuGetActiveProcessorCount();i++)
            if(CpuInterlockedCompareExchange(&g_GuestState[i].NmiIpiPending,0,0)!=0){Pending=TRUE;break;}
        if(!Pending)break;
        YieldProcessor();
    }
    if(Pending)return;

    //
    // *** Uninitialize NMI broadcasting mechanism ***
    //
    g_NmiBroadcastingInitialized = FALSE;

#if USE_DEFAULT_OS_IDT_AS_HOST_IDT == TRUE

    //
    // De-register NMI handler
    //
    KeDeregisterNmiCallback(g_NmiHandlerForKeDeregisterNmiCallback);

#endif //  USE_DEFAULT_OS_IDT_AS_HOST_IDT == TRUE

    //
    // Broadcast on all core to cause not to exit for NMIs
    //
    BroadcastDisableNmiExitingAllCores();

    //
    // Uinitialize APIC related function
    //
    ApicUninitialize();
}

/**
 * @brief Handles NMIs in kernel-mode
 *
 * @param Context
 * @param Handled
 * @return BOOLEAN
 */
BOOLEAN
VmxBroadcastHandleNmiCallback(PVOID Context, BOOLEAN Handled)
{
    UNREFERENCED_PARAMETER(Context);

    ULONG CurrentCore;
    CurrentCore                  = PlatformCpuGetCurrentProcessorNumber();
    VIRTUAL_MACHINE_STATE * VCpu = &g_GuestState[CurrentCore];

    //
    // This mechanism tries to solve the problem of receiving NMIs
    // when we're already in vmx-root mode, e.g., when we want to
    // inject NMIs to other cores and those cores are already operating
    // in vmx-root mode; however, this is not the approach to solve the
    // problem. In order to solve this problem, we should create our own
    // host IDT in vmx-root mode (Note that we should set VMCS_HOST_IDTR_BASE
    // and there is no need to LIMIT as it's fixed at 0xffff for VMX
    // operations).
    // Because we want to use the debugging mechanism of the Windows
    // we use the same IDT with the guest (guest and host IDT is the
    // same), but in the future versions we solve this problem by our
    // own ISR NMI handler in vmx-root mode
    //

    //
    // We should check whether the NMI is in vmx-root mode or not
    // if it's not in vmx-root mode then it's not related to us
    //
    if (!VmxBroadcastNmiHandler(VCpu, TRUE))
    {
        return Handled;
    }
    else
    {
        //
        // If we're here then it related to us
        // return true to show that it's handled
        //
        return TRUE;
    }
}

/**
 * @brief Broadcast NMI in vmx-root mode
 * @details caller to this function should take actions to the current core
 * the NMI won't be triggered for the current core
 *
 * @param VCpu The virtual processor's state
 * @param VmxBroadcastAction
 * @return BOOLEAN
 */
BOOLEAN
VmxBroadcastNmi(VIRTUAL_MACHINE_STATE * VCpu, NMI_BROADCAST_ACTION_TYPE VmxBroadcastAction)
{
    ULONG ProcessorsCount;

    //
    // Check if NMI broadcasting is initialized
    //
    if (!g_NmiBroadcastingInitialized)
    {
        return FALSE;
    }

    ProcessorsCount = PlatformCpuGetActiveProcessorCount();

    //
    // Indicate that we're waiting for NMI
    //
    for (SIZE_T i = 0; i < ProcessorsCount; i++)
    {
        if (i != VCpu->CoreId)
        {
            SpinlockInterlockedCompareExchange((volatile LONG *)&g_GuestState[i].NmiBroadcastingState.NmiBroadcastAction,
                                               VmxBroadcastAction,
                                               NMI_BROADCAST_ACTION_NONE);
            VmxBroadcastKickCpu(&g_GuestState[i]);
        }
    }

    //
    // Broadcast NMI through APIC (xAPIC or x2APIC)
    //
    // 每个目标核最多一个未消费的内部 NMI；coherence 与既有广播共用握手。

    return TRUE;
}

/**
 * @brief Handle broadcast NMIs in vmx-root mode
 *
 * @param VCpu The virtual processor's state
 * @param IsOnVmxNmiHandler
 *
 * @return BOOLEAN Shows whether it's handled by this routine or not
 */
BOOLEAN
VmxBroadcastNmiHandler(VIRTUAL_MACHINE_STATE * VCpu, BOOLEAN IsOnVmxNmiHandler)
{
    NMI_BROADCAST_ACTION_TYPE BroadcastAction;
    BOOLEAN                   IsHandled = CpuInterlockedExchange(&VCpu->NmiIpiPending, 0) != 0;
    (VOID)CpuInterlockedExchange(&VCpu->HiddenCoherenceKick, 0);

    //
    // Check if NMI relates to us or not
    // Set NMI broadcasting action to none (clear the action)
    //
    BroadcastAction = CpuInterlockedExchange((volatile LONG *)&VCpu->NmiBroadcastingState.NmiBroadcastAction, NMI_BROADCAST_ACTION_NONE);

    if (BroadcastAction == NMI_BROADCAST_ACTION_NONE)
    {
        goto ReturnIsHandled;
    }

    //
    // *** It's relating to us ***
    //

    switch (BroadcastAction)
    {
    case NMI_BROADCAST_ACTION_TEST:

        //
        // Use for stress testing of the broadcasting mechanism
        //
        IsHandled = TRUE;

        break;

    case NMI_BROADCAST_ACTION_REQUEST:

        //
        // Handle NMI of halt the other cores
        //
        VmmCallbackNmiBroadcastRequestHandler(VCpu->CoreId, IsOnVmxNmiHandler);
        IsHandled = TRUE;

        break;

    case NMI_BROADCAST_ACTION_INVALIDATE_EPT_CACHE_SINGLE_CONTEXT:

        //
        // Invalidate EPT cache (single-context)
        //
        EptInveptSingleContext(VCpu->EptPointer.AsUInt);

        IsHandled = TRUE;

        break;

    case NMI_BROADCAST_ACTION_INVALIDATE_EPT_CACHE_ALL_CONTEXTS:

        //
        // Invalidate EPT cache (all contexts)
        //
        EptInveptAllContexts();
        IsHandled = TRUE;

        break;

    default:

        IsHandled = FALSE;
        LogError("Err, invalid NMI reason received");

        break;
    }

ReturnIsHandled:
    return IsHandled;
}
