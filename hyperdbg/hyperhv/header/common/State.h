/**
 * @file State.h
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Model-Specific Registers definitions
 *
 * @version 0.2
 * @date 2022-12-01
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//////////////////////////////////////////////////
//				      typedefs         			 //
//////////////////////////////////////////////////

typedef EPT_PML4E     EPT_PML4_POINTER, *PEPT_PML4_POINTER;
typedef EPT_PDPTE     EPT_PML3_POINTER, *PEPT_PML3_POINTER;
typedef EPT_PDPTE_1GB EPT_PML3_ENTRY, *PEPT_PML3_ENTRY;
typedef EPT_PDE_2MB   EPT_PML2_ENTRY, *PEPT_PML2_ENTRY;
typedef EPT_PDE       EPT_PML2_POINTER, *PEPT_PML2_POINTER;
typedef EPT_PTE       EPT_PML1_ENTRY, *PEPT_PML1_ENTRY;

//////////////////////////////////////////////////
//				    Constants					//
//////////////////////////////////////////////////

/**
 * @brief Pending External Interrupts Buffer Capacity
 *
 */
#define PENDING_INTERRUPTS_BUFFER_CAPACITY 64

/**
 * @brief Maximum number of hidden breakpoints in a page
 *
 */
#define MaximumHiddenBreakpointsOnPage 40
#define MaximumDegradedReplaySlots 64

typedef enum _EPT_HOOK_DEGRADED_REPLAY_STATE
{
    EptHookDegradedReplayNone       = 0,
    EptHookDegradedReplayExecutePre = 1,
    EptHookDegradedReplayAllowOriginal = 2,
    EptHookDegradedReplayClaimed    = 3,
} EptHookDegradedReplayState;

//////////////////////////////////////////////////
//					  Enums		    			//
//////////////////////////////////////////////////

/**
 * @brief Types of actions for NMI broadcasting
 *
 */
typedef enum _NMI_BROADCAST_ACTION_TYPE
{
    NMI_BROADCAST_ACTION_NONE = 0,
    NMI_BROADCAST_ACTION_TEST,
    NMI_BROADCAST_ACTION_REQUEST,
    NMI_BROADCAST_ACTION_INVALIDATE_EPT_CACHE_SINGLE_CONTEXT,
    NMI_BROADCAST_ACTION_INVALIDATE_EPT_CACHE_ALL_CONTEXTS,

} NMI_BROADCAST_ACTION_TYPE;

/**
 * @brief Types of last violation happened to EPT hook
 *
 */
typedef enum _EPT_HOOKED_LAST_VIOLATION
{
    EPT_HOOKED_LAST_VIOLATION_READ  = 1,
    EPT_HOOKED_LAST_VIOLATION_WRITE = 2,
    EPT_HOOKED_LAST_VIOLATION_EXEC  = 3

} EPT_HOOKED_LAST_VIOLATION;

//////////////////////////////////////////////////
//			      Memory Layout      			//
//////////////////////////////////////////////////

/**
 * @brief The number of 512GB PML4 entries in the page table
 *
 */
#define VMM_EPT_PML4E_COUNT 512

/**
 * @brief The number of 1GB PDPT entries in the page table per 512GB PML4 entry
 *
 */
#define VMM_EPT_PML3E_COUNT 512

/**
 * @brief Then number of 2MB Page Directory entries in the page table per 1GB
 *  PML3 entry
 *
 */
#define VMM_EPT_PML2E_COUNT 512

/**
 * @brief Then number of 4096 byte Page Table entries in the page table per 2MB PML2
 * entry when dynamically split
 *
 */
#define VMM_EPT_PML1E_COUNT 512

/**
 * @brief Structure for saving EPT Table
 *
 */
typedef struct _VMM_EPT_PAGE_TABLE
{
    /**
     * @brief 28.2.2 Describes 512 contiguous 512GB memory regions each with 512 1GB regions.
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
    EPT_PML4_POINTER PML4[VMM_EPT_PML4E_COUNT];

    /**
     * @brief Describes exactly 512 contiguous 1GB memory regions within a our singular 512GB PML4 region
     * (This entry is used to support the entire address space).
     * @details The reason why there is a minus one here is that the original PML3 is described in the next field.
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
    EPT_PML3_ENTRY PML3_RSVD[VMM_EPT_PML4E_COUNT - 1][VMM_EPT_PML3E_COUNT];

    /**
     * @brief Describes exactly 512 contiguous 1GB memory regions within a our singular 512GB PML4 region.
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
    EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];

    /**
     * @brief For each 1GB PML3 entry, create 512 2MB entries to map identity.
     * NOTE: We are using 2MB pages as the smallest paging size in our map, so we do not manage individual 4096 byte pages.
     * Therefore, we do not allocate any PML1 (4096 byte) paging structures.
     */
    DECLSPEC_ALIGN(PAGE_SIZE)
    EPT_PML2_ENTRY PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];

    /**
     * @brief Tracks dynamic 2MB->4KB splits for this EPT table.
     * NOTE: Each item stores a direct VA to the split PML1 page and the corresponding PML2 entry it services.
     *
     */
    LIST_ENTRY DynamicSplitList;

} VMM_EPT_PAGE_TABLE, *PVMM_EPT_PAGE_TABLE;

//////////////////////////////////////////////////
//					  Structure	    			//
//////////////////////////////////////////////////

/**
 * @brief The status of transparency of each core after and before VMX
 *
 */
typedef struct _VM_EXIT_TRANSPARENCY
{
    UINT64 PreviousTimeStampCounter;

    HANDLE  ThreadId;
    UINT64  RevealedTimeStampCounterByRdtsc;
    BOOLEAN CpuidAfterRdtscDetected;

} VM_EXIT_TRANSPARENCY, *PVM_EXIT_TRANSPARENCY;

/**
 * @brief Save the state of core in the case of VMXOFF
 *
 */
typedef struct _VMX_VMXOFF_STATE
{
    BOOLEAN IsVmxoffExecuted; // Shows whether the VMXOFF executed or not
    UINT64  GuestRip;         // Rip address of guest to return
    UINT64  GuestRsp;         // Rsp address of guest to return

} VMX_VMXOFF_STATE, *PVMX_VMXOFF_STATE;

/**
 * @brief Structure to save the state of each hooked pages
 *
 */
typedef struct _EPT_HOOKED_PAGE_DETAIL
{
    DECLSPEC_ALIGN(PAGE_SIZE)
    CHAR FakePageContents[PAGE_SIZE];

    /**
     * @brief Linked list entries for each page hook.
     */
    LIST_ENTRY PageHookList;

    /**
     * @brief The virtual address from the caller perspective view (cr3)
     */
    UINT64 VirtualAddress;

    /**
     * @brief The virtual address of it's entry on g_EptHook2sDetourListHead
     * this way we can de-allocate the list whenever the hook is finished
     */
    UINT64 AddressOfEptHook2sDetourListEntry;

    /**
     * @brief The base address of the page. Used to find this structure in the list of page hooks
     * when a hook is hit.
     */
    SIZE_T PhysicalBaseAddress;

    /**
     * @brief Start address of the target physical address.
     */
    SIZE_T StartOfTargetPhysicalAddress;

    /**
     * @brief End address of the target physical address.
     */
    SIZE_T EndOfTargetPhysicalAddress;

    /**
     * @brief Tag used for notifying the caller.
     */
    UINT64 HookingTag;

    /**
     * @brief Optional memory monitor metadata that can coexist with a hidden breakpoint page.
     */
    SIZE_T MonitorStartOfTargetPhysicalAddress;
    SIZE_T MonitorEndOfTargetPhysicalAddress;
    BOOLEAN HasMemoryMonitor;
    BOOLEAN MonitorReadAccess;
    BOOLEAN MonitorWriteAccess;
    BOOLEAN MonitorExecuteAccess;

    /**
     * @brief The base address of the page with fake contents. Used to swap page with fake contents
     * when a hook is hit.
     */
    SIZE_T PhysicalBaseAddressOfFakePageContents;

    /**
     * @brief The original page entry. Will be copied back when the hook is removed
     * from the page.
     */
    EPT_PML1_ENTRY OriginalEntry;

    /**
     * @brief The original page entry. Will be copied back when the hook is remove from the page.
     */
    EPT_PML1_ENTRY ChangedEntry;

    /**
     * @brief The buffer of the trampoline function which is used in the inline hook.
     */
    PCHAR Trampoline;

    /**
     * @brief This field shows whether the hook contains a hidden hook for execution or not
     */
    BOOLEAN IsExecutionHook;

    /**
     * @brief If TRUE shows that this is the information about
     * a hidden breakpoint command (not a monitor or hidden detours)
     */
    BOOLEAN IsHiddenBreakpoint;

    /**
     * @brief TRUE when a hidden breakpoint page is degraded to X=0 emulated INT3
     * because an execute monitor exists on the same physical page.
     */
    BOOLEAN IsHiddenBreakpointDegraded;

    /**
     * @brief This field shows whether the hook is for MMIO shadowing or not
     */
    BOOLEAN IsMmioShadowing;

    /**
     * @brief Temporary context for the post event monitors
     * It shows the context of the last address that triggered the hook
     * Note: Only used for read/write trigger events
     */
    EPT_HOOKS_CONTEXT LastContextState;

    /**
     * @brief This field shows whether the hook should call the post event trigger
     * after restoring the state or not
     */
    BOOLEAN IsPostEventTriggerAllowed;

    /**
     * @brief This field shows the last violation happened to this EPT hook
     */
    EPT_HOOKED_LAST_VIOLATION LastViolation;

    /**
     * @brief Address of hooked pages (multiple breakpoints on a single page)
     * this is only used in hidden breakpoints (not hidden detours)
     */
    UINT64 BreakpointAddresses[MaximumHiddenBreakpointsOnPage];

    /**
     * @brief Character that was previously used in BreakpointAddresses
     * this is only used in hidden breakpoints (not hidden detours)
     */
    CHAR PreviousBytesOnBreakpointAddresses[MaximumHiddenBreakpointsOnPage];

    /**
     * @brief Per-breakpoint replay stage for degraded hidden breakpoints.
     */
    LONG DegradedBreakpointReplayStage[MaximumDegradedReplaySlots];

    /**
     * @brief Addresses that still need degraded replay even if the debugger
     * removes the software breakpoint while stopped on the injected #BP.
     */
    UINT64 DegradedBreakpointReplayAddress[MaximumDegradedReplaySlots];

    /**
     * @brief Owner process for each degraded replay slot.
     */
    UINT32 DegradedBreakpointReplayOwnerProcessId[MaximumDegradedReplaySlots];

    /**
     * @brief Owner thread for each degraded replay slot.
     */
    UINT32 DegradedBreakpointReplayOwnerThreadId[MaximumDegradedReplaySlots];

    /**
     * @brief Count of MTF restores that completed the final original-instruction
     * replay for degraded hidden breakpoints.
     */
    UINT64 DegradedBreakpointMtfReplayCount;

    /**
     * @brief Count of degraded replay slots exhaustion events.
     */
    UINT64 DegradedBreakpointReplayOverflowCount;

    /**
     * @brief Count of breakpoints (multiple breakpoints on a single page)
     * this is only used in hidden breakpoints (not hidden detours)
     */
    UINT64 CountOfBreakpoints;

    /**
     * @brief Diagnostic-only counters for tracing this entry's MTF
     * restore-to-changed-entry lifecycle. MtfRestoreCompletedCount includes
     * normal MTF vm-exit restores and downstream overwrite-flush restores.
     * MtfStarvedByOtherHitCount counts attempted overwrite windows ("would
     * starve without the flush"), not necessarily a permanently lost restore.
     * Non-evicting, monotonically increasing; read-only from companion-driver
     * via EptHookQueryState.
     */
    UINT64 MtfArmedCount;
    UINT64 MtfRestoreCompletedCount;
    UINT64 MtfStarvedByOtherHitCount;

    /**
     * @brief Diagnostic-only per-site breakdown of MtfArmedCount. The three
     * arm sites (BP-driven exact-address hit, general R/W/X EPT-violation
     * handling, same-RIP violation-threshold pass-through) share one
     * MtfArmedCount; these disambiguate which site produced each increment.
     * MtfArmedByBpCount + MtfArmedByRwCount + MtfArmedByThresholdCount ==
     * MtfArmedCount. Non-evicting, monotonically increasing; read-only from
     * companion-driver via EptHookQueryState. No effect on hook behavior.
     */
    UINT64 MtfArmedByBpCount;
    UINT64 MtfArmedByRwCount;
    UINT64 MtfArmedByThresholdCount;

    /**
     * @brief Last MTF restore vm-exit RIP and replay context VA. Diagnostic-only
     * latch used to distinguish same-RIP replay stalls from later pipeline bugs.
     */
    UINT64 MtfLastExitRip;
    UINT64 MtfLastContextVirtualAddress;

} EPT_HOOKED_PAGE_DETAIL, *PEPT_HOOKED_PAGE_DETAIL;

/**
 * @brief The status of NMI broadcasting in VMX
 *
 */
typedef struct _NMI_BROADCASTING_STATE
{
    volatile NMI_BROADCAST_ACTION_TYPE NmiBroadcastAction; // The broadcast action for NMI

} NMI_BROADCASTING_STATE, *PNMI_BROADCASTING_STATE;

/**
 * @brief The status of each core after and before VMX
 *
 */
typedef struct _VIRTUAL_MACHINE_STATE
{
    BOOLEAN          IsOnVmxRootMode;                                               // Detects whether the current logical core is on Executing on VMX Root Mode
    BOOLEAN          IncrementRip;                                                  // Checks whether it has to redo the previous instruction or not (it used mainly in Ept routines)
    BOOLEAN          HasLaunched;                                                   // Indicate whether the core is virtualized or not
    BOOLEAN          IgnoreMtfUnset;                                                // Indicate whether the core should ignore unsetting the MTF or not
    BOOLEAN          WaitForImmediateVmexit;                                        // Whether the current core is waiting for an immediate vm-exit or not
    BOOLEAN          EnableExternalInterruptsOnContinue;                            // Whether to enable external interrupts on the continue  or not
    BOOLEAN          EnableExternalInterruptsOnContinueMtf;                         // Whether to enable external interrupts on the continue state of MTF or not
    BOOLEAN          RegisterBreakOnMtf;                                            // Registered Break in the case of MTFs (used in instrumentation step-in)
    BOOLEAN          IgnoreOneMtf;                                                  // Ignore (mark as handled) for one MTF
    BOOLEAN          NotNormalEptp;                                                 // Indicate that the target processor is on the normal EPTP or not
    BOOLEAN          MbecEnabled;                                                   // Indicate that the target processor is on MBEC-enabled mode or not
    PUINT64          PmlBufferAddress;                                              // Address of buffer used for dirty logging
    BOOLEAN          Test;                                                          // Used for test purposes
    UINT64           TestNumber;                                                    // Used for test purposes (Number)
    GUEST_REGS *     Regs;                                                          // The virtual processor's general-purpose registers
    GUEST_XMM_REGS * XmmRegs;                                                       // The virtual processor's XMM registers
    UINT32           CoreId;                                                        // The core's unique identifier
    UINT32           ExitReason;                                                    // The core's exit reason
    UINT32           ExitQualification;                                             // The core's exit qualification
    UINT64           LastVmexitRip;                                                 // RIP in the current VM-exit
    UINT64           VmxonRegionPhysicalAddress;                                    // Vmxon region physical address
    UINT64           VmxonRegionVirtualAddress;                                     // VMXON region virtual address
    UINT64           VmcsRegionPhysicalAddress;                                     // VMCS region physical address
    UINT64           VmcsRegionVirtualAddress;                                      // VMCS region virtual address
    UINT64           VmmStack;                                                      // Stack for VMM in VM-Exit State
    UINT64           MsrBitmapVirtualAddress;                                       // Msr Bitmap Virtual Address
    UINT64           MsrBitmapPhysicalAddress;                                      // Msr Bitmap Physical Address
    UINT64           IoBitmapVirtualAddressA;                                       // I/O Bitmap Virtual Address (A)
    UINT64           IoBitmapPhysicalAddressA;                                      // I/O Bitmap Physical Address (A)
    UINT64           IoBitmapVirtualAddressB;                                       // I/O Bitmap Virtual Address (B)
    UINT64           IoBitmapPhysicalAddressB;                                      // I/O Bitmap Physical Address (B)
    UINT32           QueuedNmi;                                                     // Queued NMIs
    UINT32           PendingExternalInterrupts[PENDING_INTERRUPTS_BUFFER_CAPACITY]; // This list holds a buffer for external-interrupts that are in pending state due to the external-interrupt
                                                                                    // blocking and waits for interrupt-window exiting
                                                                                    // From hvpp :
                                                                                    // Pending interrupt queue (FIFO).
                                                                                    // Make storage for up-to 64 pending interrupts.
                                                                                    // In practice I haven't seen more than 2 pending interrupts.
    VMX_VMXOFF_STATE        VmxoffState;                                            // Shows the vmxoff state of the guest
    NMI_BROADCASTING_STATE  NmiBroadcastingState;                                   // Shows the state of NMI broadcasting
    VM_EXIT_TRANSPARENCY    TransparencyState;                                      // The state of the debugger in transparent-mode
    PEPT_HOOKED_PAGE_DETAIL MtfEptHookRestorePoint;                                 // It shows the detail of the hooked paged that should be restore in MTF vm-exit
    BOOLEAN                 DegradedHiddenBreakpointInjectionActive;                 // TRUE while degraded replay asks the adapter to inject a current-RIP #BP
    UINT64                  DegradedBreakpointMtfReplayAddress;                      // Address whose degraded original instruction is being restored by this core's MTF
    BOOLEAN                 DegradedBreakpointMtfReplayPending;                      // TRUE while this core owns a degraded original-instruction MTF replay
    BOOLEAN                 MtfEptFallbackRestorePending;                           // TRUE when an unknown EPT violation is temporarily allowed for one instruction
    BOOLEAN                 MtfEptFallbackRestoreLargePage;                         // TRUE when the fallback restore target is a PML2 large page
    UINT64                  MtfEptFallbackPhysicalBaseAddress;                      // Physical base address for the fallback MTF restore
    EPT_PML1_ENTRY          MtfEptFallbackOriginalPml1Entry;                        // Saved PML1 entry for fallback MTF restore
    EPT_PML2_ENTRY          MtfEptFallbackOriginalPml2Entry;                        // Saved PML2 entry for fallback MTF restore
    UINT64                  LastEptViolationRip;                                    // Last RIP that caused an EPT violation on this core
    UINT32                  SameRipEptViolationCount;                               // Consecutive EPT violations at LastEptViolationRip
    UINT8                   LastExceptionOccurredInHost;                            // The vector of last exception occurred in host
    UINT64                  HostIdt;                                                // host Interrupt Descriptor Table (actual type is SEGMENT_DESCRIPTOR_INTERRUPT_GATE_64*)
    UINT64                  HostGdt;                                                // host Global Descriptor Table (actual type is SEGMENT_DESCRIPTOR_32* or SEGMENT_DESCRIPTOR_64*)
    UINT64                  HostTss;                                                // host Task State Segment (actual type is TASK_STATE_SEGMENT_64*)
    UINT64                  HostInterruptStack;                                     // host interrupt RSP

    //
    // EPT Descriptors
    //
    EPT_POINTER         EptPointer;   // Extended-Page-Table Pointer
    PVMM_EPT_PAGE_TABLE EptPageTable; // Details of core-specific page-table

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;
