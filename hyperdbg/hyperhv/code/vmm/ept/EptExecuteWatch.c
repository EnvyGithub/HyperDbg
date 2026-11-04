#include "pch.h"
#include "vmm/ept/EptExecuteWatch.h"

#ifdef HYPERDBG_ENV_WINDOWS

#define EW_MAX_PAGES 256u
#define EW_MAX_LEASES 8192u
#define EW_MAX_CPUS 256u
#define EW_MAX_STEP (EW_MAX_PAGES + 2u)
#define EW_EXECUTE 1u
#define EW_WRITE 2u
#define EW_PHYSICAL_MASK 0x000ffffffffff000ull
#define EW_AD_MASK 0x300ull
#define EW_LARGE_MASK 0x000fffffffe00000ull
#define EW_SPINS 65536u

typedef struct EW_TABLE { UINT64 *Va; UINT64 Pa; } EW_TABLE;
typedef struct EW_PAGE { UINT64 Pa, RetiredAt, PublishedAt; UINT32 References, ExecuteReferences; volatile LONG WriteReferences; } EW_PAGE;
typedef struct EW_LEASE { UINT64 Token; UINT32 Page, Access; } EW_LEASE;
typedef struct EW_WRITER { volatile LONG64 Token; UINT64 Page; } EW_WRITER;
typedef struct EW_CPU {
    EW_TABLE Pml4, Pml3, Pml2[EW_MAX_PAGES], Pml1[EW_MAX_PAGES];
    UINT64 ViewPages[EW_MAX_PAGES], StepPages[EW_MAX_STEP], StepWriters[EW_MAX_STEP], StepRip, StepCr3, ViewGeneration;
    UINT32 ViewAccess[EW_MAX_PAGES], StepAccess[EW_MAX_STEP];
    UINT64 Pml4Source[512], Pml3Source[512];
    UINT32 ViewCount, Pml2Count, Pml1Count, StepCount;
    UINT32 Pml2Index[EW_MAX_PAGES];
    UINT64 Pml1Chunk[EW_MAX_PAGES], Pml1Source[EW_MAX_PAGES];
    UINT64 Pml1Execute[EW_MAX_PAGES][8];
    UINT64 Pml1Write[EW_MAX_PAGES][8];
    UINT64 *Pml1SourceVa[EW_MAX_PAGES];
    BOOLEAN Pml1Large[EW_MAX_PAGES], Installed, Incoming, MtfPending, NeedsInvalidate;
    volatile LONG64 Acknowledged;
    EPT_POINTER Pointer;
} EW_CPU;
typedef struct EW_CONTEXT {
    volatile LONG Gate, Closing, CallbackActive, Fault;
    UINT32 MaximumPages, MaximumLeases, Cpus, ActivePages, ActiveLeases, MaximumWriters;
    volatile LONG ActiveWriters;
    volatile LONG64 Generation, Serial, Observations, Retries, CapacityFailures, SynchronizationFailures;
    VMM_EXECUTE_WATCH_CALLBACK Callback;
    EW_PAGE Pages[EW_MAX_PAGES];
    EW_LEASE Leases[EW_MAX_LEASES];
    EW_WRITER *Writers;
    volatile LONG64 WriterSerial;
    EW_CPU *Cpu;
} EW_CONTEXT;
static EW_CONTEXT *volatile g_ExecuteWatch;
static volatile LONG g_ExecuteWatchReaders, g_ExecuteWatchControl;

static EW_CONTEXT *EwEnter(VOID)
{
    InterlockedIncrement(&g_ExecuteWatchReaders);
    return InterlockedCompareExchangePointer((PVOID volatile *)&g_ExecuteWatch, NULL, NULL);
}
static VOID EwLeave(VOID) { InterlockedDecrement(&g_ExecuteWatchReaders); }
static BOOLEAN EwLock(EW_CONTEXT *C) { return InterlockedCompareExchange(&C->Gate, 1, 0) == 0; }
static VOID EwUnlock(EW_CONTEXT *C) { InterlockedExchange(&C->Gate, 0); }
static UINT64 EwGeneration(EW_CONTEXT *C) { return (UINT64)InterlockedCompareExchange64(&C->Generation, 0, 0); }
static VOID EwFault(EW_CONTEXT *C, NTSTATUS Status)
{
    (VOID)InterlockedCompareExchange(&C->Fault, Status, STATUS_SUCCESS);
    InterlockedIncrement64(&C->SynchronizationFailures);
}
static UINT64 EwMinimumAck(EW_CONTEXT *C)
{
    UINT64 Minimum = ~(UINT64)0;
    for (UINT32 I = 0; I < C->Cpus; I++) {
        UINT64 Value = (UINT64)InterlockedCompareExchange64(&C->Cpu[I].Acknowledged, 0, 0);
        if (Value < Minimum) Minimum = Value;
    }
    return Minimum;
}
static VOID EwKick(EW_CONTEXT *C)
{
    for (UINT32 I = 0; I < C->Cpus; I++) {
        InterlockedExchange(&g_GuestState[I].HiddenCoherenceKick, 1);
        VmxBroadcastKickCpu(&g_GuestState[I]);
    }
}
static BOOLEAN EwTableAllocate(EW_TABLE *T)
{
    T->Va = PlatformMemAllocateContiguousZeroedMemory(PAGE_SIZE);
    if (T->Va == NULL) return FALSE;
    T->Pa = VirtualAddressToPhysicalAddress(T->Va);
    return T->Pa != 0 && (T->Pa & (PAGE_SIZE - 1)) == 0;
}
static VOID EwTableFree(EW_TABLE *T)
{
    if (T->Va != NULL) PlatformMemFreeContiguousMemory(T->Va);
    T->Va = NULL; T->Pa = 0;
}
static VOID EwFree(EW_CONTEXT *C)
{
    if (C == NULL) return;
    if (C->Cpu != NULL) {
        for (UINT32 I = 0; I < C->Cpus; I++) {
            EW_CPU *L = &C->Cpu[I];
            EwTableFree(&L->Pml4); EwTableFree(&L->Pml3);
            for (UINT32 J = 0; J < C->MaximumPages; J++) {
                EwTableFree(&L->Pml2[J]); EwTableFree(&L->Pml1[J]);
            }
        }
        PlatformMemFreePool(C->Cpu);
    }
    if (C->Writers != NULL) PlatformMemFreePool(C->Writers);
    PlatformMemFreePool(C);
}

// overlay 的 A/D 不能冒充 primary 未被访问；只合并同一映射的状态，不把旧 fake PFN 的脏位写到新映射。
static BOOLEAN EwMergeBits(volatile LONG64 *Target, UINT64 Expected, UINT64 IdentityMask, UINT64 Bits)
{
    LONG64 Current = InterlockedCompareExchange64(Target, 0, 0);
    if (Bits == 0) return TRUE;
    for (UINT32 Attempt = 0; Attempt < 16; Attempt++) {
        if (((UINT64)Current & IdentityMask) != (Expected & IdentityMask)) return TRUE;
        LONG64 Next = Current | (LONG64)Bits;
        if (Next == Current) return TRUE;
        LONG64 Observed = InterlockedCompareExchange64(Target, Next, Current);
        if (Observed == Current) return TRUE;
        Current = Observed;
    }
    return FALSE;
}
static BOOLEAN EwMergeAd(VIRTUAL_MACHINE_STATE *Cpu, EW_CPU *L)
{
    if (L->ViewCount == 0) return TRUE;
    BOOLEAN Merged = TRUE;
    UINT64 *P4 = (UINT64 *)Cpu->EptPageTable->PML4;
    UINT64 *P3 = (UINT64 *)Cpu->EptPageTable->PML3;
    for (UINT32 I = 0; I < 512; I++) {
        Merged &= EwMergeBits((volatile LONG64 *)&P4[I], L->Pml4Source[I], EW_PHYSICAL_MASK, L->Pml4.Va[I] & 0x100u);
        Merged &= EwMergeBits((volatile LONG64 *)&P3[I], L->Pml3Source[I], EW_PHYSICAL_MASK, L->Pml3.Va[I] & 0x100u);
    }
    for (UINT32 I = 0; I < L->Pml2Count; I++) {
        UINT32 Index = L->Pml2Index[I];
        for (UINT32 J = 0; J < 512; J++) {
            UINT64 View = L->Pml2[I].Va[J];
            Merged &= EwMergeBits((volatile LONG64 *)&Cpu->EptPageTable->PML2[Index][J].AsUInt,
                View, EW_PHYSICAL_MASK | 0x80ull, View & ((View & 0x80u) ? EW_AD_MASK : 0x100u));
        }
    }
    for (UINT32 I = 0; I < L->Pml1Count; I++) {
        PEPT_PML2_ENTRY Current = EptGetPml2Entry(Cpu->EptPageTable, L->Pml1Chunk[I] << 21);
        if (Current == NULL) continue;
        UINT64 ParentAccessed = 0;
        for (UINT32 Directory = 0; Directory < L->Pml2Count; Directory++)
            if (L->Pml2Index[Directory] == (UINT32)(L->Pml1Chunk[I] >> 9))
                ParentAccessed = L->Pml2[Directory].Va[L->Pml1Chunk[I] & 511u] & 0x100u;
        Merged &= EwMergeBits((volatile LONG64 *)&Current->AsUInt, L->Pml1Source[I],
            EW_PHYSICAL_MASK | 0x80ull, ParentAccessed);
        if (L->Pml1Large[I]) {
            if (!Current->LargePage || (Current->AsUInt & EW_LARGE_MASK) != (L->Pml1Source[I] & EW_LARGE_MASK)) continue;
            UINT64 Bits = 0;
            for (UINT32 J = 0; J < 512; J++) Bits |= L->Pml1[I].Va[J] & EW_AD_MASK;
            Merged &= EwMergeBits((volatile LONG64 *)&Current->AsUInt, L->Pml1Source[I], EW_LARGE_MASK | 0x80ull, Bits);
        } else {
            if (Current->LargePage || (Current->AsUInt & EW_PHYSICAL_MASK) != (L->Pml1Source[I] & EW_PHYSICAL_MASK)) continue;
            UINT64 *Original = L->Pml1SourceVa[I];
            for (UINT32 J = 0; J < 512; J++)
                Merged &= EwMergeBits((volatile LONG64 *)&Original[J], L->Pml1[I].Va[J], EW_PHYSICAL_MASK, L->Pml1[I].Va[J] & EW_AD_MASK);
        }
    }
    return Merged;
}

static BOOLEAN EwSnapshot(EW_CONTEXT *C, EW_CPU *L)
{
    if (!EwLock(C)) return FALSE;
    L->ViewCount = 0;
    if (C->Closing == 0 && C->Fault == STATUS_SUCCESS) {
        for (UINT32 I = 0; I < C->MaximumPages; I++)
            if (C->Pages[I].References != 0) {
                UINT32 Index = L->ViewCount++;
                L->ViewPages[Index] = C->Pages[I].Pa;
                L->ViewAccess[Index] = (C->Pages[I].ExecuteReferences ? EW_EXECUTE : 0) |
                    (C->Pages[I].WriteReferences ? EW_WRITE : 0);
            }
    }
    L->ViewGeneration = EwGeneration(C);
    EwUnlock(C);
    return TRUE;
}
static BOOLEAN EwExempt(EW_CPU *L, UINT64 Page, UINT32 Access)
{
    for (UINT32 I = 0; I < L->StepCount; I++) if (L->StepPages[I] == Page && (L->StepAccess[I] & Access) != 0) return TRUE;
    return FALSE;
}
static UINT64 EwReadEntry(const UINT64 *Entry)
{ return (UINT64)InterlockedCompareExchange64((volatile LONG64 *)Entry, 0, 0); }
static BOOLEAN EwPrimaryStable(VIRTUAL_MACHINE_STATE *Cpu, EW_CPU *L)
{
    for (UINT32 I = 0; I < 512; I++) {
        if ((EwReadEntry(&Cpu->EptPageTable->PML4[I].AsUInt) & ~0x100ull) != (L->Pml4Source[I] & ~0x100ull) ||
            (EwReadEntry(&Cpu->EptPageTable->PML3[I].AsUInt) & ~0x100ull) != (L->Pml3Source[I] & ~0x100ull)) return FALSE;
    }
    for (UINT32 I = 0; I < L->Pml2Count; I++) for (UINT32 J = 0; J < 512; J++) {
        UINT64 Expected = L->Pml2[I].Va[J], Chunk = (UINT64)L->Pml2Index[I] * 512 + J;
        for (UINT32 K = 0; K < L->Pml1Count; K++) if (L->Pml1Chunk[K] == Chunk) { Expected = L->Pml1Source[K]; break; }
        if ((EwReadEntry(&Cpu->EptPageTable->PML2[L->Pml2Index[I]][J].AsUInt) & ~EW_AD_MASK) != (Expected & ~EW_AD_MASK)) return FALSE;
    }
    for (UINT32 I = 0; I < L->Pml1Count; I++) if (!L->Pml1Large[I]) for (UINT32 J = 0; J < 512; J++) {
        UINT64 Expected = L->Pml1[I].Va[J] & ~6ull;
        if (L->Pml1Execute[I][J / 64] & (1ull << (J % 64))) Expected |= 4;
        if (L->Pml1Write[I][J / 64] & (1ull << (J % 64))) Expected |= 2;
        if ((EwReadEntry(&L->Pml1SourceVa[I][J]) & ~EW_AD_MASK) != (Expected & ~EW_AD_MASK)) return FALSE;
    }
    return TRUE;
}
// primary 的全部 R/W/PFN/内存类型决定保持不变；2MB 叶只在 overlay 中拆成 4KB。
static BOOLEAN EwBuild(VIRTUAL_MACHINE_STATE *Cpu, EW_CPU *L)
{
    L->NeedsInvalidate = TRUE;
    L->Pml2Count = L->Pml1Count = 0;
    for (UINT32 I = 0; I < 512; I++) {
        L->Pml4.Va[I] = EwReadEntry(&Cpu->EptPageTable->PML4[I].AsUInt);
        L->Pml3.Va[I] = EwReadEntry(&Cpu->EptPageTable->PML3[I].AsUInt);
    }
    RtlCopyMemory(L->Pml4Source, L->Pml4.Va, PAGE_SIZE);
    RtlCopyMemory(L->Pml3Source, L->Pml3.Va, PAGE_SIZE);
    L->Pml4.Va[0] = (L->Pml4.Va[0] & ~EW_PHYSICAL_MASK) | L->Pml3.Pa;
    for (UINT32 I = 0; I < L->ViewCount; I++) {
        UINT64 Page = L->ViewPages[I], Chunk = Page >> 21;
        UINT32 Pdpt = (UINT32)((Page >> 30) & 511), Pd = (UINT32)((Page >> 21) & 511), Pt = (UINT32)((Page >> 12) & 511);
        UINT32 Directory, Table;
        for (Directory = 0; Directory < L->Pml2Count; Directory++) if (L->Pml2Index[Directory] == Pdpt) break;
        if (Directory == L->Pml2Count) {
            L->Pml2Index[L->Pml2Count++] = Pdpt;
            for (UINT32 J = 0; J < 512; J++) L->Pml2[Directory].Va[J] = EwReadEntry(&Cpu->EptPageTable->PML2[Pdpt][J].AsUInt);
            L->Pml3.Va[Pdpt] = (L->Pml3.Va[Pdpt] & ~EW_PHYSICAL_MASK) | L->Pml2[Directory].Pa;
        }
        for (Table = 0; Table < L->Pml1Count; Table++) if (L->Pml1Chunk[Table] == Chunk) break;
        if (Table == L->Pml1Count) {
            PEPT_PML2_ENTRY Entry = &Cpu->EptPageTable->PML2[Pdpt][Pd];
            EPT_PML2_ENTRY Snapshot; Snapshot.AsUInt = EwReadEntry(&Entry->AsUInt);
            L->Pml1Chunk[Table] = Chunk; L->Pml1Source[Table] = Snapshot.AsUInt;
            L->Pml1Large[Table] = Snapshot.LargePage != 0;
            RtlZeroMemory(L->Pml1Execute[Table], sizeof(L->Pml1Execute[Table]));
            RtlZeroMemory(L->Pml1Write[Table], sizeof(L->Pml1Write[Table]));
            if (Snapshot.LargePage) {
                UINT64 Flags = Snapshot.AsUInt & ~(EW_PHYSICAL_MASK | 0x80ull);
                UINT64 Base = Snapshot.AsUInt & EW_LARGE_MASK;
                for (UINT32 J = 0; J < 512; J++) L->Pml1[Table].Va[J] = Flags | (Base + (UINT64)J * PAGE_SIZE);
                L->Pml1SourceVa[Table] = NULL;
                L->Pml2[Directory].Va[Pd] = (Snapshot.AsUInt & 0x507ull) | L->Pml1[Table].Pa;
            } else {
                PEPT_PML1_ENTRY First = EptGetPml1EntryFromSnapshot(Cpu->EptPageTable, Chunk << 21, Snapshot.AsUInt);
                if (First == NULL) return FALSE;
                L->Pml1SourceVa[Table] = (UINT64 *)First;
                for (UINT32 J = 0; J < 512; J++) L->Pml1[Table].Va[J] = EwReadEntry(&First[J].AsUInt);
                L->Pml2[Directory].Va[Pd] = (Snapshot.AsUInt & ~EW_PHYSICAL_MASK) | L->Pml1[Table].Pa;
            }
            for (UINT32 J = 0; J < 512; J++) if (L->Pml1[Table].Va[J] & 4u)
                L->Pml1Execute[Table][J / 64] |= 1ull << (J % 64);
            for (UINT32 J = 0; J < 512; J++) if (L->Pml1[Table].Va[J] & 2u)
                L->Pml1Write[Table][J / 64] |= 1ull << (J % 64);
            L->Pml1Count++;
        }
        if ((L->ViewAccess[I] & EW_EXECUTE) != 0 && !EwExempt(L, Page, EW_EXECUTE)) L->Pml1[Table].Va[Pt] &= ~4ull;
        if ((L->ViewAccess[I] & EW_WRITE) != 0 && !EwExempt(L, Page, EW_WRITE)) L->Pml1[Table].Va[Pt] &= ~2ull;
    }
    return TRUE;
}

static VOID EwWriteEptPointer(VIRTUAL_MACHINE_STATE *Cpu, EW_CONTEXT *C, UINT64 Pointer)
{
    if (VmxVmwrite64(VMCS_CTRL_EPT_POINTER, Pointer) != 0) {
        EwFault(C, STATUS_UNSUCCESSFUL);
        // 合法活动 VMCS 的字段写失败不是可重发的 guest 指令；不得吞异步事件后 resume。
        KeBugCheckEx(0x20001u, 0x45575054u, Cpu->CoreId, Cpu->ExitReason, (ULONG_PTR)Pointer);
    }
}

// 写窗口先登记、后通知。最后一个 store/MTF 完成以前，新页表路径租约不能从其间穿过。
static BOOLEAN EwWriterBegin(EW_CONTEXT *C, UINT64 Page, UINT64 *Token)
{
    *Token = 0;
    if (!EwLock(C)) return FALSE;
    if (C->Closing || C->Fault != STATUS_SUCCESS) { EwUnlock(C); return TRUE; }
    UINT32 Index;
    for (Index = 0; Index < C->MaximumWriters; Index++) if (C->Writers[Index].Token == 0) break;
    UINT64 Serial = (UINT64)InterlockedIncrement64(&C->WriterSerial);
    if (Index == C->MaximumWriters || Serial > 0x7ffffffffffull) { EwUnlock(C); return FALSE; }
    C->Writers[Index].Page = Page;
    UINT64 Value = (Serial << 20) | (Index + 1u);
    InterlockedIncrement(&C->ActiveWriters);
    InterlockedExchange64(&C->Writers[Index].Token, (LONG64)Value);
    *Token = Value; EwUnlock(C); return TRUE;
}
static VOID EwWriterEnd(EW_CONTEXT *C, UINT64 Token)
{
    if (!Token) return;
    UINT32 Index = (UINT32)(Token & 0xfffffu);
    if (!Index || --Index >= C->MaximumWriters) return;
    if ((UINT64)InterlockedCompareExchange64(&C->Writers[Index].Token, 0, (LONG64)Token) == Token)
        InterlockedDecrement(&C->ActiveWriters);
}
static BOOLEAN EwWriterPresent(EW_CONTEXT *C, UINT64 Page)
{
    // 调用者持有 Gate；End 只清 Token，不修改 Page，不能被下一 writer 重用到本次扫描中。
    if (C->ActiveWriters == 0) return FALSE;
    for (UINT32 I = 0; I < C->MaximumWriters; I++)
        if (C->Writers[I].Token != 0 && C->Writers[I].Page == Page) return TRUE;
    return FALSE;
}
static VOID EwClearStep(EW_CONTEXT *C, EW_CPU *L)
{
    for (UINT32 I = 0; I < L->StepCount; I++) {
        EwWriterEnd(C, L->StepWriters[I]); L->StepWriters[I] = 0; L->StepAccess[I] = 0;
    }
    L->StepCount = 0;
}
static BOOLEAN EwCallback(EW_CONTEXT *C, VIRTUAL_MACHINE_STATE *Cpu, UINT64 Address, UINT32 Access, UINT64 Size)
{
    GUEST_REGS Registers = {0};
    if (Cpu->Regs != NULL) Registers = *Cpu->Regs;
    VMM_EXECUTE_WATCH_HIT Hit = {0}; Hit.Size = sizeof(Hit); Hit.CoreId = Cpu->CoreId;
    VmxVmread64P(VMCS_GUEST_RIP, &Hit.GuestRip); Hit.GuestCr3 = GetGuestCr3(); Hit.GuestCr4 = GetGuestCr4();
    Hit.PhysicalAddress = Address; Hit.Registers = &Registers; Hit.CsSelector = GetGuestCs().Selector;
    Hit.Access = Access; Hit.AccessSize = Size;
    VmxVmread64P(VMCS_GUEST_RFLAGS, &Hit.Rflags);
    InterlockedIncrement(&C->CallbackActive); InterlockedIncrement64(&C->Observations);
    if (C->Callback != NULL && C->Closing == 0) C->Callback(&Hit);
    if (Access == EW_EXECUTE && Hit.Action == 0 && Hit.WriteRax != 0 && Cpu->Regs != NULL) Cpu->Regs->rax = Hit.Rax;
    InterlockedDecrement(&C->CallbackActive);
    if (Hit.Action != 0) { InterlockedIncrement64(&C->Retries); return FALSE; }
    return TRUE;
}

BOOLEAN EptExecuteWatchBeginPhysicalWrite(UINT64 Address, UINT64 Size, PUINT64 Token)
{
    if (!Token) return FALSE; *Token = 0;
    if (g_ExecuteWatch == NULL || !VmxGetCurrentExecutionMode()) return TRUE;
    if (!Size || Size > PAGE_SIZE - (Address & (PAGE_SIZE - 1))) return FALSE;
    if (Address >= SIZE_512_GB) return TRUE; // 此后端不接受该范围的路径租约。
    EW_CONTEXT *C = EwEnter(); BOOLEAN Allowed = TRUE;
    if (C != NULL) {
        UINT64 Page = Address & ~(UINT64)(PAGE_SIZE - 1);
        Allowed = EwWriterBegin(C, Page, Token);
        if (Allowed && *Token != 0) {
            if (!EwLock(C)) Allowed = FALSE;
            else {
                BOOLEAN Watched = FALSE;
                for (UINT32 I = 0; I < C->MaximumPages; I++)
                    if (C->Pages[I].WriteReferences && C->Pages[I].Pa == Page) { Watched = TRUE; break; }
                EwUnlock(C);
                if (Watched) Allowed = EwCallback(C, &g_GuestState[PlatformCpuGetCurrentProcessorNumber()], Address, 3, Size);
            }
            if (!Allowed) { EwWriterEnd(C, *Token); *Token = 0; }
        }
    }
    EwLeave(); return Allowed;
}
VOID EptExecuteWatchEndPhysicalWrite(UINT64 Token)
{
    if (!Token) return;
    EW_CONTEXT *C = EwEnter(); if (C) EwWriterEnd(C, Token); EwLeave();
}

BOOLEAN EptExecuteWatchOnExit(VIRTUAL_MACHINE_STATE *Cpu)
{
    if (g_ExecuteWatch == NULL) return TRUE;
    EW_CONTEXT *C = EwEnter(); BOOLEAN Result = TRUE;
    if (C != NULL && Cpu->CoreId < C->Cpus && !Cpu->VmxoffState.IsVmxoffExecuted) {
        EW_CPU *L = &C->Cpu[Cpu->CoreId];
        L->Incoming = L->Installed;
        if (L->Installed) {
            EwWriteEptPointer(Cpu, C, Cpu->EptPointer.AsUInt);
            L->Installed = FALSE;
            if (!EwMergeAd(Cpu, L)) EwFault(C, STATUS_DEVICE_BUSY);
        }
        // EPT 边界与隐藏 INT3 回放可能仍属于同一条指令；其他退出不保留旧放行范围。
        if (Cpu->ExitReason != VMX_EXIT_REASON_EPT_VIOLATION && Cpu->ExitReason != VMX_EXIT_REASON_MONITOR_TRAP_FLAG &&
            Cpu->ExitReason != VMX_EXIT_REASON_EXCEPTION_OR_NMI) EwClearStep(C, L);
    }
    EwLeave(); return Result;
}

static BOOLEAN EwApply(VIRTUAL_MACHINE_STATE *Cpu, EW_CONTEXT *C, BOOLEAN Install)
{
    EW_CPU *L = &C->Cpu[Cpu->CoreId];
    if (g_ModeBasedExecutionControlState || g_ExecTrapInitialized || Cpu->PmlBufferAddress != NULL)
        EwFault(C, STATUS_NOT_SUPPORTED);
    UINT64 Rip = 0; VmxVmread64P(VMCS_GUEST_RIP, &Rip);
    if (L->StepCount != 0 && (L->StepRip != Rip || L->StepCr3 != GetGuestCr3())) EwClearStep(C, L);
    UINT32 PreviousCount = L->ViewCount;
    BOOLEAN Snapshot = EwSnapshot(C, L);
    // 取新快照遇到争用也必须按当前 primary 重建旧视图，不能执行已经退休的 fake PFN。
    if (C->Fault != STATUS_SUCCESS || C->Closing != 0) L->ViewCount = 0;
    if (PreviousCount == 0 && L->ViewCount == 0 && !L->Installed && !L->NeedsInvalidate) {
        if (Snapshot) InterlockedExchange64(&L->Acknowledged, (LONG64)L->ViewGeneration);
        return Snapshot;
    }
    if (L->ViewCount != 0) {
        BOOLEAN Stable = FALSE;
        for (UINT32 Attempt = 0; Attempt < 8; Attempt++)
            if (EwBuild(Cpu, L) && EwPrimaryStable(Cpu, L)) { Stable = TRUE; break; }
        if (!Stable) { EwFault(C, STATUS_RETRY); L->ViewCount = 0; return FALSE; }
    }
    if (EptInveptSingleContext(L->Pointer.AsUInt) != 0) { EwFault(C, STATUS_UNSUCCESSFUL); return FALSE; }
    L->NeedsInvalidate = FALSE;
    if (Install) {
        UINT64 Pointer = L->ViewCount != 0 ? L->Pointer.AsUInt : Cpu->EptPointer.AsUInt;
        EwWriteEptPointer(Cpu, C, Pointer);
        L->Installed = L->ViewCount != 0;
        if (L->Installed) L->NeedsInvalidate = TRUE;
    }
    if (Snapshot) InterlockedExchange64(&L->Acknowledged, (LONG64)L->ViewGeneration);
    return Snapshot;
}
VOID EptExecuteWatchBeforeResume(VIRTUAL_MACHINE_STATE *Cpu)
{
    if (g_ExecuteWatch == NULL) return;
    EW_CONTEXT *C = EwEnter();
    if (C != NULL && Cpu->CoreId < C->Cpus && !Cpu->VmxoffState.IsVmxoffExecuted) (VOID)EwApply(Cpu, C, TRUE);
    EwLeave();
}
BOOLEAN EptExecuteWatchMtf(VIRTUAL_MACHINE_STATE *Cpu)
{
    if (g_ExecuteWatch == NULL) return FALSE;
    EW_CONTEXT *C = EwEnter(); BOOLEAN Handled = FALSE;
    if (C != NULL && Cpu->CoreId < C->Cpus) {
        EW_CPU *L = &C->Cpu[Cpu->CoreId]; Handled = L->MtfPending; EwClearStep(C, L); L->MtfPending = FALSE;
    }
    EwLeave(); return Handled;
}

static BOOLEAN EwHasWriteWatch(EW_CONTEXT *C, UINT64 Page)
{
    for (UINT32 I = 0; I < C->MaximumPages; I++)
        if (InterlockedCompareExchange(&C->Pages[I].WriteReferences, 0, 0) != 0 && C->Pages[I].Pa == Page) return TRUE;
    return FALSE;
}
BOOLEAN EptExecuteWatchViolation(VIRTUAL_MACHINE_STATE *Cpu, UINT64 PhysicalAddress,
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION Q)
{
    if (g_ExecuteWatch == NULL) return FALSE;
    EW_CONTEXT *C = EwEnter(); BOOLEAN Handled = FALSE;
    if (C == NULL || Cpu->CoreId >= C->Cpus || (!Q.ExecuteAccess && !Q.WriteAccess)) goto Done;
    EW_CPU *L = &C->Cpu[Cpu->CoreId]; UINT64 Page = PhysicalAddress & ~(UINT64)(PAGE_SIZE - 1);
    UINT32 Access = Q.WriteAccess ? EW_WRITE : EW_EXECUTE, Incoming = 0;
    if (L->Incoming) for (UINT32 I = 0; I < L->ViewCount; I++)
        if (L->ViewPages[I] == Page) { Incoming = L->ViewAccess[I]; break; }
    // 新 W 租约还在 all-core ACK 时，也要处理 primary 先触发的写退出。
    if (!(Incoming & Access) && !(Access == EW_WRITE && EwHasWriteWatch(C, Page))) goto Done;
    BOOLEAN Large = FALSE; PEPT_PML1_ENTRY Leaf = EptGetPml1OrPml2Entry(Cpu->EptPageTable, Page, &Large);
    UINT64 Permission = Access == EW_EXECUTE ? 4u : 2u;
    BOOLEAN PrimaryAllows = Leaf != NULL && (Leaf->AsUInt & Permission) &&
        (Cpu->EptPageTable->PML4[0].AsUInt & Permission) &&
        (Cpu->EptPageTable->PML3[(Page >> 30) & 511].AsUInt & Permission) &&
        (Cpu->EptPageTable->PML2[(Page >> 30) & 511][(Page >> 21) & 511].AsUInt & Permission);
    if (Access == EW_EXECUTE && !PrimaryAllows) goto Done;
    Handled = TRUE; HvSuppressRipIncrement(Cpu);
    if (L->StepCount == 0 || L->StepRip != Cpu->LastVmexitRip || L->StepCr3 != GetGuestCr3()) {
        EwClearStep(C, L); L->StepRip = Cpu->LastVmexitRip; L->StepCr3 = GetGuestCr3();
    }
    UINT32 Step;
    for (Step = 0; Step < L->StepCount; Step++) if (L->StepPages[Step] == Page) break;
    if (Step == L->StepCount) {
        if (Step == EW_MAX_STEP) { EwFault(C, STATUS_INSUFFICIENT_RESOURCES); goto Done; }
        L->StepPages[Step] = Page; L->StepAccess[Step] = 0; L->StepWriters[Step] = 0; L->StepCount++;
    }
    if (Access == EW_WRITE && L->StepWriters[Step] == 0 &&
        !EwWriterBegin(C, Page, &L->StepWriters[Step])) { InterlockedIncrement64(&C->Retries); goto Done; }
    // 即使 callback 要求重试也保留 MTF 完成通知；若随后进入 fault/primary-only，
    // 首次实际执行仍会结束 writer 区间，不把未授写阶段留下的元数据永久占住。
    if (Access == EW_WRITE) { L->MtfPending = TRUE; HvSetMonitorTrapFlag(TRUE); }
    BOOLEAN Active = FALSE;
    if (Access == EW_WRITE || (GetGuestCs().Selector & 3u) == 3u) {
        if (!EwLock(C)) { InterlockedIncrement64(&C->Retries); goto Done; }
        for (UINT32 I = 0; I < C->MaximumPages; I++) if (C->Pages[I].Pa == Page &&
            (Access == EW_WRITE ? C->Pages[I].WriteReferences : C->Pages[I].ExecuteReferences)) { Active = TRUE; break; }
        EwUnlock(C);
    }
    // IDT 投递不代表被中断 RIP 已到达调用者；只放行投递，不消费返回帧。
    // 页表写仍必须先取消依赖帧，不能因投递阶段而跳过映射失效通知。
    BOOLEAN Observe = Access == EW_WRITE || !EventEptViolationIsVectoring();
    if (Active && Observe && !C->Closing && C->Fault == STATUS_SUCCESS && !EwCallback(C, Cpu, PhysicalAddress, Access, 0)) goto Done;
    L->StepAccess[Step] |= Access;
    L->MtfPending = TRUE; HvSetMonitorTrapFlag(TRUE);
    // 底层本来拒绝 W 时只做失效通知，不授权 W；交回原 hook/coherence 完成它的事务。
    if (Access == EW_WRITE && !PrimaryAllows) Handled = FALSE;
Done:
    EwLeave(); return Handled;
}

BOOLEAN EptExecuteWatchActive(VOID)
{ return InterlockedCompareExchangePointer((PVOID volatile *)&g_ExecuteWatch, NULL, NULL) != NULL; }

BOOLEAN EptExecuteWatchLegacyUnhookBegin(VOID)
{
    if (InterlockedCompareExchange(&g_ExecuteWatchControl, 1, 0) != 0) return FALSE;
    if (g_ExecuteWatch != NULL) { InterlockedExchange(&g_ExecuteWatchControl, 0); return FALSE; }
    return TRUE;
}
VOID EptExecuteWatchLegacyUnhookEnd(VOID) { InterlockedExchange(&g_ExecuteWatchControl, 0); }

IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchInitializeV1(UINT32 MaximumPages, UINT32 MaximumLeases, VMM_EXECUTE_WATCH_CALLBACK Callback)
{
    if (VmxGetCurrentExecutionMode() || !Callback || !MaximumPages || MaximumPages > EW_MAX_PAGES ||
        !MaximumLeases || MaximumLeases > EW_MAX_LEASES) return STATUS_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&g_ExecuteWatchControl, 1, 0) != 0) return STATUS_DEVICE_BUSY;
    NTSTATUS Status = STATUS_SUCCESS; EW_CONTEXT *C = NULL;
    if (g_ExecuteWatch != NULL) { Status = STATUS_ALREADY_REGISTERED; goto Done; }
    if (!g_GuestState || !g_NmiBroadcastingInitialized || g_ModeBasedExecutionControlState || g_ExecTrapInitialized) { Status = STATUS_NOT_SUPPORTED; goto Done; }
    UINT32 Cpus = PlatformCpuGetActiveProcessorCount();
    if (!Cpus || Cpus > EW_MAX_CPUS) { Status = STATUS_NOT_SUPPORTED; goto Done; }
    if (!MemoryMapperPrivatePtePagesReady(Cpus)) { Status = STATUS_INVALID_DEVICE_STATE; goto Done; }
    for (UINT32 I = 0; I < Cpus; I++) if (!g_GuestState[I].HasLaunched || !g_GuestState[I].EptPageTable || g_GuestState[I].PmlBufferAddress) { Status = STATUS_NOT_SUPPORTED; goto Done; }
    C = PlatformMemAllocateZeroedNonPagedPool(sizeof(*C));
    if (!C) { Status = STATUS_INSUFFICIENT_RESOURCES; goto Done; }
    C->MaximumPages = MaximumPages; C->MaximumLeases = MaximumLeases; C->Cpus = Cpus; C->Callback = Callback; C->Generation = 1;
    C->MaximumWriters = Cpus * (MaximumPages + 4u);
    C->Writers = PlatformMemAllocateZeroedNonPagedPool(sizeof(EW_WRITER) * C->MaximumWriters);
    if (!C->Writers) { Status = STATUS_INSUFFICIENT_RESOURCES; goto Done; }
    C->Cpu = PlatformMemAllocateZeroedNonPagedPool(sizeof(EW_CPU) * Cpus);
    if (!C->Cpu) { Status = STATUS_INSUFFICIENT_RESOURCES; goto Done; }
    for (UINT32 I = 0; I < Cpus; I++) {
        EW_CPU *L = &C->Cpu[I];
        if (!EwTableAllocate(&L->Pml4) || !EwTableAllocate(&L->Pml3)) { Status = STATUS_INSUFFICIENT_RESOURCES; goto Done; }
        for (UINT32 J = 0; J < MaximumPages; J++)
            if (!EwTableAllocate(&L->Pml2[J]) || !EwTableAllocate(&L->Pml1[J])) { Status = STATUS_INSUFFICIENT_RESOURCES; goto Done; }
        L->Pointer = g_GuestState[I].EptPointer; L->Pointer.PageFrameNumber = L->Pml4.Pa >> 12;
    }
    // 发布期间拒绝 acquire；DPC 屏障也排空在初始化之前已经进入的旧 root unhook 调用者。
    C->Closing = 1;
    InterlockedExchangePointer((PVOID volatile *)&g_ExecuteWatch, C);
    Status = ConfigureEptExecuteWatchSynchronizeV1();
    if (NT_SUCCESS(Status) && C->Fault != STATUS_SUCCESS) Status = (NTSTATUS)C->Fault;
    if (NT_SUCCESS(Status)) { InterlockedExchange(&C->Closing, 0); C = NULL; }
    else {
        InterlockedExchangePointer((PVOID volatile *)&g_ExecuteWatch, NULL);
        for (UINT32 I = 0; I < EW_SPINS && g_ExecuteWatchReaders != 0; I++) YieldProcessor();
        if (g_ExecuteWatchReaders != 0) { InterlockedExchangePointer((PVOID volatile *)&g_ExecuteWatch, C); C = NULL; }
    }
Done:
    EwFree(C); InterlockedExchange(&g_ExecuteWatchControl, 0); return Status;
}

static NTSTATUS EwAcquireFromRoot(UINT64 Page, PUINT64 Token, UINT32 Access)
{
    if (!Token) return STATUS_INVALID_PARAMETER; *Token = 0;
    if (!VmxGetCurrentExecutionMode() || (Page & (PAGE_SIZE - 1)) || Page >= SIZE_512_GB) return STATUS_INVALID_PARAMETER;
    EW_CONTEXT *C = EwEnter(); NTSTATUS Status = STATUS_SUCCESS;
    if (!C || C->Closing) { Status = STATUS_INVALID_DEVICE_STATE; goto Done; }
    if (PlatformCpuGetCurrentProcessorNumber() >= C->Cpus || PlatformCpuGetActiveProcessorCount() != C->Cpus)
    { Status = STATUS_NOT_SUPPORTED; goto Done; }
    VIRTUAL_MACHINE_STATE *Cpu = &g_GuestState[PlatformCpuGetCurrentProcessorNumber()];
    if (!Cpu->HasLaunched || Cpu->VmxoffState.IsVmxoffExecuted) { Status = STATUS_INVALID_DEVICE_STATE; goto Done; }
    if (C->Fault != STATUS_SUCCESS) { Status = (NTSTATUS)C->Fault; goto Done; }
    if (Access == EW_WRITE && MemoryMapperIsPrivatePtePage(Page)) { Status = STATUS_NOT_SUPPORTED; goto Done; }
    if (!EwLock(C)) { Status = STATUS_DEVICE_BUSY; goto Done; }
    if (C->Closing || C->Fault != STATUS_SUCCESS) {
        Status = C->Closing ? STATUS_INVALID_DEVICE_STATE : (NTSTATUS)C->Fault;
        EwUnlock(C); goto Done;
    }
    if (Access == EW_WRITE && EwWriterPresent(C, Page)) { EwUnlock(C); Status = STATUS_DEVICE_BUSY; goto Done; }
    UINT32 PageIndex, LeaseIndex;
    for (LeaseIndex = 0; LeaseIndex < C->MaximumLeases; LeaseIndex++) if (!C->Leases[LeaseIndex].Token) break;
    for (PageIndex = 0; PageIndex < C->MaximumPages; PageIndex++) if (C->Pages[PageIndex].References && C->Pages[PageIndex].Pa == Page) break;
    if (PageIndex == C->MaximumPages) {
        UINT64 Minimum = EwMinimumAck(C);
        for (PageIndex = 0; PageIndex < C->MaximumPages; PageIndex++)
            if (!C->Pages[PageIndex].References && C->Pages[PageIndex].RetiredAt <= Minimum) break;
    }
    if (LeaseIndex == C->MaximumLeases || PageIndex == C->MaximumPages) {
        InterlockedIncrement64(&C->CapacityFailures); EwUnlock(C); Status = STATUS_INSUFFICIENT_RESOURCES; goto Done;
    }
    UINT64 Serial = (UINT64)InterlockedIncrement64(&C->Serial);
    if (Serial > 0x7fffffffffffULL) { EwUnlock(C); Status = STATUS_INSUFFICIENT_RESOURCES; goto Done; }
    C->Leases[LeaseIndex].Token = (Serial << 16) | (LeaseIndex + 1u); C->Leases[LeaseIndex].Page = PageIndex; C->Leases[LeaseIndex].Access = Access;
    *Token = C->Leases[LeaseIndex].Token;
    BOOLEAN NewPage = C->Pages[PageIndex].References == 0;
    if (NewPage) { C->ActivePages++; C->Pages[PageIndex].Pa = Page; }
    C->Pages[PageIndex].References++;
    BOOLEAN NewAccess = Access == EW_WRITE ? InterlockedIncrement(&C->Pages[PageIndex].WriteReferences) == 1 : C->Pages[PageIndex].ExecuteReferences++ == 0;
    if (NewAccess) {
        C->Pages[PageIndex].PublishedAt = (UINT64)InterlockedIncrement64(&C->Generation);
    }
    C->ActiveLeases++;
    UINT64 Generation = C->Pages[PageIndex].PublishedAt; EwUnlock(C);
    if (EwMinimumAck(C) >= Generation) {
        if (C->Fault != STATUS_SUCCESS) Status = (NTSTATUS)C->Fault;
        goto Done;
    }
    (VOID)EwApply(Cpu, C, FALSE); EwKick(C);
    for (UINT32 I = 0; I < EW_SPINS && EwMinimumAck(C) < Generation && C->Fault == STATUS_SUCCESS; I++) YieldProcessor();
    if (C->Fault != STATUS_SUCCESS) Status = (NTSTATUS)C->Fault;
    else if (EwMinimumAck(C) < Generation) { InterlockedIncrement64(&C->SynchronizationFailures); Status = STATUS_IO_TIMEOUT; }
Done:
    EwLeave(); return Status;
}
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchAcquireFromRootV1(UINT64 Page, PUINT64 Token)
{ return EwAcquireFromRoot(Page, Token, EW_EXECUTE); }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptWriteWatchAcquireFromRootV1(UINT64 Page, PUINT64 Token)
{ return EwAcquireFromRoot(Page, Token, EW_WRITE); }

IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchReleaseV1(UINT64 Token)
{
    EW_CONTEXT *C = EwEnter(); NTSTATUS Status = STATUS_SUCCESS;
    if (!C || !Token) { Status = STATUS_NOT_FOUND; goto Done; }
    UINT32 Index = (UINT32)(Token & 0xffffu);
    if (!Index || --Index >= C->MaximumLeases) { Status = STATUS_NOT_FOUND; goto Done; }
    if (!EwLock(C)) { Status = STATUS_DEVICE_BUSY; goto Done; }
    if (C->Leases[Index].Token != Token) { EwUnlock(C); Status = STATUS_NOT_FOUND; goto Done; }
    EW_PAGE *P = &C->Pages[C->Leases[Index].Page]; UINT32 Access = C->Leases[Index].Access;
    C->Leases[Index].Token = 0; C->ActiveLeases--;
    BOOLEAN Changed = Access == EW_WRITE ? InterlockedDecrement(&P->WriteReferences) == 0 : --P->ExecuteReferences == 0;
    BOOLEAN Retired = --P->References == 0;
    UINT64 Generation = Changed ? (UINT64)InterlockedIncrement64(&C->Generation) : EwGeneration(C);
    if (Retired) { C->ActivePages--; P->RetiredAt = Generation; }
    EwUnlock(C); if (Changed) EwKick(C);
Done:
    EwLeave(); return Status;
}

static VOID EwDpc(KDPC *Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc); UNREFERENCED_PARAMETER(Context);
    UINT32 Core = PlatformCpuGetCurrentProcessorNumber();
    (VOID)AsmVmxVmcall(VMCALL_INVEPT_SINGLE_CONTEXT, g_GuestState[Core].EptPointer.AsUInt, 0, 0);
    PlatformBroadcastSynchronizeEndOfRoutine(Arg1, Arg2);
}
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchSynchronizeV1(VOID)
{
    if (VmxGetCurrentExecutionMode()) return STATUS_INVALID_DEVICE_STATE;
    EW_CONTEXT *C = EwEnter(); NTSTATUS Status = STATUS_SUCCESS;
    if (!C) goto Done;
    UINT64 Generation = EwGeneration(C);
    PlatformDpcGenericCall(EwDpc, NULL);
    if (EwMinimumAck(C) < Generation) Status = STATUS_DEVICE_BUSY;
    else if (C->Fault != STATUS_SUCCESS && C->Closing == 0) Status = (NTSTATUS)C->Fault;
Done:
    EwLeave(); return Status;
}
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchUninitializeV1(VOID)
{
    if (VmxGetCurrentExecutionMode()) return STATUS_INVALID_DEVICE_STATE;
    if (InterlockedCompareExchange(&g_ExecuteWatchControl, 1, 0) != 0) return STATUS_DEVICE_BUSY;
    EW_CONTEXT *C = g_ExecuteWatch; NTSTATUS Status = STATUS_SUCCESS;
    if (!C) goto Done;
    if (!EwLock(C)) { Status = STATUS_DEVICE_BUSY; goto Done; }
    if (C->ActiveLeases || C->CallbackActive || C->ActiveWriters) { EwUnlock(C); Status = STATUS_DEVICE_BUSY; goto Done; }
    InterlockedExchange(&C->Closing, 1); InterlockedIncrement64(&C->Generation); EwUnlock(C);
    Status = ConfigureEptExecuteWatchSynchronizeV1();
    if (!NT_SUCCESS(Status)) goto Done;
    for (UINT32 I = 0; I < C->Cpus; I++)
        if (C->Cpu[I].Installed || C->Cpu[I].MtfPending || C->Cpu[I].NeedsInvalidate) { Status = STATUS_DEVICE_BUSY; goto Done; }
    InterlockedExchangePointer((PVOID volatile *)&g_ExecuteWatch, NULL);
    for (UINT32 I = 0; I < EW_SPINS && g_ExecuteWatchReaders != 0; I++) YieldProcessor();
    if (g_ExecuteWatchReaders != 0) {
        InterlockedExchangePointer((PVOID volatile *)&g_ExecuteWatch, C); Status = STATUS_DEVICE_BUSY; goto Done;
    }
    EwFree(C);
Done:
    InterlockedExchange(&g_ExecuteWatchControl, 0); return Status;
}
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchQueryV1(VMM_EXECUTE_WATCH_STATUS *S)
{
    if (!S || S->Size != sizeof(*S)) return STATUS_INVALID_PARAMETER;
    EW_CONTEXT *C = EwEnter(); NTSTATUS Status = STATUS_SUCCESS; RtlZeroMemory(S, sizeof(*S)); S->Size = sizeof(*S);
    if (!C) goto Done;
    if (!EwLock(C)) { Status = STATUS_DEVICE_BUSY; goto Done; }
    S->Initialized = 1; S->Closing = C->Closing; S->MaximumPages = C->MaximumPages; S->MaximumLeases = C->MaximumLeases;
    S->ActivePages = C->ActivePages; S->ActiveLeases = C->ActiveLeases; S->CallbackActive = C->CallbackActive;
    S->ActiveWriters = (UINT32)InterlockedCompareExchange(&C->ActiveWriters, 0, 0);
    S->Generation = EwGeneration(C); S->MinimumAcknowledged = EwMinimumAck(C);
    S->Observations = C->Observations; S->Retries = C->Retries; S->CapacityFailures = C->CapacityFailures; S->SynchronizationFailures = C->SynchronizationFailures;
    EwUnlock(C);
    if (C->Fault != STATUS_SUCCESS) Status = (NTSTATUS)C->Fault;
Done:
    EwLeave(); return Status;
}

#else
// 此后端的准备/退出证明目前限于 Windows；其他宿主保持原 EPT 路径并明确报告未实现。
BOOLEAN EptExecuteWatchOnExit(VIRTUAL_MACHINE_STATE *Cpu) { UNREFERENCED_PARAMETER(Cpu); return TRUE; }
VOID EptExecuteWatchBeforeResume(VIRTUAL_MACHINE_STATE *Cpu) { UNREFERENCED_PARAMETER(Cpu); }
BOOLEAN EptExecuteWatchViolation(VIRTUAL_MACHINE_STATE *Cpu, UINT64 Address, VMX_EXIT_QUALIFICATION_EPT_VIOLATION Q)
{ UNREFERENCED_PARAMETER(Cpu); UNREFERENCED_PARAMETER(Address); UNREFERENCED_PARAMETER(Q); return FALSE; }
BOOLEAN EptExecuteWatchMtf(VIRTUAL_MACHINE_STATE *Cpu) { UNREFERENCED_PARAMETER(Cpu); return FALSE; }
BOOLEAN EptExecuteWatchActive(VOID) { return FALSE; }
BOOLEAN EptExecuteWatchLegacyUnhookBegin(VOID) { return TRUE; }
VOID EptExecuteWatchLegacyUnhookEnd(VOID) { }
BOOLEAN EptExecuteWatchBeginPhysicalWrite(UINT64 Address, UINT64 Size, PUINT64 Token)
{ UNREFERENCED_PARAMETER(Address); UNREFERENCED_PARAMETER(Size); if (Token) *Token = 0; return TRUE; }
VOID EptExecuteWatchEndPhysicalWrite(UINT64 Token) { UNREFERENCED_PARAMETER(Token); }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchInitializeV1(UINT32 Pages, UINT32 Leases, VMM_EXECUTE_WATCH_CALLBACK Callback)
{ UNREFERENCED_PARAMETER(Pages); UNREFERENCED_PARAMETER(Leases); UNREFERENCED_PARAMETER(Callback); return STATUS_NOT_SUPPORTED; }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchAcquireFromRootV1(UINT64 Page, PUINT64 Token)
{ UNREFERENCED_PARAMETER(Page); if (Token) *Token = 0; return STATUS_NOT_SUPPORTED; }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptWriteWatchAcquireFromRootV1(UINT64 Page, PUINT64 Token)
{ UNREFERENCED_PARAMETER(Page); if (Token) *Token = 0; return STATUS_NOT_SUPPORTED; }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchReleaseV1(UINT64 Token) { UNREFERENCED_PARAMETER(Token); return STATUS_NOT_SUPPORTED; }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchSynchronizeV1(VOID) { return STATUS_SUCCESS; }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchUninitializeV1(VOID) { return STATUS_SUCCESS; }
IMPORT_EXPORT_VMM NTSTATUS ConfigureEptExecuteWatchQueryV1(VMM_EXECUTE_WATCH_STATUS *S)
{ UNREFERENCED_PARAMETER(S); return STATUS_NOT_SUPPORTED; }
#endif
