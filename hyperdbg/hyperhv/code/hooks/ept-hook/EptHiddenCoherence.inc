// [DOWNSTREAM] 串行隐藏页写事务；NMI 仅唤醒，确认发生在完整 VM-exit 尾部。
#define EPT_COH_MAX_PAGES 257u
#define EPT_COH_MAX_GUEST_PAGES 32u
#define EPT_COH_MAX_CPUS 256u
#define EPT_COH_QUIESCE 1
#define EPT_COH_WRITING 2
#define EPT_COH_RESUME 3
#define EPT_COH_FAULT 4
#define EPT_COH_RETIRED 5
#define EPT_COH_GUEST 1u
#define EPT_COH_ROOT 2u
#define EPT_COH_CONTROL 3u
static struct {
    volatile LONG64 Gate, Serial, RoundSerial, State, Published;
    volatile LONG ControlHeld, OwnerHeld;
    LONG64 ControlToken;
    UINT32 Kind, Owner, Count, Cpus, WaitExits;
    UINT64 Rip, Cr3, Cr4, Va, Length;
    BOOLEAN RootActive, WriteAttempted, RestoreOriginal;
    EPT_HOOKED_PAGE_DETAIL *Pages[EPT_COH_MAX_PAGES];
    volatile LONG64 Ack[EPT_COH_MAX_CPUS];
} g_HiddenCoherence;
static UINT64 EptCoherenceState(VOID)
{ return (UINT64)CpuInterlockedCompareExchange64(&g_HiddenCoherence.State,0,0); }
static LONG EptCoherenceCurrentPhase(VOID)
{ return (LONG)(EptCoherenceState() & 7u); }
static VOID EptCoherencePhase(LONG Phase)
{
    UINT64 Serial=(UINT64)CpuInterlockedIncrement64(&g_HiddenCoherence.RoundSerial);
    CpuInterlockedExchange64(&g_HiddenCoherence.State,(LONG64)((Serial<<3)|(UINT32)Phase));
}
static BOOLEAN EptCoherenceAllAck(UINT64 State)
{
    for(UINT32 i=0;i<g_HiddenCoherence.Cpus;i++)
        if((UINT64)CpuInterlockedCompareExchange64(&g_HiddenCoherence.Ack[i],0,0)!=State)return FALSE;
    return TRUE;
}
static BOOLEAN EptCoherenceContains(EPT_HOOKED_PAGE_DETAIL *Page)
{
    for(UINT32 i=0;i<g_HiddenCoherence.Count;i++)if(g_HiddenCoherence.Pages[i]==Page)return TRUE;
    return FALSE;
}
static BOOLEAN EptCoherenceAdd(EPT_HOOKED_PAGE_DETAIL *Page)
{
    if(Page==NULL||EptCoherenceContains(Page))return TRUE;
    if(!Page->IsHiddenBreakpoint||Page->CoherenceFault||g_HiddenCoherence.Count==(g_HiddenCoherence.Kind==EPT_COH_GUEST?EPT_COH_MAX_GUEST_PAGES:EPT_COH_MAX_PAGES))return FALSE;
    g_HiddenCoherence.Pages[g_HiddenCoherence.Count++]=Page;return TRUE;
}
static VOID EptCoherenceKick(VIRTUAL_MACHINE_STATE *Cpu)
{
    for(UINT32 i=0;i<g_HiddenCoherence.Cpus;i++)if(i!=Cpu->CoreId)
    { CpuInterlockedExchange(&g_GuestState[i].HiddenCoherenceKick,1);VmxBroadcastKickCpu(&g_GuestState[i]); }
}
static EPT_PML1_ENTRY EptCoherenceDenied(EPT_HOOKED_PAGE_DETAIL *Page)
{
    EPT_PML1_ENTRY Entry=Page->OriginalEntry;
    Entry.ReadAccess=1;Entry.WriteAccess=0;Entry.ExecuteAccess=0;return Entry;
}
BOOLEAN EptCoherenceApply(VIRTUAL_MACHINE_STATE *Cpu)
{
    const LONG64 Gate=CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,0);
    UINT64 State=EptCoherenceState();LONG Phase=(LONG)(State&7u);
    if(Gate==0||g_HiddenCoherence.Published!=Gate||Phase==0||Phase==EPT_COH_WRITING)return TRUE;
    if(Cpu->CoreId>=g_HiddenCoherence.Cpus)return FALSE;
    if((UINT64)CpuInterlockedCompareExchange64(&g_HiddenCoherence.Ack[Cpu->CoreId],0,0)!=State)
    {
        for(UINT32 i=0;i<g_HiddenCoherence.Count;i++)
        {
            EPT_HOOKED_PAGE_DETAIL *Page=g_HiddenCoherence.Pages[i];
            PEPT_PML1_ENTRY Pte=EptGetPml1Entry(Cpu->EptPageTable,Page->PhysicalBaseAddress);
            if(Pte==NULL)return FALSE;
            EPT_PML1_ENTRY Entry=Page->ChangedEntry;
            if(Phase==EPT_COH_QUIESCE||Phase==EPT_COH_FAULT)Entry=EptCoherenceDenied(Page);
            else if(Phase==EPT_COH_RETIRED||g_HiddenCoherence.RestoreOriginal)
            { EptHookRetireMtfRestorePointForUnhook(Cpu,Page->PhysicalBaseAddress,FALSE);Entry=Page->OriginalEntry; }
            else if(Cpu->MtfEptHookRestorePoint==Page)
            { Entry=Page->OriginalEntry;Entry.WriteAccess=0; }
            Pte->AsUInt=Entry.AsUInt;
        }
        if(EptInveptSingleContext(Cpu->EptPointer.AsUInt)!=0)return FALSE;
        if(g_HiddenCoherence.Gate!=Gate||EptCoherenceState()!=State||g_HiddenCoherence.Published!=Gate)return FALSE;
        CpuInterlockedExchange64(&g_HiddenCoherence.Ack[Cpu->CoreId],(LONG64)State);
    }
    // 故障先全核撤销执行，再开放 original；不允许一核可写原页而另一核仍执行 fake。
    if(Phase==EPT_COH_FAULT&&g_HiddenCoherence.Gate==Gate&&EptCoherenceAllAck(State))
    {
        UINT64 Next=((UINT64)CpuInterlockedIncrement64(&g_HiddenCoherence.RoundSerial)<<3)|EPT_COH_RETIRED;
        if((UINT64)CpuInterlockedCompareExchange64(&g_HiddenCoherence.State,(LONG64)Next,(LONG64)State)==State)
        { (VOID)EptCoherenceApply(Cpu);EptCoherenceKick(Cpu); }
        return TRUE;
    }
    // 确认后不再解引用页；token 避免旧轮清掉下一事务。
    if((Phase==EPT_COH_RESUME||Phase==EPT_COH_RETIRED)&&g_HiddenCoherence.Gate==Gate&&
       EptCoherenceState()==State&&EptCoherenceAllAck(State)&&!g_HiddenCoherence.ControlHeld&&!g_HiddenCoherence.OwnerHeld)
        CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,Gate);
    return TRUE;
}
static VOID EptCoherencePublish(VIRTUAL_MACHINE_STATE *Cpu,LONG Phase)
{
    EptCoherencePhase(Phase);
    CpuInterlockedExchange64(&g_HiddenCoherence.Published,g_HiddenCoherence.Gate);
    (VOID)EptCoherenceApply(Cpu);EptCoherenceKick(Cpu);
}
static VOID EptCoherenceFault(VIRTUAL_MACHINE_STATE *Cpu,NTSTATUS Status)
{
    for(UINT32 i=0;i<g_HiddenCoherence.Count;i++)
    {
        g_HiddenCoherence.Pages[i]->CoherenceFaultEpoch=(UINT64)g_HiddenCoherence.Gate;
        CpuInterlockedExchange(&g_HiddenCoherence.Pages[i]->CoherenceFault,Status);
    }
    g_HiddenCoherence.RootActive=FALSE;
    EptCoherencePublish(Cpu,EPT_COH_FAULT);
    CpuInterlockedExchange(&g_HiddenCoherence.OwnerHeld,0);
    (VOID)EptCoherenceApply(Cpu);
}
// 恢复未确认也必须可见；不让正常 RESUME 无限保留而仍被查询为 armed。
static BOOLEAN EptCoherenceResume(VIRTUAL_MACHINE_STATE *Cpu)
{
    LONG64 Token=g_HiddenCoherence.Gate;
    EptCoherencePublish(Cpu,EPT_COH_RESUME);UINT64 State=EptCoherenceState();
    for(UINT32 i=0;i<65536&&!EptCoherenceAllAck(State);i++)YieldProcessor();
    if(!EptCoherenceAllAck(State)){EptCoherenceFault(Cpu,STATUS_IO_TIMEOUT);return FALSE;}
    // owner 结束访问全局页数组后才释放 gate，避免另一 CPU 下一代事务覆盖状态。
    CpuInterlockedExchange(&g_HiddenCoherence.OwnerHeld,0);
    CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,Token);return TRUE;
}
static BOOLEAN EptCoherenceRefresh(VOID)
{
    for(UINT32 i=0;i<g_HiddenCoherence.Count;i++)
        if(!EptHookRefreshExecutionFakePage(g_HiddenCoherence.Pages[i]))return FALSE;
    return TRUE;
}
static BOOLEAN EptCoherenceRevokeOwner(VIRTUAL_MACHINE_STATE *Cpu)
{
    for(UINT32 i=0;i<g_HiddenCoherence.Count;i++)
    {
        EPT_HOOKED_PAGE_DETAIL *Page=g_HiddenCoherence.Pages[i];
        PEPT_PML1_ENTRY Pte=EptGetPml1Entry(Cpu->EptPageTable,Page->PhysicalBaseAddress);
        if(Pte==NULL)return FALSE;
        Pte->AsUInt=EptCoherenceDenied(Page).AsUInt;
    }
    return EptInveptSingleContext(Cpu->EptPointer.AsUInt)==0;
}
// 真实 MTF 完成与临时 quiesce 分开：先消费回放身份，再重新应用执行视图。
BOOLEAN EptCoherenceFinishMtf(VIRTUAL_MACHINE_STATE *Cpu)
{
    if(g_HiddenCoherence.Gate==0||g_HiddenCoherence.Published!=g_HiddenCoherence.Gate)return FALSE;
    if(g_HiddenCoherence.Kind==EPT_COH_GUEST&&g_HiddenCoherence.Owner==Cpu->CoreId&&
       EptCoherenceCurrentPhase()==EPT_COH_WRITING)
    {
        Cpu->MtfEptHookRestorePoint=NULL;
        if(!EptCoherenceRevokeOwner(Cpu)||!EptCoherenceRefresh())EptCoherenceFault(Cpu,STATUS_UNSUCCESSFUL);
        else (VOID)EptCoherenceResume(Cpu);
        return TRUE;
    }
    if(Cpu->MtfEptHookRestorePoint!=NULL&&EptCoherenceContains(Cpu->MtfEptHookRestorePoint))
    {
        EPT_HOOKED_PAGE_DETAIL *Completed=Cpu->MtfEptHookRestorePoint;
        Cpu->MtfEptHookRestorePoint=NULL;
        CpuInterlockedExchange64(&g_HiddenCoherence.Ack[Cpu->CoreId],0);
        // owner 可在已观察到旧 Ack 后关闭 gate。本次 MTF 必须独立恢复本核，
        // 不能让 Apply(Gate==0) 的空操作把 original 执行映射遗留到下一次命中。
        LONG64 Current=CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,0);
        LONG Phase=EptCoherenceCurrentPhase();
        EPT_PML1_ENTRY Entry=Completed->CoherenceFault?Completed->OriginalEntry:Completed->ChangedEntry;
        BOOLEAN Denied=FALSE;
        if(Current!=0&&g_HiddenCoherence.Published==Current&&EptCoherenceContains(Completed))
        {
            if(Phase==EPT_COH_QUIESCE||Phase==EPT_COH_WRITING||Phase==EPT_COH_FAULT)
                {Entry=EptCoherenceDenied(Completed);Denied=TRUE;}
            else if(Phase==EPT_COH_RESUME&&!g_HiddenCoherence.RestoreOriginal)
                Entry=Completed->ChangedEntry;
        }
        PEPT_PML1_ENTRY Pte=EptGetPml1Entry(Cpu->EptPageTable,Completed->PhysicalBaseAddress);
        if(Pte==NULL)
        {LogError("Err, completed MTF has no EPT leaf; retaining coherence without granting execution");return TRUE;}
        Pte->AsUInt=Entry.AsUInt;
        if(EptInveptSingleContext(Cpu->EptPointer.AsUInt)!=0)
        {
            // 封锁/退休阶段不能落到旧 handler 将 fake 重新设为可执行。
            if(Denied||Completed->CoherenceFault){(VOID)EptCoherenceApply(Cpu);return TRUE;}
            Cpu->MtfEptHookRestorePoint=Completed;return FALSE;
        }
        (VOID)EptCoherenceApply(Cpu);return TRUE;
    }
    return FALSE;
}
// 异常/调度/非预期 VM-exit 不能遗留等待特定 RIP 的事务。已有部分写按实际原页刷新。
VOID EptCoherenceOnExit(VIRTUAL_MACHINE_STATE *Cpu)
{
    if(g_HiddenCoherence.Gate<=0||g_HiddenCoherence.Published!=g_HiddenCoherence.Gate||
       g_HiddenCoherence.Kind!=EPT_COH_GUEST||g_HiddenCoherence.Owner!=Cpu->CoreId)return;
    LONG Phase=EptCoherenceCurrentPhase();
    if(Phase!=EPT_COH_QUIESCE&&Phase!=EPT_COH_WRITING)return;
    if((Cpu->ExitReason==VMX_EXIT_REASON_EPT_VIOLATION&&Cpu->LastVmexitRip==g_HiddenCoherence.Rip&&
        GetGuestCr3()==g_HiddenCoherence.Cr3)||Cpu->ExitReason==VMX_EXIT_REASON_MONITOR_TRAP_FLAG)return;
    // 取消不自动执行原指令；后续 guest 自身重试会重新触发写事务。
    if(Cpu->MtfEptHookRestorePoint&&EptCoherenceContains(Cpu->MtfEptHookRestorePoint))
        EptHookRetireMtfRestorePointForUnhook(Cpu,0,TRUE);
    (VOID)EptCoherenceRevokeOwner(Cpu);
    EptCoherenceFault(Cpu,STATUS_CANCELLED);
}
VOID EptCoherenceSafePoint(VIRTUAL_MACHINE_STATE *Cpu)
{ if(!Cpu->VmxoffState.IsVmxoffExecuted)(VOID)EptCoherenceApply(Cpu); }
static VOID EptCoherenceDpc(PKDPC Dpc,PVOID Context,PVOID A,PVOID B)
{
    UNREFERENCED_PARAMETER(Dpc);
    if(AsmVmxVmcall(VMCALL_HIDDEN_COHERENCE_APPLY,0,0,0)!=STATUS_SUCCESS)
        CpuInterlockedExchange((volatile LONG*)Context,1);
    PlatformBroadcastSynchronizeEndOfRoutine(A,B);
}
static BOOLEAN EptCoherenceDpcRound(VOID)
{
    volatile LONG Failed=0;UINT64 Before=EptCoherenceState();
    PlatformDpcGenericCall(EptCoherenceDpc,(PVOID)&Failed);
    // FAULT 的最后一次确认会发布 RETIRED，后者也必须由完整 DPC 轮确认。
    if(!Failed&&Before!=EptCoherenceState())PlatformDpcGenericCall(EptCoherenceDpc,(PVOID)&Failed);
    return Failed==0&&EptCoherenceAllAck(EptCoherenceState());
}
BOOLEAN EptCoherenceControlEnter(VOID)
{
    LONG64 Old=CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,0);
    LONG64 Token=-CpuInterlockedIncrement64(&g_HiddenCoherence.Serial);
    if(Token>=0)return FALSE;
    // 仅接管已停止写入的恢复轮。活动 root/guest 写不能被控制面抢占。
    if(Old!=0&&(g_HiddenCoherence.ControlHeld||g_HiddenCoherence.OwnerHeld||
       (EptCoherenceCurrentPhase()!=EPT_COH_RESUME&&EptCoherenceCurrentPhase()!=EPT_COH_FAULT&&EptCoherenceCurrentPhase()!=EPT_COH_RETIRED)))return FALSE;
    if(CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,Token,Old)!=Old)return FALSE;
    g_HiddenCoherence.ControlToken=Token;CpuInterlockedExchange(&g_HiddenCoherence.ControlHeld,1);
    if(Old!=0)
    {
        CpuInterlockedExchange64(&g_HiddenCoherence.Published,Token);
        if(!EptCoherenceDpcRound())
        {CpuInterlockedExchange(&g_HiddenCoherence.ControlHeld,0);return FALSE;}
    }
    g_HiddenCoherence.Kind=EPT_COH_CONTROL;g_HiddenCoherence.Count=0;EptCoherencePhase(0);return TRUE;
}
VOID EptCoherenceControlLeave(VOID)
{
    LONG64 Token=g_HiddenCoherence.ControlToken;
    CpuInterlockedExchange(&g_HiddenCoherence.ControlHeld,0);
    LONG Phase=EptCoherenceCurrentPhase();
    if(Phase==0||((Phase==EPT_COH_RESUME||Phase==EPT_COH_RETIRED)&&EptCoherenceAllAck(EptCoherenceState())))
        CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,Token);
}
static BOOLEAN EptCoherenceControlBegin(EPT_HOOKED_PAGE_DETAIL *Page)
{
    if(g_HiddenCoherence.Gate>=0||!g_HiddenCoherence.ControlHeld||VmxGetCurrentExecutionMode())return FALSE;
    g_HiddenCoherence.Kind=EPT_COH_CONTROL;g_HiddenCoherence.Owner=~(UINT32)0;
    g_HiddenCoherence.Cpus=PlatformCpuGetActiveProcessorCount();
    if(!g_HiddenCoherence.Cpus||g_HiddenCoherence.Cpus>EPT_COH_MAX_CPUS)return FALSE;
    g_HiddenCoherence.Count=1;g_HiddenCoherence.Pages[0]=Page;
    g_HiddenCoherence.RestoreOriginal=Page->CoherenceFault!=0;
    EptCoherencePhase(EPT_COH_QUIESCE);CpuInterlockedExchange64(&g_HiddenCoherence.Published,g_HiddenCoherence.Gate);
    if(EptCoherenceDpcRound())return TRUE;
    // 未修改 fake 内容。失败仍发布恢复轮，保留资源供下次 checked 接管。
    EptCoherencePhase(EPT_COH_RESUME);(VOID)EptCoherenceDpcRound();return FALSE;
}
static BOOLEAN EptCoherenceControlEnd(VOID)
{
    EptCoherencePhase(EPT_COH_RESUME);
    if(!EptCoherenceDpcRound())
    {
        for(UINT32 i=0;i<g_HiddenCoherence.Count;i++)
        {
            g_HiddenCoherence.Pages[i]->CoherenceFaultEpoch=(UINT64)g_HiddenCoherence.Gate;
            CpuInterlockedExchange(&g_HiddenCoherence.Pages[i]->CoherenceFault,STATUS_UNSUCCESSFUL);
        }
        EptCoherencePhase(EPT_COH_FAULT);(VOID)EptCoherenceDpcRound();return FALSE;
    }
    EptCoherencePhase(0);return TRUE;
}
static BOOLEAN EptCoherenceClaim(VIRTUAL_MACHINE_STATE *Cpu,UINT32 Kind)
{
    if(!g_NmiBroadcastingInitialized)return FALSE;
    UINT32 Cpus=PlatformCpuGetActiveProcessorCount();
    if(!Cpus||Cpus>EPT_COH_MAX_CPUS)return FALSE;
    LONG64 Token=CpuInterlockedIncrement64(&g_HiddenCoherence.Serial);
    if(Token<=0||CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,Token,0)!=0)return FALSE;
    CpuInterlockedExchange(&g_HiddenCoherence.OwnerHeld,1);
    g_HiddenCoherence.Kind=Kind;g_HiddenCoherence.Owner=Cpu->CoreId;g_HiddenCoherence.Cpus=Cpus;
    g_HiddenCoherence.Count=0;g_HiddenCoherence.WaitExits=0;g_HiddenCoherence.RootActive=FALSE;g_HiddenCoherence.WriteAttempted=FALSE;g_HiddenCoherence.RestoreOriginal=FALSE;
    g_HiddenCoherence.Rip=Cpu->LastVmexitRip;g_HiddenCoherence.Cr3=GetGuestCr3();g_HiddenCoherence.Cr4=GetGuestCr4();
    return TRUE;
}
BOOLEAN EptCoherenceViolation(VIRTUAL_MACHINE_STATE *Cpu,EPT_HOOKED_PAGE_DETAIL *Page,
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION Qualification)
{
    if(!Page->IsHiddenBreakpoint)return FALSE;
    if(Page->CoherenceFault&&g_HiddenCoherence.Gate!=0&&g_HiddenCoherence.Published==g_HiddenCoherence.Gate&&
       EptCoherenceContains(Page)&&EptCoherenceCurrentPhase()!=EPT_COH_RETIRED)
    {HvSuppressRipIncrement(Cpu);return TRUE;}
    if(Page->CoherenceFault)
    {
        PEPT_PML1_ENTRY Pte=EptGetPml1Entry(Cpu->EptPageTable,Page->PhysicalBaseAddress);
        if(Pte){Pte->AsUInt=Page->OriginalEntry.AsUInt;(VOID)EptInveptSingleContext(Cpu->EptPointer.AsUInt);}
        HvSuppressRipIncrement(Cpu);return TRUE;
    }
    LONG64 Gate=CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,0);
    if(Gate==0)
    {
        if(!Qualification.WriteAccess)return FALSE;
        if(!EptCoherenceClaim(Cpu,EPT_COH_GUEST))goto Retry;
        if(!EptCoherenceAdd(Page)||!EptCoherenceAdd(Cpu->MtfEptHookRestorePoint))
        {EptCoherenceFault(Cpu,STATUS_CONFLICTING_ADDRESSES);goto Retry;}
        EptCoherencePublish(Cpu,EPT_COH_QUIESCE);
    }
    else if(g_HiddenCoherence.Published!=Gate)
    {if(!Qualification.WriteAccess)return FALSE;goto Retry;}
    else if(g_HiddenCoherence.Kind==EPT_COH_GUEST&&g_HiddenCoherence.Owner==Cpu->CoreId&&
            EptCoherenceCurrentPhase()==EPT_COH_WRITING&&!EptCoherenceContains(Page))
    {
        if(!EptCoherenceAdd(Page)){EptCoherenceFault(Cpu,STATUS_INSUFFICIENT_RESOURCES);goto Retry;}
        EptCoherencePublish(Cpu,EPT_COH_QUIESCE);
    }
    else if(!EptCoherenceContains(Page)){if(!Qualification.WriteAccess)return FALSE;goto Retry;}
    if(EptCoherenceCurrentPhase()==EPT_COH_QUIESCE&&g_HiddenCoherence.Kind==EPT_COH_GUEST&&
       g_HiddenCoherence.Owner==Cpu->CoreId&&!EptCoherenceAllAck(EptCoherenceState())&&++g_HiddenCoherence.WaitExits>=4096)
    {EptCoherenceFault(Cpu,STATUS_IO_TIMEOUT);goto Retry;}
    if(EptCoherenceCurrentPhase()==EPT_COH_QUIESCE&&g_HiddenCoherence.Kind==EPT_COH_GUEST&&
       g_HiddenCoherence.Owner==Cpu->CoreId&&EptCoherenceAllAck(EptCoherenceState())&&
       Cpu->LastVmexitRip==g_HiddenCoherence.Rip&&GetGuestCr3()==g_HiddenCoherence.Cr3)
    {
        // 先准备完成路径，再授写。原有回放页已纳入同一恢复集合。
        Cpu->MtfEptHookRestorePoint=Page;Cpu->MtfEptHookViolation=EPT_HOOKED_LAST_VIOLATION_WRITE;
        HvEnableMtfAndChangeExternalInterruptState(Cpu);
        BOOLEAN Granted=TRUE;
        for(UINT32 i=0;i<g_HiddenCoherence.Count;i++)
        {
            EPT_HOOKED_PAGE_DETAIL *P=g_HiddenCoherence.Pages[i];
            PEPT_PML1_ENTRY Pte=EptGetPml1Entry(Cpu->EptPageTable,P->PhysicalBaseAddress);
            if(!Pte){Granted=FALSE;break;}Pte->AsUInt=P->OriginalEntry.AsUInt;
        }
        if(Granted&&EptInveptSingleContext(Cpu->EptPointer.AsUInt)==0)EptCoherencePhase(EPT_COH_WRITING);
        else {(VOID)EptCoherenceRevokeOwner(Cpu);EptCoherenceFault(Cpu,STATUS_UNSUCCESSFUL);}
    }
Retry:
    HvSuppressRipIncrement(Cpu);return TRUE;
}
BOOLEAN EptCoherenceBreakpointRetry(EPT_HOOKED_PAGE_DETAIL *Page)
{
    return !Page->CoherenceFault&&g_HiddenCoherence.Gate!=0&&g_HiddenCoherence.Published==g_HiddenCoherence.Gate&&
        EptCoherenceCurrentPhase()!=0&&EptCoherenceContains(Page);
}
NTSTATUS EptCoherenceBeginWrite(UINT64 Cr3,UINT64 Cr4,UINT64 Va,UINT64 Size,UINT64 *Token)
{
    if(Token==NULL)return STATUS_INVALID_PARAMETER;*Token=0;
    if(!VmxGetCurrentExecutionMode()||!Size||Size>1048576u||Va+Size-1<Va||GetGuestCr3()!=Cr3||GetGuestCr4()!=Cr4)return STATUS_INVALID_PARAMETER;
    VIRTUAL_MACHINE_STATE *Cpu=&g_GuestState[PlatformCpuGetCurrentProcessorNumber()];
    if(!EptCoherenceClaim(Cpu,EPT_COH_ROOT))return STATUS_DEVICE_BUSY;
    CR3_TYPE Space={0};Space.Flags=Cr3;NTSTATUS Status=STATUS_SUCCESS;
    g_HiddenCoherence.Va=Va;g_HiddenCoherence.Length=Size;
    for(UINT64 Offset=0;Offset<Size;)
    {
        UINT64 Pa=VirtualAddressToPhysicalAddressByProcessCr3((PVOID)(Va+Offset),Space);
        if(!Pa){Status=STATUS_RETRY;break;}
        EPT_HOOKED_PAGE_DETAIL *Page=EptHookFindByPhysAddress((UINT64)PAGE_ALIGN(Pa));
        if(!EptCoherenceAdd(Page)){Status=STATUS_CONFLICTING_ADDRESSES;break;}
        UINT64 Chunk=PAGE_SIZE-(UINT64)PAGE_OFFSET(Va+Offset);if(Chunk>Size-Offset)Chunk=Size-Offset;Offset+=Chunk;
    }
    if(!NT_SUCCESS(Status)){CpuInterlockedExchange(&g_HiddenCoherence.OwnerHeld,0);CpuInterlockedExchange64(&g_HiddenCoherence.Gate,0);return Status;}
    if(g_HiddenCoherence.Count)
    {
        EptCoherencePublish(Cpu,EPT_COH_QUIESCE);
        for(UINT32 i=0;i<65536&&!EptCoherenceAllAck(EptCoherenceState());i++)YieldProcessor();
        if(!EptCoherenceAllAck(EptCoherenceState()))
        {(VOID)EptCoherenceResume(Cpu);return STATUS_IO_TIMEOUT;}
    }
    g_HiddenCoherence.RootActive=TRUE;*Token=(UINT64)g_HiddenCoherence.Gate;return STATUS_SUCCESS;
}
NTSTATUS EptCoherenceWrite(UINT64 Cr3,UINT64 Cr4,UINT64 Va,UINT64 Pa,const VOID *Buffer,UINT32 Size,PUINT32 Bytes,PBOOLEAN Unknown)
{
    if(Bytes==NULL||Unknown==NULL)return STATUS_INVALID_PARAMETER;*Bytes=0;*Unknown=FALSE;
    if(!VmxGetCurrentExecutionMode()||!Buffer||!Size||Size>PAGE_SIZE-(UINT64)PAGE_OFFSET(Pa)||
       !g_HiddenCoherence.RootActive||g_HiddenCoherence.Kind!=EPT_COH_ROOT||
       g_HiddenCoherence.Owner!=PlatformCpuGetCurrentProcessorNumber()||g_HiddenCoherence.Gate<=0||
       Cr3!=g_HiddenCoherence.Cr3||Cr4!=g_HiddenCoherence.Cr4||GetGuestCr3()!=Cr3||GetGuestCr4()!=Cr4||
       Va<g_HiddenCoherence.Va||Size>g_HiddenCoherence.Length||Va-g_HiddenCoherence.Va>g_HiddenCoherence.Length-Size)
        return STATUS_INVALID_PARAMETER;
    CR3_TYPE Space={0};Space.Flags=Cr3;
    if(VirtualAddressToPhysicalAddressByProcessCr3((PVOID)Va,Space)!=Pa)return STATUS_RETRY;
    EPT_HOOKED_PAGE_DETAIL *Page=EptHookFindByPhysAddress((UINT64)PAGE_ALIGN(Pa));
    if(Page&&!EptCoherenceContains(Page))return STATUS_RETRY;
    g_HiddenCoherence.WriteAttempted=TRUE;
    if(!MemoryMapperWriteMemorySafeByPhysicalAddress(Pa,(UINT64)Buffer,Size))
    {*Unknown=TRUE;return STATUS_UNSUCCESSFUL;}
    *Bytes=Size;return STATUS_SUCCESS;
}
NTSTATUS EptCoherenceEndWrite(UINT64 Token,PBOOLEAN Unknown)
{
    if(Unknown==NULL)return STATUS_INVALID_PARAMETER;*Unknown=FALSE;
    if(!VmxGetCurrentExecutionMode()||!g_HiddenCoherence.RootActive||g_HiddenCoherence.Kind!=EPT_COH_ROOT||
       g_HiddenCoherence.Owner!=PlatformCpuGetCurrentProcessorNumber()||Token!=(UINT64)g_HiddenCoherence.Gate)
        return STATUS_INVALID_PARAMETER;
    VIRTUAL_MACHINE_STATE *Cpu=&g_GuestState[PlatformCpuGetCurrentProcessorNumber()];
    g_HiddenCoherence.RootActive=FALSE;
    if(!g_HiddenCoherence.Count){CpuInterlockedExchange(&g_HiddenCoherence.OwnerHeld,0);CpuInterlockedCompareExchange64(&g_HiddenCoherence.Gate,0,(LONG64)Token);return STATUS_SUCCESS;}
    if(g_HiddenCoherence.WriteAttempted&&!EptCoherenceRefresh())
    {*Unknown=TRUE;EptCoherenceFault(Cpu,STATUS_UNSUCCESSFUL);return STATUS_UNSUCCESSFUL;}
    BOOLEAN Attempted=g_HiddenCoherence.WriteAttempted;
    if(!EptCoherenceResume(Cpu)){*Unknown=Attempted;return STATUS_IO_TIMEOUT;}
    return STATUS_SUCCESS;
}
BOOLEAN EptCoherenceQueryFault(UINT64 PhysicalPage,UINT64 *Epoch,NTSTATUS *Status)
{
    EPT_HOOKED_PAGE_DETAIL *Page=EptHookFindByPhysAddress(PhysicalPage);
    NTSTATUS Fault=Page?(NTSTATUS)CpuInterlockedCompareExchange(&Page->CoherenceFault,0,0):STATUS_SUCCESS;
    if(Epoch)*Epoch=Fault&&Page?Page->CoherenceFaultEpoch:0;
    if(Status)*Status=Fault;
    return Fault!=STATUS_SUCCESS;
}
