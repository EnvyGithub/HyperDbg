/**
 * @brief Initializes hypervisor
 * @param VmmCallbacks
 *
 * @return BOOLEAN Shows whether the initialization was successful or not
 */
BOOLEAN
VmFuncInitVmm(VMM_CALLBACKS * VmmCallbacks)
{
    BOOLEAN Result;
    if (!EptControlAcquireExclusive()) return FALSE;
    EptControlSetWriteReady(FALSE);
    Result = HvInitVmm(VmmCallbacks);
    if(Result)
    {
        VmxBroadcastInitialize();
        if(!g_NmiBroadcastingInitialized){(VOID)VmxPerformTermination();Result=FALSE;}
    }
    EptControlSetWriteReady(Result);
    EptControlReleaseExclusive();
    return Result;
}

/**
 * @brief Uninitialize Terminate Vmx on all logical cores
 *
 * @return VOID
 */
VOID
VmFuncUninitVmm()
{
    if (!EptControlAcquireExclusive()) return;
    EptControlSetWriteReady(FALSE);
    VmxBroadcastUninitialize();
    if(!g_NmiBroadcastingInitialized)(VOID)VmxPerformTermination();
    EptControlReleaseExclusive();
}

/**
 * @brief Uninitialize VMX on all logical cores and report teardown status
 *
 * @return BOOLEAN TRUE only after all cores left VMX operation and shared
 * resources were released
 */
BOOLEAN
VmFuncUninitVmmChecked()
{
    BOOLEAN Result;
    if (!EptControlAcquireExclusive()) return FALSE;
    EptControlSetWriteReady(FALSE);
    VmxBroadcastUninitialize();
    Result = !g_NmiBroadcastingInitialized && VmxPerformTermination();
    EptControlReleaseExclusive();
    return Result;
}

