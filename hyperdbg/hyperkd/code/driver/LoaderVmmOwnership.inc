// 失败初始化同样持有回调；只有 checked 退出成功才能允许释放 KD 或卸载 driver。
static BOOLEAN LoaderReleaseVmmOwnership(VOID)
{
    if(!g_VmmResourcesOwned)return TRUE;
    if(!VmFuncUninitVmmChecked())return FALSE;
    g_VmmInitialized=FALSE;
    DrvSetVmmResourcesOwned(FALSE);
    return TRUE;
}
