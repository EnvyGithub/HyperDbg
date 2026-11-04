#pragma once

// 所有执行页只在独立 EPT 视图中屏蔽 X；primary 页表和 guest 字节保持不变。
BOOLEAN EptExecuteWatchOnExit(VIRTUAL_MACHINE_STATE *Cpu);
VOID EptExecuteWatchBeforeResume(VIRTUAL_MACHINE_STATE *Cpu);
BOOLEAN EptExecuteWatchViolation(VIRTUAL_MACHINE_STATE *Cpu, UINT64 PhysicalAddress,
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION Qualification);
BOOLEAN EptExecuteWatchMtf(VIRTUAL_MACHINE_STATE *Cpu);
BOOLEAN EptExecuteWatchActive(VOID);
BOOLEAN EptExecuteWatchLegacyUnhookBegin(VOID);
VOID EptExecuteWatchLegacyUnhookEnd(VOID);
// root 写的整个临界区必须配对；返回 FALSE 时没有授权实际写入。
BOOLEAN EptExecuteWatchBeginPhysicalWrite(UINT64 Address, UINT64 Size, PUINT64 Token);
VOID EptExecuteWatchEndPhysicalWrite(UINT64 Token);
