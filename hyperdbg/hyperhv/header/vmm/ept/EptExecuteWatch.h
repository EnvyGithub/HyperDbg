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
