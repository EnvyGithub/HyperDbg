/**
 * @file pt.cpp
 * @author Masoud Rahimi Jafari (Masoodrahimy1379@gmail.com)
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief !pt command
 * @details
 * @version 0.19
 * @date 2026-04-29
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

//
// Global Variables
//
extern BOOLEAN g_IsHyperTraceModuleLoaded;
extern BOOLEAN g_IsSerialConnectedToRemoteDebuggee;

//
// Stop event: signaled when '!pt pause' is run so the trace thread wakes up
// and stops waiting for the target process to exit.
//
static HANDLE g_PtTraceStopEvent = NULL;

/**
 * @brief Argument block passed to the background trace thread
 */
typedef struct _PT_TRACE_THREAD_ARGS
{
    char    Path[MAX_PATH];
    char    Function[256];
    BOOLEAN Packets;
    int     PinCore;
    UINT32  ProcessId;
    UINT32  ThreadId;
    char    PName[MAX_PATH];
    BOOLEAN HasPath;
    BOOLEAN HasFunction;
    BOOLEAN HasPName;
} PT_TRACE_THREAD_ARGS;

/**
 * @brief help of the !pt command
 *
 * @return VOID
 */
VOID
CommandPtHelp()
{
    ShowMessages("!pt : enables, disables and configures Intel Processor Trace (PT).\n\n");

    ShowMessages("syntax : \t!pt enable\n");
    ShowMessages("syntax : \t!pt enable [size BufferSize (hex)]\n");
    ShowMessages("syntax : \t!pt enable [pid ProcessId (hex)] [size BufferSize (hex)] [core CoreId (hex)]\n");
    ShowMessages("syntax : \t!pt enable [tid ThreadId (hex)] [size BufferSize (hex)] [core CoreId (hex)]\n");
    ShowMessages("syntax : \t!pt enable [pname ProcessName (string)] [size BufferSize (hex)] [core CoreId (hex)]\n");
    ShowMessages("syntax : \t!pt enable [path Path (string)] [size BufferSize (hex)] [core CoreId (hex)]\n");
    ShowMessages("syntax : \t!pt enable [cr3 Cr3Value (hex)] [size BufferSize (hex)]\n");
    ShowMessages("syntax : \t!pt disable\n");
    ShowMessages("syntax : \t!pt pause\n");
    ShowMessages("syntax : \t!pt resume\n");
    ShowMessages("syntax : \t!pt flush\n");
    ShowMessages("syntax : \t!pt dump print [type TypeOfDump (string)]\n");
    ShowMessages("syntax : \t!pt dump path [type TypeOfDump (string)]\n");
    ShowMessages("syntax : \t!pt filter [Mode (string)]\n");
    ShowMessages("syntax : \t!pt filter [range1 FromAddress (hex) ToAddress (hex)] [range2 FromAddress (hex) ToAddress (hex)] [range3 FromAddress (hex) ToAddress (hex)] [range4 FromAddress (hex) ToAddress (hex)]\n");
    ShowMessages("syntax : \t!pt filter [range1 module ModuleName (string)] [range2 module ModuleName (string)] [range3 module ModuleName (string)] [range4 module ModuleName (string)]\n");
    ShowMessages("syntax : \t!pt filter [stoprange1 FromAddress (hex) ToAddress (hex)] [stoprange2 FromAddress (hex) ToAddress (hex)] [stoprange3 FromAddress (hex) ToAddress (hex)] [stoprange4 FromAddress (hex) ToAddress (hex)]\n");
    ShowMessages("syntax : \t!pt filter [stoprange1 module ModuleName (string)] [stoprange2 module ModuleName (string)] [stoprange3 module ModuleName (string)] [stoprange4 module ModuleName (string)]\n");
    ShowMessages("syntax : \t!pt packet [PacketType (string)]\n");

    ShowMessages("\n");
    ShowMessages("\t\te.g : !pt enable\n");
    ShowMessages("\t\te.g : !pt enable size 0x200000\n");
    ShowMessages("\t\te.g : !pt enable pid 0x4a8\n");
    ShowMessages("\t\te.g : !pt enable pname notepad.exe\n");
    ShowMessages("\t\te.g : !pt enable tid 0x1234 core 3\n");
    ShowMessages("\t\te.g : !pt enable cr3 0x1aabb000\n");
    ShowMessages("\t\te.g : !pt enable pid 0x4a8 size 0x200000\n");
    ShowMessages("\t\te.g : !pt enable path \"c:\\programs\\my exe file.exe\" size 0x200000 core 3\n");
    ShowMessages("\t\te.g : !pt disable\n");
    ShowMessages("\t\te.g : !pt pause\n");
    ShowMessages("\t\te.g : !pt resume\n");
    ShowMessages("\t\te.g : !pt flush\n");
    ShowMessages("\t\te.g : !pt dump print type instruction\n");
    ShowMessages("\t\te.g : !pt dump print type packet\n");
    ShowMessages("\t\te.g : !pt dump path C:\\trace.txt type instruction\n");
    ShowMessages("\t\te.g : !pt filter user\n");
    ShowMessages("\t\te.g : !pt filter user kernel\n");
    ShowMessages("\t\te.g : !pt filter range1 0x140001000 0x140002000\n");
    ShowMessages("\t\te.g : !pt filter range1 module main\n");
    ShowMessages("\t\te.g : !pt filter range1 module ntdll range2 module nt\n");
    ShowMessages("\t\te.g : !pt filter stoprange1 0x140003000 0x140004000\n");
    ShowMessages("\t\te.g : !pt packet psb pip tsc\n");

    ShowMessages("\n");
    ShowMessages("Where:\n");
    ShowMessages("\t[Mode (string)] could be 'kernel' or/and 'user'\n");
    ShowMessages("\t[TypeOfDump (string)] could be 'instruction' or 'packet'\n");
    ShowMessages("\t[ModuleName (string)] could be 'main' (the main module of the process), 'nt', 'win32k', or any other module name\n");
    ShowMessages("\t[PacketType (string)] could be either or a combination of 'psb', 'pip', 'tsc', 'mtc', 'cyc', 'tnt', 'tip', 'fup', or 'mode'\n");
    ShowMessages("\n");
}

/**
 * @brief Send PT requests
 *
 * @param PtRequest
 *
 * @return VOID
 */
BOOLEAN
CommandPtSendRequest(HYPERTRACE_PT_OPERATION_PACKETS * PtRequest)
{
    BOOL  Status;
    ULONG ReturnedLength;

    if (g_IsSerialConnectedToRemoteDebuggee)
    {
        //
        // Send the request over serial kernel debugger
        //
        if (!KdSendHyperTracePtPacketsToDebuggee(PtRequest, SIZEOF_HYPERTRACE_PT_OPERATION_PACKETS))
        {
            return FALSE;
        }
        else
        {
            return TRUE;
        }
    }
    else
    {
        AssertShowMessageReturnStmt(g_IsHyperTraceModuleLoaded, g_DeviceHandle, ASSERT_MESSAGE_HYPERTRACE_NOT_LOADED, ASSERT_MESSAGE_DRIVER_NOT_LOADED, AssertReturnFalse);

        //
        // Send IOCTL
        //
        Status = DeviceIoControl(
            g_DeviceHandle,                         // Handle to device
            IOCTL_PERFORM_HYPERTRACE_PT_OPERATION,  // IO Control Code (IOCTL)
            PtRequest,                              // Input Buffer to driver.
            SIZEOF_HYPERTRACE_PT_OPERATION_PACKETS, // Input buffer length
            PtRequest,                              // Output Buffer from driver.
            SIZEOF_HYPERTRACE_PT_OPERATION_PACKETS, // Length of output buffer in bytes.
            &ReturnedLength,                        // Bytes placed in buffer.
            NULL                                    // synchronous call
        );

        if (!Status)
        {
            ShowMessages("ioctl failed with code 0x%x\n", GetLastError());

            return FALSE;
        }

        if (PtRequest->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL)
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
}

/**
 * @brief Request to perform an PT operation
 *
 * @param PtRequest
 *
 * @return BOOLEAN
 */
BOOLEAN
HyperDbgPerformPtOperation(HYPERTRACE_PT_OPERATION_PACKETS * PtRequest)
{
    return CommandPtSendRequest(PtRequest);
}

/**
 * @brief Send pt enable command
 *
 * @return BOOLEAN
 */
static BOOLEAN
CommandPtSendEnable()
{
    HYPERTRACE_PT_OPERATION_PACKETS PtRequest = {};

    //
    // Set the PtRequest structure for the operation
    //
    PtRequest.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_ENABLE;

    //
    // Send the request to perform the operation
    //
    if (!HyperDbgPerformPtOperation(&PtRequest))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/**
 * @brief Send pt disable command
 *
 * @return BOOLEAN
 */
static BOOLEAN
CommandPtSendDisable()
{
    HYPERTRACE_PT_OPERATION_PACKETS PtRequest = {};

    //
    // Set the PtRequest structure for the operation
    //
    PtRequest.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_DISABLE;

    //
    // Send the request to perform the operation
    //
    if (!HyperDbgPerformPtOperation(&PtRequest))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/**
 * @brief Send pt pause command
 *
 * @return BOOLEAN
 */
static BOOLEAN
CommandPtSendPause()
{
    HYPERTRACE_PT_OPERATION_PACKETS PtRequest = {};

    //
    // Set the PtRequest structure for the operation
    //
    PtRequest.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_PAUSE;

    //
    // Send the request to perform the operation
    //
    if (!HyperDbgPerformPtOperation(&PtRequest))
    {
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Send pt resume command
 *
 * @return BOOLEAN
 */
static BOOLEAN
CommandPtSendResume()
{
    HYPERTRACE_PT_OPERATION_PACKETS PtRequest = {};

    //
    // Set the PtRequest structure for the operation
    //
    PtRequest.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_RESUME;

    //
    // Send the request to perform the operation
    //
    if (!HyperDbgPerformPtOperation(&PtRequest))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/**
 * @brief Send pt flush command
 *
 * @return BOOLEAN
 */
static BOOLEAN
CommandPtSendFlush()
{
    HYPERTRACE_PT_OPERATION_PACKETS PtRequest = {};

    //
    // Set the PtRequest structure for the operation
    //
    PtRequest.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_FLUSH;

    //
    // Send the request to perform the operation
    //
    if (!HyperDbgPerformPtOperation(&PtRequest))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/**
 * @brief Send pt filter command
 *
 * @return BOOLEAN
 */
static BOOLEAN
CommandPtSendFilterByPid(UINT32  ProcessId,
                         BOOLEAN IsUserMode,
                         BOOLEAN IsKernelMode,
                         UINT64  StartRange1,
                         UINT64  EndRange1,
                         UINT64  StartRange2,
                         UINT64  EndRange2,
                         UINT64  StartRange3,
                         UINT64  EndRange3,
                         UINT64  StartRange4,
                         UINT64  EndRange4)
{
    HYPERTRACE_PT_OPERATION_PACKETS Op             = {};
    UINT8                           NumberOfRanges = 0;

    //
    // Set the Op structure for the operation
    //
    Op.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_FILTER;

    //
    // Set execution modes
    //
    Op.FilterOptions.TraceUser   = IsUserMode ? 1 : 0;
    Op.FilterOptions.TraceKernel = IsKernelMode ? 1 : 0;

    //
    // Set the process ID
    //
    Op.EnableOptions.Pid = ProcessId;

    //
    // Set the first range if provided
    //
    if (StartRange1 != NULL && EndRange1 != NULL)
    {
        Op.FilterOptions.AddrRanges[NumberOfRanges].Start = StartRange1;
        Op.FilterOptions.AddrRanges[NumberOfRanges].End   = EndRange1;
        NumberOfRanges++;
    }

    //
    // Set the second range if provided
    //
    if (StartRange2 != NULL && EndRange2 != NULL)
    {
        Op.FilterOptions.AddrRanges[NumberOfRanges].Start = StartRange2;
        Op.FilterOptions.AddrRanges[NumberOfRanges].End   = EndRange2;
        NumberOfRanges++;
    }

    //
    // Set the third range if provided
    //
    if (StartRange3 != NULL && EndRange3 != NULL)
    {
        Op.FilterOptions.AddrRanges[NumberOfRanges].Start = StartRange3;
        Op.FilterOptions.AddrRanges[NumberOfRanges].End   = EndRange3;
        NumberOfRanges++;
    }

    //
    // Set the fourth range if provided
    //
    if (StartRange4 != NULL && EndRange4 != NULL)
    {
        Op.FilterOptions.AddrRanges[NumberOfRanges].Start = StartRange4;
        Op.FilterOptions.AddrRanges[NumberOfRanges].End   = EndRange4;
        NumberOfRanges++;
    }

    //
    // Set number of ranges
    //
    Op.FilterOptions.NumAddrRanges = NumberOfRanges;

    //
    // Send the request to perform the operation
    //
    if (!HyperDbgPerformPtOperation(&Op))
    {
        return FALSE;
    }
    else
    {
        ShowMessages("[+] PT Filter: cr3=0x%llx, pid=0x%x, user=%x, kernel=%x, ranges=%x\n",
                     Op.EnableOptions.Cr3,
                     Op.EnableOptions.Pid,
                     Op.FilterOptions.TraceUser,
                     Op.FilterOptions.TraceKernel,
                     Op.FilterOptions.NumAddrRanges);

        return TRUE;
    }

    return TRUE;
}

/**
 * @brief Shared core: enable PT, wait for the target, decode and disable
 *
 * @details Called by the three specialised helpers after they have filled
 *          Process with a valid hProcess (and optionally hThread).
 *          Owns and closes all handles in Process before returning.
 *
 * @param Process      Pointer to a PROCESS_INFORMATION whose hProcess (and
 *                     optionally hThread) have already been opened/created
 * @param Path         Executable path used for symbol resolution, or NULL
 * @param Function     Symbol name to narrow the IP filter, or NULL
 * @param Packets      TRUE  → decode raw packets; FALSE → decode instructions
 * @param PinCore      ≥ 0  → pin the target to that logical core; < 0 → free
 * @param LaunchedNew  TRUE  → process was launched suspended here (will be
 *                             resumed, and terminated on error); FALSE → the
 *                             process was already running (never terminated)
 *
 * @return VOID
 */
static VOID
CommandPtRunAndTraceCore(PROCESS_INFORMATION * Process,
                         const CHAR *          Path,
                         const CHAR *          Function,
                         BOOLEAN               Packets,
                         int                   PinCore,
                         BOOLEAN               LaunchedNew)
{
    DWORD_PTR                       Mask;
    HYPERTRACE_PT_MMAP_PACKETS      Mmap        = {};
    HYPERTRACE_PT_OPERATION_PACKETS Sizes       = {};
    IMAGE_SYMBOL_CONTEXT            Ctx         = {};
    UINT64                          TextStart   = 0;
    UINT64                          TextEnd     = 0;
    UINT64                          FilterStart = 0;
    UINT64                          FilterEnd   = 0;
    UINT64                          Total       = 0;

    if (PinCore < 0)
    {
        PinCore = PT_DEFAULT_PINNING_CORE;
    }

    Mask = (DWORD_PTR)1 << PinCore;

    //
    // Set process affinity to the specified core so that all PT trace will land on that core
    //
    if (SetProcessAffinityMask(Process->hProcess, Mask))
    {
        ShowMessages("[+] pinned target to core %d (all trace should land on this core)\n", PinCore);
    }
    else
    {
        ShowMessages("[!] could not pin to core %d (error 0x%x); running unpinned\n", PinCore, GetLastError());
    }

    //
    // Capture the .text section of the target process image for symbol resolution
    //
    if (!PtHelperCaptureImage(Process->hProcess, &TextStart, &TextEnd, &Ctx))
    {
        ShowMessages("[-] cannot read target image / .text section\n");

        if (LaunchedNew)
            TerminateProcess(Process->hProcess, 1);

        goto Cleanup;
    }

    ShowMessages("[+] image base 0x%llx, .text 0x%llx-0x%llx (%llu bytes)\n",
                 (UINT64)Ctx.ImageBase,
                 (UINT64)TextStart,
                 (UINT64)TextEnd,
                 (UINT64)Ctx.CodeSize);

    FilterStart = TextStart;
    FilterEnd   = TextEnd;

    //
    // Narrow the IP filter to the specified function if possible
    //
    if (Function != NULL && Path != NULL &&
        PtHelperResolveFunction(Process->hProcess, Path, Function, Ctx.ImageBase, &FilterStart, &FilterEnd))
    {
        ShowMessages("[+] IP filter narrowed to '%s' 0x%llx-0x%llx (%llu bytes)\n",
                     Function,
                     (UINT64)FilterStart,
                     (UINT64)FilterEnd,
                     (UINT64)(FilterEnd - FilterStart + 1));
    }
    else
    {
        ShowMessages("[!] IP filter: whole .text (symbol '%s' not found or not applicable)\n",
                     Function ? Function : "(none)");
    }

    //
    // Enable PT with the specified filter and wait for the target process to exit
    //
    if (!CommandPtSendFilterByPid(Process->dwProcessId, TRUE, FALSE, FilterStart, FilterEnd, NULL, NULL, NULL, NULL, NULL, NULL) ||
        !CommandPtSendEnable())
    {
        ShowMessages("[-] cannot enable Intel PT\n");

        if (LaunchedNew)
        {
            TerminateProcess(Process->hProcess, 1);
        }

        goto Cleanup;
    }

    //
    // Request the PT buffers to be mapped into user space so that we can decode them after the target exits
    //
    if (!HyperDbgPtMmapSendRequest(&Mmap))
    {
        ShowMessages("[-] MMAP failed\n");
        CommandPtSendDisable();
        if (LaunchedNew)
            TerminateProcess(Process->hProcess, 1);
        goto Cleanup;
    }

    ShowMessages("[+] PT enabled, %u per-core buffers mapped\n", Mmap.NumCpus);

    if (LaunchedNew)
    {
        ShowMessages("[*] resuming target and waiting for it to exit...\n");
        ResumeThread(Process->hThread);
    }
    else
    {
        ShowMessages("[*] waiting for target process to exit...\n");
    }

    //
    // Wait for the target process to exit OR for '!pt pause' to be called,
    // whichever occurs first
    //
    if (g_PtTraceStopEvent != NULL)
    {
        HANDLE WaitHandles[2] = {Process->hProcess, g_PtTraceStopEvent};
        WaitForMultipleObjects(2, WaitHandles, FALSE, INFINITE);
    }
    else
    {
        WaitForSingleObject(Process->hProcess, INFINITE);
    }

    ShowMessages("[+] target exited or trace stopped, decoding trace\n");

    //
    // Pause PT so that the buffers are not being written to while we decode them
    //
    CommandPtSendPause();

    Sizes.PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_SIZE;

    //
    // Request the sizes of the PT buffers for each core so that we know how much to decode
    //
    if (!CommandPtSendRequest(&Sizes))
    {
        ShowMessages("[-] cannot query PT sizes\n");
        CommandPtSendDisable();
        goto Cleanup;
    }

    //
    // Decode the trace for each core that has a non-zero buffer size
    //
    for (UINT32 i = 0; i < Mmap.NumCpus; i++)
    {
        UINT32 Cpu   = Mmap.Cpus[i].CpuId;
        UINT64 Bytes = (Cpu < Sizes.NumCpus) ? Sizes.BytesPerCpu[Cpu] : 0;

        if (Bytes == 0)
            continue;

        if (Bytes > Mmap.Cpus[i].Size)
            Bytes = Mmap.Cpus[i].Size;

        ShowMessages("\n[*] core %u: %llu bytes of trace\n", Cpu, (UINT64)Bytes);
        Total += Packets
                     ? PtHelperDecodeCorePackets(Cpu, (const UINT8 *)(ULONG_PTR)Mmap.Cpus[i].UserVa, Bytes, Ctx.ImageBase)
                     : PtHelperDecodeCore(Cpu, (const UINT8 *)(ULONG_PTR)Mmap.Cpus[i].UserVa, Bytes, &Ctx);
    }

    ShowMessages("\n[+] decoded %llu %s total\n", (UINT64)Total, Packets ? "packet(s)" : "instruction(s)");

    //
    // Disable PT now that we are done decoding the trace
    //
    CommandPtSendDisable();

Cleanup:

    if (Ctx.Code != NULL)
    {
        free(Ctx.Code);
        Ctx.Code = NULL;
    }

    if (Process->hThread != NULL)
        CloseHandle(Process->hThread);
    if (Process->hProcess != NULL)
        CloseHandle(Process->hProcess);
}

/**
 * @brief Launch an executable at Path as a suspended process, enable PT, and
 *        decode the trace after the process exits
 *
 * @param Path      Full path to the executable to launch
 * @param Function  Symbol name to narrow the IP filter, or NULL for whole .text
 * @param Packets   TRUE → decode raw packets; FALSE → decode instructions
 * @param PinCore   ≥ 0 → pin to that logical core; < 0 → unpinned
 *
 * @return VOID
 */
static VOID
CommandPtRunAndTraceByPath(const CHAR * Path, const CHAR * Function, BOOLEAN Packets, int PinCore)
{
    STARTUPINFOA        Startup = {};
    PROCESS_INFORMATION Process = {};

    Startup.cb = sizeof(Startup);

    if (!CreateProcessA(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &Startup, &Process))
    {
        ShowMessages("[-] cannot launch '%s' (error 0x%x)\n", Path, GetLastError());
        return;
    }

    ShowMessages("[+] launched '%s' (pid %u, suspended)\n", Path, Process.dwProcessId);

    CommandPtRunAndTraceCore(&Process, Path, Function, Packets, PinCore, TRUE);
}

/**
 * @brief Open an existing process by PID, enable PT, and decode the trace
 *        after the process exits
 *
 * @param ProcessId  PID of the target process
 * @param Function   Symbol name to narrow the IP filter, or NULL for whole .text
 * @param Packets    TRUE → decode raw packets; FALSE → decode instructions
 * @param PinCore    ≥ 0 → pin to that logical core; < 0 → unpinned
 *
 * @return VOID
 */
static VOID
CommandPtRunAndTraceByPid(UINT32 ProcessId, const CHAR * Function, BOOLEAN Packets, int PinCore)
{
    PROCESS_INFORMATION Process = {};

    Process.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)ProcessId);

    if (Process.hProcess == NULL)
    {
        ShowMessages("[-] cannot open process 0x%x (error 0x%x)\n", ProcessId, GetLastError());
        return;
    }

    Process.dwProcessId = ProcessId;

    ShowMessages("[+] attached to pid 0x%x\n", ProcessId);

    CommandPtRunAndTraceCore(&Process, NULL, Function, Packets, PinCore, FALSE);
}

/**
 * @brief Open an existing thread by TID, derive its owning process, enable PT,
 *        and decode the trace after the process exits
 *
 * @param ThreadId  TID of the target thread
 * @param Function  Symbol name to narrow the IP filter, or NULL for whole .text
 * @param Packets   TRUE → decode raw packets; FALSE → decode instructions
 * @param PinCore   ≥ 0 → pin to that logical core; < 0 → unpinned
 *
 * @return VOID
 */
static VOID
CommandPtRunAndTraceByTid(UINT32 ThreadId, const CHAR * Function, BOOLEAN Packets, int PinCore)
{
    PROCESS_INFORMATION  Process      = {};
    HANDLE               ThreadHandle = NULL;
    DWORD                OwningPid    = 0;
    THREAD_BASIC_INFO_EX Tbi          = {0};
    ULONG                RetTid       = 0;
    HMODULE              NtdllTid     = GetModuleHandleA("ntdll.dll");
    PFN_NT_QIT           NtQit        = NtdllTid ? (PFN_NT_QIT)GetProcAddress(NtdllTid, "NtQueryInformationThread") : NULL;

    ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, (DWORD)ThreadId);

    if (ThreadHandle == NULL)
    {
        ShowMessages("[-] cannot open thread 0x%x (error 0x%x)\n", ThreadId, GetLastError());
        return;
    }

    if (NtQit == NULL || NtQit(ThreadHandle, 0, &Tbi, sizeof(Tbi), &RetTid) < 0 || Tbi.ClientId.UniqueProcess == NULL)
    {
        ShowMessages("[-] cannot get owning PID for thread 0x%x\n", ThreadId);
        CloseHandle(ThreadHandle);
        return;
    }

    OwningPid = (DWORD)(ULONG_PTR)Tbi.ClientId.UniqueProcess;

    if (OwningPid == 0)
    {
        ShowMessages("[-] cannot get owning PID for thread 0x%x\n", ThreadId);
        CloseHandle(ThreadHandle);
        return;
    }

    Process.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, OwningPid);

    if (Process.hProcess == NULL)
    {
        ShowMessages("[-] cannot open process %u (error 0x%x)\n", OwningPid, GetLastError());
        CloseHandle(ThreadHandle);
        return;
    }

    Process.hThread     = ThreadHandle;
    Process.dwProcessId = OwningPid;
    Process.dwThreadId  = ThreadId;

    ShowMessages("[+] attached to tid 0x%x (owning pid %u)\n", ThreadId, OwningPid);

    CommandPtRunAndTraceCore(&Process, NULL, Function, Packets, PinCore, FALSE);
}

/**
 * @brief Search for a running process by name and trace it
 *
 * @param PName     Process name to search for (e.g. "notepad.exe")
 * @param Function  Symbol name to narrow the IP filter, or NULL for whole .text
 * @param Packets   TRUE → decode raw packets; FALSE → decode instructions
 * @param PinCore   ≥ 0 → pin to that logical core; < 0 → unpinned
 *
 * @return VOID
 */
static VOID
CommandPtRunAndTraceByPname(const CHAR * PName, const CHAR * Function, BOOLEAN Packets, int PinCore)
{
    HANDLE         Snapshot  = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 Entry     = {};
    UINT32         ProcessId = 0;

    Entry.dwSize = sizeof(PROCESSENTRY32);

    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Snapshot == INVALID_HANDLE_VALUE)
    {
        ShowMessages("[-] cannot enumerate processes (error 0x%x)\n", GetLastError());
        return;
    }

    if (Process32First(Snapshot, &Entry))
    {
        do
        {
            if (_stricmp(Entry.szExeFile, PName) == 0)
            {
                ProcessId = Entry.th32ProcessID;
                break;
            }
        } while (Process32Next(Snapshot, &Entry));
    }

    CloseHandle(Snapshot);

    if (ProcessId == 0)
    {
        ShowMessages("[-] cannot find a running process named '%s'\n", PName);
        return;
    }

    ShowMessages("[+] found '%s' at pid 0x%x\n", PName, ProcessId);

    CommandPtRunAndTraceByPid(ProcessId, Function, Packets, PinCore);
}

/**
 * @brief Wrapper: dispatch to the appropriate trace helper based on whichever
 *        selector (Path, ProcessId, ThreadId, PName) is provided
 *
 * @param Path       Executable path, or NULL
 * @param Function   Symbol name for IP filter, or NULL
 * @param Packets    TRUE → raw packets; FALSE → instructions
 * @param PinCore    Logical core to pin the target to, or < 0 for unpinned
 * @param ProcessId  PID of an existing process, or 0
 * @param ThreadId   TID of an existing thread, or 0
 * @param PName      Process name to search for, or NULL
 *
 * @return VOID
 */
static VOID
CommandPtRunAndTrace(const CHAR * Path, const CHAR * Function, BOOLEAN Packets, int PinCore, UINT32 ProcessId, UINT32 ThreadId, const CHAR * PName)
{
    if (Path != NULL)
        CommandPtRunAndTraceByPath(Path, Function, Packets, PinCore);
    else if (ThreadId != 0)
        CommandPtRunAndTraceByTid(ThreadId, Function, Packets, PinCore);
    else if (ProcessId != 0)
        CommandPtRunAndTraceByPid(ProcessId, Function, Packets, PinCore);
    else if (PName != NULL)
        CommandPtRunAndTraceByPname(PName, Function, Packets, PinCore);
    else
        ShowMessages("[-] no path, PID, TID, or process name specified\n");
}

/**
 * @brief Thread procedure: calls CommandPtRunAndTrace, then cleans up the
 *        stop event so a new trace can be started.
 *
 * @param Param  Heap-allocated PT_TRACE_THREAD_ARGS freed before returning
 *
 * @return DWORD
 */
static DWORD WINAPI
PtTraceThreadProc(LPVOID Param)
{
    PT_TRACE_THREAD_ARGS * Args = (PT_TRACE_THREAD_ARGS *)Param;

    CommandPtRunAndTrace(
        Args->HasPath ? Args->Path : NULL,
        Args->HasFunction ? Args->Function : NULL,
        Args->Packets,
        Args->PinCore,
        Args->ProcessId,
        Args->ThreadId,
        Args->HasPName ? Args->PName : NULL);

    free(Args);

    //
    // Release the stop event so the next '!pt enable ...' can create a fresh one
    //
    if (g_PtTraceStopEvent != NULL)
    {
        CloseHandle(g_PtTraceStopEvent);
        g_PtTraceStopEvent = NULL;
    }

    return 0;
}

/**
 * @brief Spawn a background thread to run CommandPtRunAndTrace
 *
 * @details Creates an auto-reset stop event that is signaled when '!pt pause'
 *          is issued, waking the trace thread from its wait.  The thread owns
 *          both the argument block and the event and cleans them up on exit.
 *
 * @param Path       Executable path, or NULL
 * @param Function   Symbol name for IP filter, or NULL
 * @param Packets    TRUE \u2192 raw packets; FALSE \u2192 instructions
 * @param PinCore    Logical core to pin, or < 0 for unpinned
 * @param ProcessId  PID of an existing process, or 0
 * @param ThreadId   TID of an existing thread, or 0
 * @param PName      Process name to search for, or NULL
 *
 * @return BOOLEAN TRUE if the thread was successfully launched
 */
static BOOLEAN
CommandPtLaunchTraceThread(const CHAR * Path,
                           const CHAR * Function,
                           BOOLEAN      Packets,
                           int          PinCore,
                           UINT32       ProcessId,
                           UINT32       ThreadId,
                           const CHAR * PName)
{
    PT_TRACE_THREAD_ARGS * Args;
    HANDLE                 Thread;

    if (g_PtTraceStopEvent != NULL)
    {
        ShowMessages("err, a trace is already running; use '!pt pause' to stop it first\n");
        return FALSE;
    }

    //
    // Auto-reset event: consumed by WaitForMultipleObjects when signaled
    //
    g_PtTraceStopEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    if (g_PtTraceStopEvent == NULL)
    {
        ShowMessages("[-] cannot create stop event (error 0x%x)\n", GetLastError());
        return FALSE;
    }

    Args = (PT_TRACE_THREAD_ARGS *)calloc(1, sizeof(PT_TRACE_THREAD_ARGS));

    if (Args == NULL)
    {
        ShowMessages("[-] out of memory\n");
        CloseHandle(g_PtTraceStopEvent);
        g_PtTraceStopEvent = NULL;
        return FALSE;
    }

    if (Path != NULL)
    {
        strcpy_s(Args->Path, sizeof(Args->Path), Path);
        Args->HasPath = TRUE;
    }

    if (Function != NULL)
    {
        strcpy_s(Args->Function, sizeof(Args->Function), Function);
        Args->HasFunction = TRUE;
    }

    Args->Packets   = Packets;
    Args->PinCore   = PinCore;
    Args->ProcessId = ProcessId;
    Args->ThreadId  = ThreadId;

    if (PName != NULL)
    {
        strcpy_s(Args->PName, sizeof(Args->PName), PName);
        Args->HasPName = TRUE;
    }

    Thread = CreateThread(NULL, 0, PtTraceThreadProc, Args, 0, NULL);

    if (Thread == NULL)
    {
        ShowMessages("[-] cannot create trace thread (error 0x%x)\n", GetLastError());
        CloseHandle(g_PtTraceStopEvent);
        g_PtTraceStopEvent = NULL;
        free(Args);
        return FALSE;
    }

    ShowMessages("[*] trace thread launched (TID %u); run '!pt pause' to stop early\n", GetThreadId(Thread));
    CloseHandle(Thread); // detach — thread owns its own lifetime
    return TRUE;
}

/**
 * @brief Map the per-CPU PT output buffers into the current process
 *
 * @details On success MmapRequest->Cpus[0..NumCpus) hold one { UserVa, Size }
 *          per CPU, valid in this process until PT is disabled / flushed.
 *          Only meaningful in local (VMI) mode.
 *
 * @param MmapRequest
 *
 * @return BOOLEAN
 */
BOOLEAN
HyperDbgPtMmapSendRequest(HYPERTRACE_PT_MMAP_PACKETS * MmapRequest)
{
    BOOL  Status;
    ULONG ReturnedLength;

    if (g_IsSerialConnectedToRemoteDebuggee)
    {
        //
        // The mmap surface maps into the caller's address space, which only
        // makes sense in local mode (no remote-debuggee transport for it).
        //
        ShowMessages("err, PT mmap is only available in local (VMI) mode\n");
        return FALSE;
    }

    AssertShowMessageReturnStmt(g_IsHyperTraceModuleLoaded, g_DeviceHandle, ASSERT_MESSAGE_HYPERTRACE_NOT_LOADED, ASSERT_MESSAGE_DRIVER_NOT_LOADED, AssertReturnFalse);

    Status = DeviceIoControl(
        g_DeviceHandle,                    // Handle to device
        IOCTL_PERFORM_HYPERTRACE_PT_MMAP,  // IO Control Code (IOCTL)
        MmapRequest,                       // Input Buffer to driver.
        SIZEOF_HYPERTRACE_PT_MMAP_PACKETS, // Input buffer length
        MmapRequest,                       // Output Buffer from driver.
        SIZEOF_HYPERTRACE_PT_MMAP_PACKETS, // Length of output buffer in bytes.
        &ReturnedLength,                   // Bytes placed in buffer.
        NULL                               // synchronous call
    );

    if (!Status)
    {
        ShowMessages("ioctl failed with code 0x%x\n", GetLastError());
        return FALSE;
    }

    return MmapRequest->KernelStatus == DEBUGGER_OPERATION_WAS_SUCCESSFUL;
}

/**
 * @brief Parse and display enable options for !pt enable command
 *
 * @param CommandTokens The command tokens to parse
 * @param PtRequest The PT request structure to fill with parsed options
 *
 * @return VOID
 */
static VOID
CommandPtParseEnable(vector<CommandToken> & CommandTokens, HYPERTRACE_PT_OPERATION_PACKETS * PtRequest)
{
    BOOLEAN HasPid   = FALSE;
    BOOLEAN HasPname = FALSE;
    BOOLEAN HasPath  = FALSE;
    BOOLEAN HasTid   = FALSE;
    BOOLEAN HasCr3   = FALSE;
    BOOLEAN HasSize  = FALSE;
    BOOLEAN HasCore  = FALSE;
    UINT64  Pid      = 0;
    UINT64  Tid      = 0;
    UINT64  Cr3      = 0;
    UINT64  Size     = 0;
    UINT32  Core     = 0;
    string  Pname;
    string  Path;

    for (SIZE_T i = 2; i < CommandTokens.size(); i++)
    {
        if (CompareLowerCaseStrings(CommandTokens.at(i), "pid"))
        {
            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, 'pid' expects a hex process ID\n\n");
                CommandPtHelp();
                return;
            }
            i++;
            if (!ConvertTokenToUInt64(CommandTokens.at(i), &Pid))
            {
                ShowMessages("err, '%s' is not a valid hex process ID\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                CommandPtHelp();
                return;
            }
            HasPid = TRUE;
        }
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "pname"))
        {
            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, 'pname' expects a process name\n\n");
                CommandPtHelp();
                return;
            }
            i++;
            Pname    = GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i));
            HasPname = TRUE;
        }
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "path"))
        {
            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, 'path' expects a process executable path\n\n");
                CommandPtHelp();
                return;
            }
            i++;
            Path    = GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i));
            HasPath = TRUE;
        }
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "tid"))
        {
            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, 'tid' expects a hex thread ID\n\n");
                CommandPtHelp();
                return;
            }
            i++;
            if (!ConvertTokenToUInt64(CommandTokens.at(i), &Tid))
            {
                ShowMessages("err, '%s' is not a valid hex thread ID\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                CommandPtHelp();
                return;
            }
            HasTid = TRUE;
        }
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "cr3"))
        {
            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, 'cr3' expects a hex CR3 value\n\n");
                CommandPtHelp();
                return;
            }
            i++;
            if (!ConvertTokenToUInt64(CommandTokens.at(i), &Cr3))
            {
                ShowMessages("err, '%s' is not a valid hex CR3 value\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                CommandPtHelp();
                return;
            }
            HasCr3 = TRUE;
        }
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "size"))
        {
            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, 'size' expects a hex buffer size\n\n");
                CommandPtHelp();
                return;
            }
            i++;
            if (!ConvertTokenToUInt64(CommandTokens.at(i), &Size))
            {
                ShowMessages("err, '%s' is not a valid hex size\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                CommandPtHelp();
                return;
            }
            HasSize = TRUE;
        }
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "core"))
        {
            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, 'core' expects a hex value as the core number\n\n");
                CommandPtHelp();
                return;
            }
            i++;
            if (!ConvertTokenToUInt32(CommandTokens.at(i), &Core))
            {
                ShowMessages("err, '%s' is not a valid hex size\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                CommandPtHelp();
                return;
            }
            HasCore = TRUE;
        }
        else
        {
            ShowMessages("err, unknown 'enable' option '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
            CommandPtHelp();
            return;
        }
    }

    //
    // pid, pname, tid, cr3 are mutually exclusive target selectors
    //
    INT32 SelectorCount = (HasPid ? 1 : 0) + (HasPname ? 1 : 0) + (HasPath ? 1 : 0) + (HasTid ? 1 : 0) + (HasCr3 ? 1 : 0);
    if (SelectorCount > 1)
    {
        ShowMessages("err, only one of 'pid', 'pname', 'path', 'tid', 'cr3' may be specified at a time\n\n");
        CommandPtHelp();
        return;
    }

    //
    // Show parsed enable options
    //
    ShowMessages("PT enable:\n");

    if (HasPid)
    {
        ShowMessages("  target pid   : 0x%llx\n", Pid);

        PtRequest->EnableOptions.EnableByPid = 1;
        PtRequest->EnableOptions.Pid         = (UINT32)Pid;
    }
    else if (HasPname)
    {
        ShowMessages("  target pname : %s\n", Pname.c_str());

        PtRequest->EnableOptions.EnableByCr3 = 1;
        strcpy_s(PtRequest->EnableOptions.ProcessName, sizeof(PtRequest->EnableOptions.ProcessName), Pname.c_str());
    }
    else if (HasPath)
    {
        ShowMessages("  target path : %s\n", Path.c_str());

        PtRequest->EnableOptions.EnableByPid = 1; // Path is resolved to a PID
    }
    else if (HasTid)
    {
        ShowMessages("  target tid   : 0x%llx\n", Tid);

        PtRequest->EnableOptions.EnableByTid = 1;
        PtRequest->EnableOptions.Tid         = (UINT32)Tid;
    }
    else if (HasCr3)
    {
        ShowMessages("  target cr3   : 0x%llx\n", Cr3);

        PtRequest->EnableOptions.EnableByCr3 = 1;
        PtRequest->EnableOptions.Cr3         = Cr3;
    }
    else
    {
        ShowMessages("  target       : all (no process/thread filter)\n");
    }

    //
    // Check for size options
    //
    if (HasSize)
    {
        ShowMessages("  buffer size  : 0x%llx bytes\n", Size);

        PtRequest->BufferSize = Size;
    }
    else
    {
        ShowMessages("  buffer size  : default (%llx bytes)\n", PT_DEFAULT_BUFFER_SIZE);

        PtRequest->BufferSize = PT_DEFAULT_BUFFER_SIZE;
    }

    //
    // Check for core options
    //
    if (HasCore)
    {
        ShowMessages("  core         : 0x%x\n", Core);
        PtRequest->CoreId = Core;
    }
    else
    {
        ShowMessages("  core         : default (0x%x)\n", PT_DEFAULT_PINNING_CORE);
        PtRequest->CoreId = PT_DEFAULT_PINNING_CORE;
    }

    //
    // Fill the PtRequest structure with parsed options
    //
    PtRequest->PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_ENABLE;

    //
    // Temporary workaround for testing:
    // If a path, PID, or TID is specified, invoke CommandPtRunAndTrace directly
    // to launch/attach and decode the trace in one step.
    // TODO: Should be removed once the kernel-side enable/filter path is complete.
    //
    if (HasPath)
    {
        ShowMessages("  Running '%s' on core: %llx\n", Path.c_str(), PtRequest->CoreId);
        CommandPtLaunchTraceThread(Path.c_str(), NULL, FALSE, PtRequest->CoreId, 0, 0, NULL);
    }
    else if (HasPid)
    {
        ShowMessages("  Tracing pid 0x%llx on core: %llx\n", Pid, PtRequest->CoreId);
        CommandPtLaunchTraceThread(NULL, NULL, FALSE, PtRequest->CoreId, (UINT32)Pid, 0, NULL);
    }
    else if (HasTid)
    {
        ShowMessages("  Tracing tid 0x%llx on core: %llx\n", Tid, PtRequest->CoreId);
        CommandPtLaunchTraceThread(NULL, NULL, FALSE, PtRequest->CoreId, 0, (UINT32)Tid, NULL);
    }
    else if (HasPname)
    {
        ShowMessages("  Tracing pname '%s' on core: %llx\n", Pname.c_str(), PtRequest->CoreId);
        CommandPtLaunchTraceThread(NULL, NULL, FALSE, PtRequest->CoreId, 0, 0, Pname.c_str());
    }
}

/**
 * @brief Parse and display !pt dump parameters
 *
 * @param CommandTokens The command tokens to parse
 * @param PtRequest The PT request structure to fill with parsed options
 *
 * @return VOID
 */
static VOID
CommandPtParseDump(vector<CommandToken> & CommandTokens, HYPERTRACE_PT_OPERATION_PACKETS * PtRequest)
{
    if (CommandTokens.size() < 3)
    {
        ShowMessages("err, 'dump' requires additional options\n\n");
        CommandPtHelp();
        return;
    }

    if (CompareLowerCaseStrings(CommandTokens.at(2), "print"))
    {
        //
        // !pt dump print type <instruction|packet>
        //
        if (CommandTokens.size() != 5 || !CompareLowerCaseStrings(CommandTokens.at(3), "type"))
        {
            ShowMessages("err, syntax: !pt dump print type <instruction|packet>\n\n");
            CommandPtHelp();
            return;
        }

        if (!CompareLowerCaseStrings(CommandTokens.at(4), "instruction") &&
            !CompareLowerCaseStrings(CommandTokens.at(4), "packet"))
        {
            ShowMessages("err, dump type must be 'instruction' or 'packet', got '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(CommandTokens.at(4)).c_str());
            CommandPtHelp();
            return;
        }

        ShowMessages("PT dump to console:\n");
        ShowMessages("  output : console (print)\n");
        ShowMessages("  format : %s\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(4)).c_str());
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(2), "path"))
    {
        //
        // !pt dump path <path-string> type <instruction|packet>
        //
        if (CommandTokens.size() != 6 || !CompareLowerCaseStrings(CommandTokens.at(4), "type"))
        {
            ShowMessages("err, syntax: !pt dump path <path> type <instruction|packet>\n\n");
            CommandPtHelp();
            return;
        }

        if (!CompareLowerCaseStrings(CommandTokens.at(5), "instruction") &&
            !CompareLowerCaseStrings(CommandTokens.at(5), "packet"))
        {
            ShowMessages("err, dump type must be 'instruction' or 'packet', got '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(CommandTokens.at(5)).c_str());
            CommandPtHelp();
            return;
        }

        ShowMessages("PT dump to file:\n");
        ShowMessages("  output : file\n");
        ShowMessages("  path   : %s\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(3)).c_str());
        ShowMessages("  format : %s\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(5)).c_str());
    }
    else
    {
        ShowMessages("err, unknown 'dump' sub-option '%s'\n\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(2)).c_str());
        CommandPtHelp();
    }
}

/**
 * @brief Parse and display !pt filter parameters
 *
 * @param CommandTokens The command tokens to parse
 * @param PtRequest The PT request structure to fill with parsed options
 *
 * @return VOID
 */
static VOID
CommandPtParseFilter(vector<CommandToken> & CommandTokens, HYPERTRACE_PT_OPERATION_PACKETS * PtRequest)
{
    struct PtRangeEntry
    {
        BOOLEAN Active;
        BOOLEAN IsModule;
        UINT64  Start;
        UINT64  End;
        string  ModuleName;
    };

    PtRangeEntry Ranges[4]     = {};
    PtRangeEntry StopRanges[4] = {};
    BOOLEAN      TraceUser     = FALSE;
    BOOLEAN      TraceKernel   = FALSE;

    for (SIZE_T i = 2; i < CommandTokens.size(); i++)
    {
        if (CompareLowerCaseStrings(CommandTokens.at(i), "user"))
        {
            TraceUser = TRUE;
        }
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "kernel"))
        {
            TraceKernel = TRUE;
        }
        else
        {
            //
            // Resolve range1..range4 / stoprange1..stoprange4
            //
            BOOLEAN IsStop   = FALSE;
            INT32   RangeIdx = -1;

            if (CompareLowerCaseStrings(CommandTokens.at(i), "range1"))
            {
                IsStop   = FALSE;
                RangeIdx = 0;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(i), "range2"))
            {
                IsStop   = FALSE;
                RangeIdx = 1;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(i), "range3"))
            {
                IsStop   = FALSE;
                RangeIdx = 2;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(i), "range4"))
            {
                IsStop   = FALSE;
                RangeIdx = 3;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(i), "stoprange1"))
            {
                IsStop   = TRUE;
                RangeIdx = 0;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(i), "stoprange2"))
            {
                IsStop   = TRUE;
                RangeIdx = 1;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(i), "stoprange3"))
            {
                IsStop   = TRUE;
                RangeIdx = 2;
            }
            else if (CompareLowerCaseStrings(CommandTokens.at(i), "stoprange4"))
            {
                IsStop   = TRUE;
                RangeIdx = 3;
            }
            else
            {
                ShowMessages("err, unknown filter option '%s'\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                CommandPtHelp();
                return;
            }

            PtRangeEntry * Entry = IsStop ? &StopRanges[RangeIdx] : &Ranges[RangeIdx];

            if (i + 1 >= CommandTokens.size())
            {
                ShowMessages("err, '%s' expects <start> <end> or 'module <name>'\n\n",
                             GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                CommandPtHelp();
                return;
            }

            if (CompareLowerCaseStrings(CommandTokens.at(i + 1), "module"))
            {
                //
                // range<N> module <module-name>
                //
                if (i + 2 >= CommandTokens.size())
                {
                    ShowMessages("err, 'module' expects a module name\n\n");
                    CommandPtHelp();
                    return;
                }
                i += 2;
                Entry->IsModule   = TRUE;
                Entry->ModuleName = GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i));
                Entry->Active     = TRUE;
            }
            else
            {
                //
                // range<N> <start> <end>
                //
                if (i + 2 >= CommandTokens.size())
                {
                    ShowMessages("err, '%s' expects <start> <end>\n\n",
                                 GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                    CommandPtHelp();
                    return;
                }
                i++;
                if (!ConvertTokenToUInt64(CommandTokens.at(i), &Entry->Start))
                {
                    ShowMessages("err, '%s' is not a valid address\n\n",
                                 GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                    CommandPtHelp();
                    return;
                }
                i++;
                if (!ConvertTokenToUInt64(CommandTokens.at(i), &Entry->End))
                {
                    ShowMessages("err, '%s' is not a valid address\n\n",
                                 GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
                    CommandPtHelp();
                    return;
                }
                Entry->IsModule = FALSE;
                Entry->Active   = TRUE;
            }
        }
    }

    //
    // Show parsed filter options
    //
    ShowMessages("PT filter:\n");

    if (TraceUser)
    {
        ShowMessages("  privilege  : user (CPL > 0)\n");

        PtRequest->FilterOptions.TraceUser = 1;
    }
    if (TraceKernel)
    {
        ShowMessages("  privilege  : kernel (CPL == 0)\n");

        PtRequest->FilterOptions.TraceKernel = 1;
    }
    if (!TraceUser && !TraceKernel)
    {
        ShowMessages("  privilege  : (default - user + kernel)\n");

        PtRequest->FilterOptions.TraceUser   = 1;
        PtRequest->FilterOptions.TraceKernel = 1;
    }

    for (INT32 r = 0; r < 4; r++)
    {
        if (Ranges[r].Active)
        {
            if (Ranges[r].IsModule)
                ShowMessages("  range%d     : module '%s'\n", r + 1, Ranges[r].ModuleName.c_str());
            else
                ShowMessages("  range%d     : 0x%llx - 0x%llx\n", r + 1, Ranges[r].Start, Ranges[r].End);
        }

        //
        // Set the PtRequest structure for filter operation
        //
        PtRequest->FilterOptions.AddrRanges[r].IsStopRange = FALSE;

        PtRequest->FilterOptions.AddrRanges[r].Start = Ranges[r].Start;
        PtRequest->FilterOptions.AddrRanges[r].End   = Ranges[r].End;
    }

    for (INT32 r = 0; r < 4; r++)
    {
        if (StopRanges[r].Active)
        {
            if (StopRanges[r].IsModule)
                ShowMessages("  stoprange%d : module '%s'\n", r + 1, StopRanges[r].ModuleName.c_str());
            else
                ShowMessages("  stoprange%d : 0x%llx - 0x%llx\n", r + 1, StopRanges[r].Start, StopRanges[r].End);
        }

        //
        // Set the PtRequest structure for filter operation
        //
        PtRequest->FilterOptions.AddrRanges[r].IsStopRange = TRUE;

        PtRequest->FilterOptions.AddrRanges[r].Start = Ranges[r].Start;
        PtRequest->FilterOptions.AddrRanges[r].End   = Ranges[r].End;
    }

    //
    // Set the PtRequest structure for filter operation
    //
    PtRequest->PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_FILTER;
}

/**
 * @brief Parse and display !pt packet parameters
 * @param CommandTokens The command tokens to parse
 * @param PtRequest The PT request structure to fill with parsed options
 *
 * @return VOID
 */
static VOID
CommandPtParsePacket(vector<CommandToken> & CommandTokens, HYPERTRACE_PT_OPERATION_PACKETS * PtRequest)
{
    if (CommandTokens.size() < 3)
    {
        ShowMessages("err, 'packet' requires at least one option\n\n");
        CommandPtHelp();
        return;
    }

    BOOLEAN PktPsb  = FALSE;
    BOOLEAN PktPip  = FALSE;
    BOOLEAN PktTsc  = FALSE;
    BOOLEAN PktMtc  = FALSE;
    BOOLEAN PktCyc  = FALSE;
    BOOLEAN PktTnt  = FALSE;
    BOOLEAN PktTip  = FALSE;
    BOOLEAN PktFup  = FALSE;
    BOOLEAN PktMode = FALSE;

    for (SIZE_T i = 2; i < CommandTokens.size(); i++)
    {
        if (CompareLowerCaseStrings(CommandTokens.at(i), "psb"))
            PktPsb = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "pip"))
            PktPip = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "tsc"))
            PktTsc = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "mtc"))
            PktMtc = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "cyc"))
            PktCyc = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "tnt"))
            PktTnt = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "tip"))
            PktTip = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "fup"))
            PktFup = TRUE;
        else if (CompareLowerCaseStrings(CommandTokens.at(i), "mode"))
            PktMode = TRUE;
        else
        {
            ShowMessages("err, unknown 'packet' option '%s'\n\n",
                         GetCaseSensitiveStringFromCommandToken(CommandTokens.at(i)).c_str());
            CommandPtHelp();
            return;
        }
    }

    //
    // Show parsed packet options
    //
    ShowMessages("PT packet filter:\n");

    if (PktPsb)
    {
        ShowMessages("  packet type: PSB  (Packet Stream Boundary)\n");

        PtRequest->PacketOptions.PSB = 1;
    }
    if (PktPip)
    {
        ShowMessages("  packet type: PIP  (Paging Information Packet)\n");

        PtRequest->PacketOptions.PIP = 1;
    }
    if (PktTsc)
    {
        ShowMessages("  packet type: TSC  (Timestamp Counter)\n");

        PtRequest->PacketOptions.TSC = 1;
    }
    if (PktMtc)
    {
        ShowMessages("  packet type: MTC  (Mini Timestamp Counter)\n");

        PtRequest->PacketOptions.MTC = 1;
    }
    if (PktCyc)
    {
        ShowMessages("  packet type: CYC  (Cycle Counter)\n");

        PtRequest->PacketOptions.CYC = 1;
    }
    if (PktTnt)
    {
        ShowMessages("  packet type: TNT  (Taken/Not-Taken)\n");

        PtRequest->PacketOptions.TNT = 1;
    }
    if (PktTip)
    {
        ShowMessages("  packet type: TIP  (Target IP)\n");

        PtRequest->PacketOptions.TNT = 1;
    }
    if (PktFup)
    {
        ShowMessages("  packet type: FUP  (Flow Update Packet)\n");

        PtRequest->PacketOptions.FUP = 1;
    }
    if (PktMode)
    {
        ShowMessages("  packet type: MODE (Mode packet)\n");

        PtRequest->PacketOptions.MODE = 1;
    }

    //
    // Set the PtRequest structure for packet operation
    //
    PtRequest->PtOperationType = HYPERTRACE_PT_OPERATION_REQUEST_TYPE_PACKET;
}

/**
 * @brief !pt command handler
 *
 * @param CommandTokens
 * @param Command
 *
 * @return VOID
 */
VOID
CommandPt(vector<CommandToken> CommandTokens, string Command)
{
    HYPERTRACE_PT_OPERATION_PACKETS PtRequest = {};

    if (CommandTokens.size() == 1)
    {
        ShowMessages("incorrect use of the '%s'\n\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
        CommandPtHelp();
        return;
    }

    //
    // Parse subcommands
    //
    if (CompareLowerCaseStrings(CommandTokens.at(1), "enable"))
    {
        //
        // Parse and display enable options for !pt enable command
        //
        CommandPtParseEnable(CommandTokens, &PtRequest);
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "disable"))
    {
        if (CommandTokens.size() != 2)
        {
            ShowMessages("err, 'disable' takes no arguments\n\n");
            CommandPtHelp();
            return;
        }

        //
        // Parse and display disable options for !pt disable command
        //
        CommandPtSendDisable();
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "pause"))
    {
        if (CommandTokens.size() != 2)
        {
            ShowMessages("err, 'pause' takes no arguments\n\n");
            CommandPtHelp();
            return;
        }

        //
        // Wake the trace thread (if any) that is waiting for the target process
        //
        if (g_PtTraceStopEvent != NULL)
        {
            SetEvent(g_PtTraceStopEvent);
        }
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "resume"))
    {
        if (CommandTokens.size() != 2)
        {
            ShowMessages("err, 'resume' takes no arguments\n\n");
            CommandPtHelp();
            return;
        }

        //
        // Parse and display resume options for !pt resume command
        //
        CommandPtSendResume();
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "flush"))
    {
        if (CommandTokens.size() != 2)
        {
            ShowMessages("err, 'flush' takes no arguments\n\n");
            CommandPtHelp();
            return;
        }

        //
        // Parse and display flush options for !pt flush command
        //
        CommandPtSendFlush();
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "dump"))
    {
        //
        // Parse and display dump options for !pt dump command
        //
        CommandPtParseDump(CommandTokens, &PtRequest);
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "filter"))
    {
        //
        // Parse and display filter options for !pt filter command
        //
        CommandPtParseFilter(CommandTokens, &PtRequest);
    }
    else if (CompareLowerCaseStrings(CommandTokens.at(1), "packet"))
    {
        //
        // Parse and display packet options for !pt packet command
        //
        CommandPtParsePacket(CommandTokens, &PtRequest);
    }
    else
    {
        ShowMessages("incorrect use of the '%s'\n\n",
                     GetCaseSensitiveStringFromCommandToken(CommandTokens.at(0)).c_str());
        CommandPtHelp();
    }
}
