/**
 * @file symbol.h
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Symbol related functions header
 * @details
 * @version 0.1
 * @date 2021-06-09
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//////////////////////////////////////////////////
//			        Structures		            //
//////////////////////////////////////////////////

/**
 * @brief Save the local function symbols' description
 *
 */
typedef struct _LOCAL_FUNCTION_DESCRIPTION
{
    std::string ObjectName;
    UINT32      ObjectSize;

} LOCAL_FUNCTION_DESCRIPTION, *PLOCAL_FUNCTION_DESCRIPTION;

/**
 * @brief Save the local module symbols' description
 *
 */
typedef struct _IMAGE_SYMBOL_CONTEXT
{
    UINT64  ImageBase;
    UINT64  CodeBase;
    UINT64  CodeSize;
    UINT8 * Code;
} IMAGE_SYMBOL_CONTEXT;

/*
 * @brief Process basic information structure
 */
typedef struct _PROC_BASIC_INFO
{
    LONG      ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR Reserved[4];
} PROC_BASIC_INFO;

/**
 * @brief Thread basic information
 *
 */
typedef struct _THREAD_BASIC_INFO_EX
{
    LONG  ExitStatus;
    PVOID TebBaseAddress;
    struct
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFO_EX;

//////////////////////////////////////////////////
//		       Function Defs                    //
//////////////////////////////////////////////////

typedef LONG(NTAPI * PFN_NT_QIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI * PFN_NT_QIT)(HANDLE, ULONG, PVOID, ULONG, PULONG);

//////////////////////////////////////////////////
//			    	    Pdbex                   //
//////////////////////////////////////////////////

#define PDBEX_DEFAULT_CONFIGURATION "-j- -k- -e n -i"

//////////////////////////////////////////////////
//			 For symbol (pdb) parsing		    //
//////////////////////////////////////////////////

VOID
SymbolBuildAndShowSymbolTable();

BOOLEAN
SymbolShowFunctionNameBasedOnAddress(UINT64 Address, PUINT64 UsedBaseAddress);

BOOLEAN
SymbolLoadOrDownloadSymbols(BOOLEAN IsDownload, BOOLEAN SilentLoad);

BOOLEAN
SymbolConvertNameOrExprToAddress(const string & TextToConvert, PUINT64 Result);

BOOLEAN
SymbolDeleteSymTable();

BOOLEAN
SymbolBuildSymbolTable(PMODULE_SYMBOL_DETAIL * BufferToStoreDetails,
                       PUINT32                 StoredLength,
                       UINT32                  UserProcessId,
                       BOOLEAN                 SendOverSerial);

BOOLEAN
SymbolBuildAndUpdateSymbolTable(PMODULE_SYMBOL_DETAIL SymbolDetail);

VOID
SymbolInitialReload();

BOOLEAN
SymbolLocalReload(UINT32 UserProcessId);

VOID
SymbolPrepareDebuggerWithSymbolInfo(UINT32 UserProcessId);

BOOLEAN
SymbolReloadSymbolTableInDebuggerMode(UINT32 ProcessId);

#ifdef _WIN32
// PRTL_PROCESS_MODULES is from winternl.h — Windows-only
BOOLEAN
SymbolCheckAndAllocateModuleInformation(PRTL_PROCESS_MODULES * Modules);
#endif // _WIN32
