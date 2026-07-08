/**
 * @file pt-helper.h
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Headers for PT helper functions
 * @details
 * @version 0.21
 * @date 2026-07-03
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//////////////////////////////////////////////////
//					  Functions                 //
//////////////////////////////////////////////////

UINT64
PtHelperDecodeCorePackets(UINT32 Cpu, const UINT8 * Buffer, UINT64 Size, UINT64 ImageBase);

UINT64
PtHelperDecodeCore(UINT32 Cpu, const UINT8 * Buffer, UINT64 Size, IMAGE_SYMBOL_CONTEXT * Ctx);

BOOLEAN
PtHelperCaptureImage(HANDLE Process, UINT64 * TextStart, UINT64 * TextEnd, IMAGE_SYMBOL_CONTEXT * Ctx);

BOOLEAN
PtHelperResolveFunction(HANDLE Process, const CHAR * Path, const CHAR * Name, UINT64 ImageBase, UINT64 * Start, UINT64 * End);
