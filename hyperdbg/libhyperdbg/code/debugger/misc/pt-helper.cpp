/**
 * @file pt-help.cpp
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief PT helper functions
 * @details
 * @version 0.21
 * @date 2026-07-03
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

/**
 * @brief Read the process image for PT decoding
 *
 * @param Buffer
 * @param Size
 * @param Asid
 * @param Ip
 * @param Context
 *
 * @return int
 */
int
PtHelperReadImage(UINT8 * Buffer, SIZE_T Size, const struct pt_asid * Asid, UINT64 Ip, VOID * Context)
{
    (VOID) Asid;

    IMAGE_SYMBOL_CONTEXT * Ctx = (IMAGE_SYMBOL_CONTEXT *)Context;

    if (Ctx == NULL || Ctx->Code == NULL || Ip < Ctx->CodeBase || Ip >= Ctx->CodeBase + Ctx->CodeSize)
        return -pte_nomap;

    UINT64 Available = Ctx->CodeBase + Ctx->CodeSize - Ip;
    SIZE_T Count     = (Size < Available) ? Size : (SIZE_T)Available;

    memcpy(Buffer, Ctx->Code + (Ip - Ctx->CodeBase), Count);
    return (int)Count;
}

/**
 * @brief Capture the .text section of a process image
 *
 * @param Process
 * @param TextStart
 * @param TextEnd
 * @param Ctx
 *
 * @return BOOLEAN
 */
BOOLEAN
PtHelperCaptureImage(HANDLE Process, UINT64 * TextStart, UINT64 * TextEnd, IMAGE_SYMBOL_CONTEXT * Ctx)
{
    HMODULE            Ntdll = GetModuleHandleA("ntdll.dll");
    PFN_NT_QIP         NtQip = Ntdll ? (PFN_NT_QIP)GetProcAddress(Ntdll, "NtQueryInformationProcess") : NULL;
    PROC_BASIC_INFO    Pbi   = {0};
    ULONG              Ret   = 0;
    SIZE_T             Got   = 0;
    UINT64             Base  = 0;
    IMAGE_DOS_HEADER   Dos;
    IMAGE_NT_HEADERS64 Nt;
    UINT64             SectionBase;

    if (NtQip == NULL || NtQip(Process, 0, &Pbi, sizeof(Pbi), &Ret) < 0 || Pbi.PebBaseAddress == NULL)
        return FALSE;

    if (!ReadProcessMemory(Process, (PBYTE)Pbi.PebBaseAddress + 0x10, &Base, sizeof(Base), &Got) || Base == 0)
        return FALSE;

    if (!ReadProcessMemory(Process, (PVOID)Base, &Dos, sizeof(Dos), &Got) || Dos.e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    if (!ReadProcessMemory(Process, (PBYTE)Base + Dos.e_lfanew, &Nt, sizeof(Nt), &Got) || Nt.Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    Ctx->ImageBase = Base;
    SectionBase    = Base + Dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + Nt.FileHeader.SizeOfOptionalHeader;

    for (WORD i = 0; i < Nt.FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER Section;

        if (!ReadProcessMemory(Process, (PBYTE)SectionBase + (UINT64)i * sizeof(Section), &Section, sizeof(Section), &Got))
            return FALSE;

        if (memcmp(Section.Name, ".text", 6) != 0)
            continue;

        UINT64 Start = Base + Section.VirtualAddress;
        UINT64 Size  = Section.Misc.VirtualSize ? Section.Misc.VirtualSize : Section.SizeOfRawData;

        if (Size == 0)
            return FALSE;

        Ctx->Code = (UINT8 *)malloc((SIZE_T)Size);
        if (Ctx->Code == NULL)
            return FALSE;

        if (!ReadProcessMemory(Process, (PVOID)Start, Ctx->Code, (SIZE_T)Size, &Got) || Got != Size)
        {
            free(Ctx->Code);
            Ctx->Code = NULL;
            return FALSE;
        }

        Ctx->CodeBase = Start;
        Ctx->CodeSize = Size;
        *TextStart    = Start;
        *TextEnd      = Start + Size - 1;
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Resolve function address using symbol information
 *
 * @param Process
 * @param Path
 * @param Name
 * @param ImageBase
 * @param Start
 * @param End
 *
 * @return BOOLEAN
 */
BOOLEAN
PtHelperResolveFunction(HANDLE Process, const CHAR * Path, const CHAR * Name, UINT64 ImageBase, UINT64 * Start, UINT64 * End)
{
    union
    {
        SYMBOL_INFO Info;
        BYTE        Buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
    } Symbol   = {0};
    BOOLEAN Ok = FALSE;

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    if (!SymInitialize(Process, NULL, FALSE))
        return FALSE;

    if (SymLoadModuleEx(Process, NULL, Path, NULL, (DWORD64)ImageBase, 0, NULL, 0) != 0)
    {
        Symbol.Info.SizeOfStruct = sizeof(SYMBOL_INFO);
        Symbol.Info.MaxNameLen   = MAX_SYM_NAME;

        if (SymFromName(Process, Name, &Symbol.Info) && Symbol.Info.Address != 0)
        {
            *Start = Symbol.Info.Address;
            *End   = Symbol.Info.Address + (Symbol.Info.Size ? Symbol.Info.Size : 0x200) - 1;
            Ok     = TRUE;
        }
    }

    SymCleanup(Process);
    return Ok;
}

/**
 * @brief Get PT packet name
 *
 * @param Type
 *
 * @return const CHAR *
 */
const CHAR *
PtHelperPacketName(enum pt_packet_type Type)
{
    switch (Type)
    {
    case ppt_psb:
        return "PSB";
    case ppt_psbend:
        return "PSBEND";
    case ppt_pad:
        return "PAD";
    case ppt_fup:
        return "FUP";
    case ppt_tip:
        return "TIP";
    case ppt_tip_pge:
        return "TIP.PGE";
    case ppt_tip_pgd:
        return "TIP.PGD";
    case ppt_tnt_8:
        return "TNT8";
    case ppt_tnt_64:
        return "TNT64";
    case ppt_mode:
        return "MODE";
    case ppt_pip:
        return "PIP";
    case ppt_vmcs:
        return "VMCS";
    case ppt_cbr:
        return "CBR";
    case ppt_tsc:
        return "TSC";
    case ppt_tma:
        return "TMA";
    case ppt_mtc:
        return "MTC";
    case ppt_cyc:
        return "CYC";
    case ppt_ovf:
        return "OVF";
    case ppt_stop:
        return "STOP";
    case ppt_exstop:
        return "EXSTOP";
    case ppt_mnt:
        return "MNT";
    case ppt_ptw:
        return "PTW";
    default:
        return "?";
    }
}

/**
 * @brief Reconstruct IP from PT packet
 *
 * @param Packet
 * @param LastIp
 *
 * @return UINT64
 */
UINT64
PtHelperReconstructIp(const struct pt_packet_ip * Packet, UINT64 * LastIp)
{
    UINT64 Value = *LastIp;

    switch (Packet->ipc)
    {
    case pt_ipc_update_16:
        Value = (Value & ~0xffffull) | (Packet->ip & 0xffffull);
        break;
    case pt_ipc_update_32:
        Value = (Value & ~0xffffffffull) | (Packet->ip & 0xffffffffull);
        break;
    case pt_ipc_update_48:
        Value = (Value & ~0xffffffffffffull) | (Packet->ip & 0xffffffffffffull);
        break;
    case pt_ipc_sext_48:
        Value = Packet->ip & 0xffffffffffffull;
        if (Value & 0x800000000000ull)
            Value |= 0xffff000000000000ull;
        break;
    default:
        Value = Packet->ip;
        break;
    }

    *LastIp = Value;
    return Value;
}

/**
 * @brief Decode PT packets
 *
 * @param Cpu
 * @param Buffer
 * @param Size
 * @param ImageBase
 *
 * @return UINT64
 */
UINT64
PtHelperDecodeCorePackets(UINT32 Cpu, const UINT8 * Buffer, UINT64 Size, UINT64 ImageBase)
{
    struct pt_config           Config;
    struct pt_packet_decoder * Decoder;
    UINT64                     Count  = 0;
    UINT64                     LastIp = 0;
    int                        Status;

    pt_config_init(&Config);
    Config.begin = (UINT8 *)Buffer;
    Config.end   = (UINT8 *)Buffer + Size;

    Decoder = pt_pkt_alloc_decoder(&Config);
    if (Decoder == NULL)
    {
        ShowMessages("[-] core %u: cannot allocate packet decoder\n", Cpu);
        return 0;
    }

    for (;;)
    {
        Status = pt_pkt_sync_forward(Decoder);
        if (Status < 0)
            break;

        for (;;)
        {
            struct pt_packet Packet;

            Status = pt_pkt_next(Decoder, &Packet, sizeof(Packet));
            if (Status < 0)
                break;

            Count++;

            switch (Packet.type)
            {
            case ppt_tnt_8:
            case ppt_tnt_64:
                ShowMessages("    %-8s %2u  ", PtHelperPacketName(Packet.type), Packet.payload.tnt.bit_size);
                for (UINT8 Bit = 0; Bit < Packet.payload.tnt.bit_size && Bit < 64; Bit++)
                    putchar(((Packet.payload.tnt.payload >> (Packet.payload.tnt.bit_size - 1 - Bit)) & 1) ? 'T' : 'N');
                putchar('\n');
                break;

            case ppt_tip:
            case ppt_fup:
            case ppt_tip_pge:
            case ppt_tip_pgd:
                if (Packet.payload.ip.ipc == pt_ipc_suppressed)
                    ShowMessages("    %-8s (ip suppressed)\n", PtHelperPacketName(Packet.type));
                else
                {
                    UINT64 Ip = PtHelperReconstructIp(&Packet.payload.ip, &LastIp);
                    ShowMessages("    %-8s 0x%016llx  exe+0x%llx\n",
                                 PtHelperPacketName(Packet.type),
                                 (UINT64)Ip,
                                 (UINT64)(Ip - ImageBase));
                }
                break;

            case ppt_pip:
                ShowMessages("    %-8s cr3=0x%llx\n", PtHelperPacketName(Packet.type), (UINT64)Packet.payload.pip.cr3);
                break;

            case ppt_cbr:
                // ShowMessages("    %-8s ratio=%u\n", PtHelperPacketName(Packet.type), Packet.payload.cbr.ratio);
                break;

            case ppt_tsc:
                ShowMessages("    %-8s tsc=0x%llx\n", PtHelperPacketName(Packet.type), (UINT64)Packet.payload.tsc.tsc);
                break;

            default:
                // ShowMessages("    %-8s\n", PtHelperPacketName(Packet.type));
                break;
            }
        }
    }

    pt_pkt_free_decoder(Decoder);
    return Count;
}

/**
 * @brief Decode PT instructions
 *
 * @param Cpu
 * @param Buffer
 * @param Size
 * @param Ctx
 *
 * @return UINT64
 */
UINT64
PtHelperDecodeCore(UINT32 Cpu, const UINT8 * Buffer, UINT64 Size, IMAGE_SYMBOL_CONTEXT * Ctx)
{
    struct pt_config         Config;
    struct pt_insn_decoder * Decoder;
    struct pt_image *        Image;
    UINT64                   Count = 0;
    int                      Status;

    pt_config_init(&Config);
    Config.begin = (UINT8 *)Buffer;
    Config.end   = (UINT8 *)Buffer + Size;

    Decoder = pt_insn_alloc_decoder(&Config);
    if (Decoder == NULL)
    {
        ShowMessages("[-] core %u: cannot allocate instruction decoder\n", Cpu);
        return 0;
    }

    Image = pt_insn_get_image(Decoder);
    pt_image_set_callback(Image, PtHelperReadImage, Ctx);

    for (;;)
    {
        Status = pt_insn_sync_forward(Decoder);
        if (Status < 0)
            break;

        for (;;)
        {
            struct pt_insn Insn;

            while (Status & pts_event_pending)
            {
                struct pt_event Event;
                Status = pt_insn_event(Decoder, &Event, sizeof(Event));
                if (Status < 0)
                    break;
            }

            if (Status < 0 || (Status & pts_eos))
                break;

            Status = pt_insn_next(Decoder, &Insn, sizeof(Insn));
            if (Status < 0)
                break;

            ZydisDisassembledInstruction Disasm;
            ZydisMachineMode             Mode = (Insn.mode == ptem_32bit) ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64;

            if (ZYAN_SUCCESS(ZydisDisassembleIntel(Mode, Insn.ip, Insn.raw, Insn.size, &Disasm)))
                ShowMessages("    0x%016llx  exe+0x%-6llx  %s\n",
                             (UINT64)Insn.ip,
                             (UINT64)(Insn.ip - Ctx->ImageBase),
                             Disasm.text);
            else
                ShowMessages("    0x%016llx  (undecodable)\n", (UINT64)Insn.ip);

            Count++;
        }

        if (Status >= 0 && (Status & pts_eos))
            break;
    }

    pt_insn_free_decoder(Decoder);
    return Count;
}
