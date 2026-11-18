#pragma once

#ifndef HYPERDBG_VMM
#include <stdint.h>
typedef uint8_t  EPT_ORIGIN_BYTE;
typedef uint32_t EPT_ORIGIN_SIZE;
typedef int32_t  EPT_ORIGIN_INT32;
typedef int64_t  EPT_ORIGIN_INT64;
typedef uint64_t EPT_ORIGIN_ADDRESS;
#else
typedef UINT8  EPT_ORIGIN_BYTE;
typedef UINT32 EPT_ORIGIN_SIZE;
typedef INT32  EPT_ORIGIN_INT32;
typedef INT64  EPT_ORIGIN_INT64;
typedef UINT64 EPT_ORIGIN_ADDRESS;
#endif

/*
 * [DOWNSTREAM] Origin trampolines of an atomic EPT hook.
 *
 * The atomic entry patches one INT3 over the target, so an origin replays only
 * the instruction that INT3 covers and continues at Target + Length.
 *
 * Windows reads and writes another thread's context from a special APC
 * (PspGetSetContextInternal) that unwinds the thread's kernel stack from its
 * own frame to the user trap frame. A frame it cannot unwind fails
 * NtGetContextThread/NtSetContextThread with STATUS_UNSUCCESSFUL. Freeze and
 * suspend are normal kernel APCs, so a thread can stop on any instruction
 * boundary of a trampoline and stay there.
 *
 * The APC looks up every frame with RtlpLookupFunctionEntryForStackWalks. A
 * frame without a function entry is unwound as a leaf, whose return address
 * is [rsp], only if it lies inside a loaded image; a frame in executable pool
 * fails the call whatever the stack holds, and drivers cannot register unwind
 * data for pool memory. The buffer an origin is built in must therefore lie in
 * an image section without function entries: the EXEC_TRAMPOLINE pool
 * callback has to supply such memory (HyperDbg's own pool manager does not).
 *
 * Every boundary is then unwound as a leaf. Copying a prologue that pushes or
 * allocates breaks every boundary after its first stack write, and so does a
 * "push imm32 / mov [rsp+4], imm32 / ret" jump, whose first push leaves half
 * an address on top. These origins keep [rsp] at every boundary a return
 * address whose own unwind leads back to the caller, with each nonvolatile
 * register found where the hooked function's unwind data says:
 *
 *   Copy        a mov or lea that writes memory or a volatile register other
 *               than r10, executed as is, or one of two RIP-relative forms
 *               made absolute. rsp, r10, the flags and the nonvolatile
 *               registers stay as the caller left them, and [rsp] stays the
 *               caller's return address.
 *   StackAlloc  sub rsp, N becomes N/8 pushes of an address inside the
 *               origin; every pushed slot unwinds as one more leaf frame, so
 *               the chain still ends at the caller. The original leaves that
 *               area uninitialized too. A final cmp reproduces the flags of
 *               the sub.
 *   Push        push reg pushes the origin's own address as a placeholder (a
 *               leaf frame), covers it with
 *               AsmEptHookUnwindSkip8Body (an image frame that only skips the
 *               slot above it), overwrites the placeholder with the register
 *               and replaces the cover with Target + Length, whose own unwind
 *               data pops that register. A ret then enters the original.
 *
 * The others leave through jmp qword ptr [rip+0], which writes no stack.
 *
 * A guarded origin pushes Target + Length with push qword ptr [rip+disp] and
 * jumps to the caller's permanent tail, which is entered with the continuation
 * at [rsp]. The tail may clobber r10 and the arithmetic flags: the hooked
 * function's entry leaves both undefined (Windows x64 ABI), the displaced
 * instruction never writes r10, and it writes the flags only as the stack
 * allocation of a prologue, whose flags nothing reads.
 *
 * Any other first instruction (control transfers, other RIP-relative operands,
 * other writes of rsp, of r10 or of a nonvolatile register, flag-writing
 * arithmetic, LOCK/REP) is rejected and the hook is not installed.
 */

#define EPT_ORIGIN_KIND_COPY        1u
#define EPT_ORIGIN_KIND_MOV_RAX_RIP 2u
#define EPT_ORIGIN_KIND_CALL_RIP    3u
#define EPT_ORIGIN_KIND_PUSH        4u
#define EPT_ORIGIN_KIND_STACK_ALLOC 5u

#define EPT_ORIGIN_REGISTER_RSP 4u
#define EPT_ORIGIN_REGISTER_R10 10u
#define EPT_ORIGIN_REGISTER_R11 11u
#define EPT_ORIGIN_NO_REGISTER  0xffffffffu

typedef struct _EPT_ORIGIN_INSTRUCTION
{
    EPT_ORIGIN_SIZE Kind;
    EPT_ORIGIN_SIZE Register;   /* Push */
    EPT_ORIGIN_SIZE StackBytes; /* StackAlloc */
} EPT_ORIGIN_INSTRUCTION;

static __inline EPT_ORIGIN_INT32
EptOriginReadInt32(const EPT_ORIGIN_BYTE * Bytes)
{
    return (EPT_ORIGIN_INT32)((EPT_ORIGIN_SIZE)Bytes[0] | ((EPT_ORIGIN_SIZE)Bytes[1] << 8) |
                              ((EPT_ORIGIN_SIZE)Bytes[2] << 16) | ((EPT_ORIGIN_SIZE)Bytes[3] << 24));
}

/*
 * Registers a copied first instruction may write: volatile ones other than
 * r10. Writing rsp would break the leaf unwind, r10 belongs to the guarded
 * tail, and writing a nonvolatile register before the prologue saves it
 * would lose the caller's value. Index 4..7 of a byte form without REX is
 * AH..BH; rejecting those is only conservative.
 */
static __inline int
EptOriginCopyMayWrite(EPT_ORIGIN_SIZE Register)
{
    return Register == 0 || Register == 1 || Register == 2 || Register == 8 || Register == 9 ||
           Register == EPT_ORIGIN_REGISTER_R11;
}

/*
 * Copies one instruction to a trampoline. A trampoline buffer is not
 * guaranteed to lie within +/-2 GB of the original, so the two RIP-relative forms found
 * in ntoskrnl entries and in win32k syscall wrappers (which call a
 * session-global guard in their first bytes) are made absolute:
 *
 *   mov rax, qword ptr [rip+disp32]  ->  mov rax, imm64 / mov rax, [rax]
 *   call qword ptr [rip+disp32]      ->  mov r11, imm64 / call qword ptr [r11]
 *
 * Other instructions are copied unchanged. Returns the bytes written, or 0 if
 * they do not fit in Capacity.
 */
static __inline EPT_ORIGIN_SIZE
EptOriginRelocateInstruction(EPT_ORIGIN_BYTE *       Buffer,
                             EPT_ORIGIN_SIZE         Capacity,
                             const EPT_ORIGIN_BYTE * Instruction,
                             EPT_ORIGIN_SIZE         Length,
                             EPT_ORIGIN_ADDRESS      Address)
{
    EPT_ORIGIN_SIZE    DisplacementOffset = 0;
    EPT_ORIGIN_ADDRESS Absolute;
    EPT_ORIGIN_SIZE    Index;

    if (Length == 7 && Instruction[0] == 0x48 && Instruction[1] == 0x8B &&
        Instruction[2] == 0x05)
    {
        DisplacementOffset = 3;
    }
    else if ((Length == 7 && Instruction[0] == 0x48 && Instruction[1] == 0xFF &&
              Instruction[2] == 0x15) ||
             (Length == 6 && Instruction[0] == 0xFF && Instruction[1] == 0x15))
    {
        DisplacementOffset = Length - 4;
    }

    if (DisplacementOffset == 0)
    {
        if (Length > Capacity)
        {
            return 0;
        }
        for (Index = 0; Index < Length; Index++)
        {
            Buffer[Index] = Instruction[Index];
        }
        return Length;
    }

    if (Capacity < 13)
    {
        return 0;
    }
    Absolute = Address + Length +
               (EPT_ORIGIN_ADDRESS)(EPT_ORIGIN_INT64)EptOriginReadInt32(&Instruction[DisplacementOffset]);
    if (Instruction[1] == 0x8B)
    {
        Buffer[0]  = 0x48; /* mov rax, imm64 */
        Buffer[1]  = 0xB8;
        Buffer[10] = 0x48; /* mov rax, qword ptr [rax] */
        Buffer[11] = 0x8B;
        Buffer[12] = 0x00;
    }
    else
    {
        Buffer[0]  = 0x49; /* mov r11, imm64 */
        Buffer[1]  = 0xBB;
        Buffer[10] = 0x41; /* call qword ptr [r11] */
        Buffer[11] = 0xFF;
        Buffer[12] = 0x13;
    }
    for (Index = 0; Index < 8; Index++)
    {
        Buffer[2 + Index] = (EPT_ORIGIN_BYTE)(Absolute >> (Index * 8));
    }
    return 13;
}

/*
 * Classifies the instruction an atomic entry displaces. Returns 0 for the
 * forms listed at the top of this file as rejected.
 */
static __inline int
EptHookAtomicClassifyFirstInstruction(const EPT_ORIGIN_BYTE * Bytes,
                                      EPT_ORIGIN_SIZE         Length,
                                      EPT_ORIGIN_INSTRUCTION * Out)
{
    EPT_ORIGIN_SIZE Offset = 0;
    EPT_ORIGIN_SIZE Destination;
    int             Legacy = 0;
    EPT_ORIGIN_BYTE Rex    = 0;
    EPT_ORIGIN_BYTE Op;
    EPT_ORIGIN_BYTE ModRm;

    if (Bytes == 0 || Out == 0 || Length == 0)
    {
        return 0;
    }
    Out->Kind       = 0;
    Out->Register   = EPT_ORIGIN_NO_REGISTER;
    Out->StackBytes = 0;

    /* Operand-size and segment prefixes only; LOCK, REP and address-size fall through to rejection. */
    while (Offset < Length &&
           (Bytes[Offset] == 0x66 || Bytes[Offset] == 0x2E || Bytes[Offset] == 0x36 ||
            Bytes[Offset] == 0x3E || Bytes[Offset] == 0x26 || Bytes[Offset] == 0x64 ||
            Bytes[Offset] == 0x65))
    {
        Legacy = 1;
        Offset++;
    }
    if (Offset < Length && (Bytes[Offset] & 0xF0) == 0x40)
    {
        Rex = Bytes[Offset++];
    }
    if (Offset >= Length)
    {
        return 0;
    }
    Op = Bytes[Offset++];

    /* push r64 */
    if (Op >= 0x50 && Op <= 0x57)
    {
        EPT_ORIGIN_SIZE Register = (EPT_ORIGIN_SIZE)(Op & 7u) | ((Rex & 1u) ? 8u : 0u);
        if (Legacy || Offset != Length || Register == EPT_ORIGIN_REGISTER_RSP ||
            Register == EPT_ORIGIN_REGISTER_R10 || Register == EPT_ORIGIN_REGISTER_R11)
        {
            return 0;
        }
        Out->Kind     = EPT_ORIGIN_KIND_PUSH;
        Out->Register = Register;
        return 1;
    }

    /* sub rsp, imm8 / sub rsp, imm32 */
    if ((Op == 0x83 || Op == 0x81) && Rex == 0x48 && !Legacy && Offset < Length &&
        Bytes[Offset] == 0xEC)
    {
        EPT_ORIGIN_INT32 Immediate;
        Offset++;
        if (Op == 0x83)
        {
            if (Offset + 1 != Length)
            {
                return 0;
            }
            Immediate = (signed char)Bytes[Offset];
        }
        else
        {
            if (Offset + 4 != Length)
            {
                return 0;
            }
            Immediate = EptOriginReadInt32(&Bytes[Offset]);
        }
        if (Immediate <= 0 || (Immediate & 7) != 0)
        {
            return 0;
        }
        Out->Kind       = EPT_ORIGIN_KIND_STACK_ALLOC;
        Out->StackBytes = (EPT_ORIGIN_SIZE)Immediate;
        return 1;
    }

    /* The two relocated RIP-relative forms (EptOriginRelocateInstruction). */
    if (!Legacy && Length == 7 && Offset == 2 && Rex == 0x48 && Op == 0x8B && Bytes[2] == 0x05)
    {
        Out->Kind = EPT_ORIGIN_KIND_MOV_RAX_RIP;
        return 1;
    }
    if (!Legacy && Op == 0xFF && Offset < Length && Bytes[Offset] == 0x15 &&
        ((Rex == 0 && Length == 6) || (Rex == 0x48 && Length == 7)))
    {
        Out->Kind = EPT_ORIGIN_KIND_CALL_RIP;
        return 1;
    }

    /* mov r/m, r; mov r, r/m; lea r, m; mov r/m, imm */
    if (Op == 0x88 || Op == 0x89 || Op == 0x8A || Op == 0x8B || Op == 0x8D || Op == 0xC6 ||
        Op == 0xC7)
    {
        EPT_ORIGIN_SIZE Mod;
        if (Offset >= Length)
        {
            return 0;
        }
        ModRm = Bytes[Offset];
        Mod   = (EPT_ORIGIN_SIZE)(ModRm >> 6);
        if ((Mod == 0 && (ModRm & 7u) == 5) || (Op == 0x8D && Mod == 3) ||
            ((Op == 0xC6 || Op == 0xC7) && ((ModRm >> 3) & 7u) != 0))
        {
            return 0;
        }
        if (Op == 0x8A || Op == 0x8B || Op == 0x8D)
        {
            Destination = (EPT_ORIGIN_SIZE)((ModRm >> 3) & 7u) | ((Rex & 4u) ? 8u : 0u);
        }
        else if (Mod == 3)
        {
            Destination = (EPT_ORIGIN_SIZE)(ModRm & 7u) | ((Rex & 1u) ? 8u : 0u);
        }
        else
        {
            Destination = EPT_ORIGIN_NO_REGISTER;
        }
        if (Destination != EPT_ORIGIN_NO_REGISTER && !EptOriginCopyMayWrite(Destination))
        {
            return 0;
        }
        Out->Kind = EPT_ORIGIN_KIND_COPY;
        return 1;
    }

    /* mov r8, imm8 / mov r, imm */
    if (Op >= 0xB0 && Op <= 0xBF)
    {
        if (!EptOriginCopyMayWrite((EPT_ORIGIN_SIZE)(Op & 7u) | ((Rex & 1u) ? 8u : 0u)))
        {
            return 0;
        }
        Out->Kind = EPT_ORIGIN_KIND_COPY;
        return 1;
    }
    return 0;
}

#define EPT_ORIGIN_MAX_DATA 3u

typedef struct _EPT_ORIGIN_WRITER
{
    EPT_ORIGIN_BYTE *  Buffer;
    EPT_ORIGIN_SIZE    Capacity;
    EPT_ORIGIN_SIZE    Size;
    int                Overflow;
    EPT_ORIGIN_SIZE    DataCount;
    EPT_ORIGIN_SIZE    FixupAt[EPT_ORIGIN_MAX_DATA];
    EPT_ORIGIN_ADDRESS Data[EPT_ORIGIN_MAX_DATA];
} EPT_ORIGIN_WRITER;

static __inline void
EptOriginEmit(EPT_ORIGIN_WRITER * Writer, const EPT_ORIGIN_BYTE * Bytes, EPT_ORIGIN_SIZE Count)
{
    EPT_ORIGIN_SIZE Index;
    if (Writer->Overflow || Count > Writer->Capacity - Writer->Size)
    {
        Writer->Overflow = 1;
        return;
    }
    for (Index = 0; Index < Count; Index++)
    {
        Writer->Buffer[Writer->Size + Index] = Bytes[Index];
    }
    Writer->Size += Count;
}

static __inline void
EptOriginEmitValue(EPT_ORIGIN_WRITER * Writer, EPT_ORIGIN_ADDRESS Value, EPT_ORIGIN_SIZE Count)
{
    EPT_ORIGIN_BYTE Bytes[8];
    EPT_ORIGIN_SIZE Index;
    for (Index = 0; Index < Count; Index++)
    {
        Bytes[Index] = (EPT_ORIGIN_BYTE)(Value >> (Index * 8));
    }
    EptOriginEmit(Writer, Bytes, Count);
}

/* FF /6 (push) or FF /4 (jmp) qword ptr [rip+disp32] on a qword placed after the code. */
static __inline void
EptOriginEmitRipQword(EPT_ORIGIN_WRITER * Writer, EPT_ORIGIN_BYTE ModRm, EPT_ORIGIN_ADDRESS Value)
{
    EPT_ORIGIN_BYTE Opcode[2];
    if (Writer->DataCount >= EPT_ORIGIN_MAX_DATA)
    {
        Writer->Overflow = 1;
        return;
    }
    Opcode[0] = 0xFF;
    Opcode[1] = ModRm;
    EptOriginEmit(Writer, Opcode, 2);
    Writer->FixupAt[Writer->DataCount] = Writer->Size;
    Writer->Data[Writer->DataCount++]  = Value;
    EptOriginEmitValue(Writer, 0, 4);
}

static __inline int
EptOriginFinish(EPT_ORIGIN_WRITER * Writer, EPT_ORIGIN_SIZE * Size)
{
    EPT_ORIGIN_SIZE Index;
    for (Index = 0; Index < Writer->DataCount; Index++)
    {
        EPT_ORIGIN_SIZE At = Writer->Size;
        EPT_ORIGIN_SIZE Displacement;
        EptOriginEmitValue(Writer, Writer->Data[Index], 8);
        if (Writer->Overflow)
        {
            return 0;
        }
        Displacement = At - (Writer->FixupAt[Index] + 4);
        Writer->Buffer[Writer->FixupAt[Index] + 0] = (EPT_ORIGIN_BYTE)Displacement;
        Writer->Buffer[Writer->FixupAt[Index] + 1] = (EPT_ORIGIN_BYTE)(Displacement >> 8);
        Writer->Buffer[Writer->FixupAt[Index] + 2] = (EPT_ORIGIN_BYTE)(Displacement >> 16);
        Writer->Buffer[Writer->FixupAt[Index] + 3] = (EPT_ORIGIN_BYTE)(Displacement >> 24);
    }
    if (Writer->Overflow)
    {
        return 0;
    }
    *Size = Writer->Size;
    return 1;
}

#define EPT_ORIGIN_RIP_PUSH 0x35u
#define EPT_ORIGIN_RIP_JMP  0x25u

/*
 * Builds the plain origin (GuardedTail == 0) or the guarded origin of an
 * atomic hook into Buffer, the executable memory it will run from, which must
 * lie in an image section without function entries (see above).
 * UnwindSkip8 is the address of AsmEptHookUnwindSkip8Body.
 */
static __inline int
EptHookAtomicBuildOrigin(EPT_ORIGIN_BYTE *       Buffer,
                         EPT_ORIGIN_SIZE         Capacity,
                         const EPT_ORIGIN_BYTE * Instruction,
                         EPT_ORIGIN_SIZE         Length,
                         EPT_ORIGIN_ADDRESS      Target,
                         EPT_ORIGIN_ADDRESS      UnwindSkip8,
                         EPT_ORIGIN_ADDRESS      GuardedTail,
                         EPT_ORIGIN_SIZE *       OriginSize)
{
    EPT_ORIGIN_INSTRUCTION First;
    EPT_ORIGIN_WRITER      Writer       = {0};
    EPT_ORIGIN_ADDRESS     Continuation = Target + Length;

    if (Buffer == 0 || OriginSize == 0 || UnwindSkip8 == 0 ||
        !EptHookAtomicClassifyFirstInstruction(Instruction, Length, &First))
    {
        return 0;
    }
    Writer.Buffer   = Buffer;
    Writer.Capacity = Capacity;

    if (First.Kind == EPT_ORIGIN_KIND_PUSH)
    {
        /* mov r11, imm64 (continuation) */
        static const EPT_ORIGIN_BYTE MovR11[] = {0x49, 0xBB};
        /* mov qword ptr [rsp], r11 */
        static const EPT_ORIGIN_BYTE StoreR11[] = {0x4C, 0x89, 0x1C, 0x24};
        static const EPT_ORIGIN_BYTE Ret[]      = {0xC3};
        EPT_ORIGIN_BYTE StoreRegister[5];

        /* mov qword ptr [rsp+8], reg */
        StoreRegister[0] = (EPT_ORIGIN_BYTE)(0x48u | ((First.Register & 8u) ? 4u : 0u));
        StoreRegister[1] = 0x89;
        StoreRegister[2] = (EPT_ORIGIN_BYTE)(0x44u | ((First.Register & 7u) << 3));
        StoreRegister[3] = 0x24;
        StoreRegister[4] = 0x08;

        EptOriginEmit(&Writer, MovR11, sizeof(MovR11));
        EptOriginEmitValue(&Writer, Continuation, 8);
        /* [origin][caller]: the origin's own address is a leaf frame */
        EptOriginEmitRipQword(&Writer, EPT_ORIGIN_RIP_PUSH, (EPT_ORIGIN_ADDRESS)Buffer);
        /* [skip8][origin][caller]: the cover skips the slot that becomes reg */
        EptOriginEmitRipQword(&Writer, EPT_ORIGIN_RIP_PUSH, UnwindSkip8);
        /* [skip8][reg][caller] */
        EptOriginEmit(&Writer, StoreRegister, sizeof(StoreRegister));
        /* [Target+Length][reg][caller]: the original's unwind data pops reg */
        EptOriginEmit(&Writer, StoreR11, sizeof(StoreR11));
        if (GuardedTail == 0)
        {
            EptOriginEmit(&Writer, Ret, sizeof(Ret));
        }
        else
        {
            EptOriginEmitRipQword(&Writer, EPT_ORIGIN_RIP_JMP, GuardedTail);
        }
        return EptOriginFinish(&Writer, OriginSize);
    }

    if (First.Kind == EPT_ORIGIN_KIND_STACK_ALLOC)
    {
        /* mov r10d, imm32 (slot count) */
        static const EPT_ORIGIN_BYTE MovR10d[] = {0x41, 0xBA};
        /*
         * lea rax, [rip+0]   ; an address inside the origin: each pushed copy is a leaf frame
         * next: push rax
         * dec r10d
         * jnz next
         */
        static const EPT_ORIGIN_BYTE Fill[] = {0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x50,
                                               0x41, 0xFF, 0xCA, 0x75, 0xFA};
        /* lea rax, [rsp+imm32] (the entry rsp) */
        static const EPT_ORIGIN_BYTE LeaRax[] = {0x48, 0x8D, 0x84, 0x24};
        /* cmp rax, imm32: the flags of sub rsp, imm on the entry rsp */
        static const EPT_ORIGIN_BYTE CmpRax[] = {0x48, 0x3D};

        EptOriginEmit(&Writer, MovR10d, sizeof(MovR10d));
        EptOriginEmitValue(&Writer, First.StackBytes / 8u, 4);
        EptOriginEmit(&Writer, Fill, sizeof(Fill));
        EptOriginEmit(&Writer, LeaRax, sizeof(LeaRax));
        EptOriginEmitValue(&Writer, First.StackBytes, 4);
        EptOriginEmit(&Writer, CmpRax, sizeof(CmpRax));
        EptOriginEmitValue(&Writer, First.StackBytes, 4);
    }
    else
    {
        EPT_ORIGIN_SIZE Written = EptOriginRelocateInstruction(Buffer, Capacity, Instruction, Length, Target);
        if (Written == 0)
        {
            return 0;
        }
        Writer.Size = Written;
    }

    if (GuardedTail == 0)
    {
        EptOriginEmitRipQword(&Writer, EPT_ORIGIN_RIP_JMP, Continuation);
    }
    else
    {
        EptOriginEmitRipQword(&Writer, EPT_ORIGIN_RIP_PUSH, Continuation);
        EptOriginEmitRipQword(&Writer, EPT_ORIGIN_RIP_JMP, GuardedTail);
    }
    return EptOriginFinish(&Writer, OriginSize);
}
