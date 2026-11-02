#pragma once

#ifndef HYPERDBG_VMM
#include <stddef.h>
#include <stdint.h>
typedef uint64_t EPT_BP_ADDRESS;
typedef uint8_t EPT_BP_BYTE;
#else
typedef UINT64 EPT_BP_ADDRESS;
typedef BYTE EPT_BP_BYTE;
#endif

/* [DOWNSTREAM] A fake page is owned by GPA; breakpoint bytes are owned by
 * offsets within that page, not by one process's spelling of the VA. */
static __inline int
EptHiddenBreakpointSameOffset(EPT_BP_ADDRESS Left, EPT_BP_ADDRESS Right)
{
    return ((Left ^ Right) & 0xfffu) == 0;
}

static __inline int
EptHiddenBreakpointSamePage(EPT_BP_ADDRESS Left, EPT_BP_ADDRESS Right)
{
    return (Left >> 12) == (Right >> 12);
}

static __inline EPT_BP_BYTE
EptHiddenBreakpointPreviousByte(const EPT_BP_ADDRESS * Addresses,
                               const EPT_BP_BYTE * PreviousBytes,
                               size_t Count,
                               EPT_BP_ADDRESS Address,
                               EPT_BP_BYTE UnpatchedByte)
{
    size_t Index;
    for (Index = 0; Index < Count; Index++)
    {
        if (EptHiddenBreakpointSameOffset(Addresses[Index], Address))
            return PreviousBytes[Index];
    }
    return UnpatchedByte;
}

static __inline int
EptHiddenBreakpointHasOtherOffset(const EPT_BP_ADDRESS * Addresses,
                                 size_t Count,
                                 size_t RemovedIndex)
{
    size_t Index;
    for (Index = 0; Index < Count; Index++)
    {
        if (Index != RemovedIndex &&
            EptHiddenBreakpointSameOffset(Addresses[Index], Addresses[RemovedIndex]))
            return 1;
    }
    return 0;
}

typedef int (*EPT_HIDDEN_READ_PAGING_ENTRY)(void * Context, EPT_BP_ADDRESS Address, EPT_BP_ADDRESS * Entry);

/* Bounded guest-CR3 walk. It neither switches host CR3 nor dereferences a
 * guest VA. The reader supplies the existing per-CPU physical memory mapper. */
static __inline int
EptHiddenBreakpointTranslate(EPT_BP_ADDRESS GuestCr3,
                             EPT_BP_ADDRESS Address,
                             int FiveLevelPaging,
                             EPT_HIDDEN_READ_PAGING_ENTRY Read,
                             void * Context,
                             EPT_BP_ADDRESS * PhysicalAddress)
{
    static const unsigned Shifts[4] = {39, 30, 21, 12};
    const EPT_BP_ADDRESS AddressMask = 0x000ffffffffff000ull;
    EPT_BP_ADDRESS Table = GuestCr3 & AddressMask;
    EPT_BP_ADDRESS Top = Address >> 48;
    unsigned Level;
    if (FiveLevelPaging || Read == NULL || PhysicalAddress == NULL ||
        (((Address >> 47) & 1u) ? Top != 0xffffu : Top != 0))
        return 0;
    for (Level = 0; Level < 4; Level++)
    {
        EPT_BP_ADDRESS Entry = 0;
        if (!Read(Context, Table + ((Address >> Shifts[Level]) & 511u) * 8u, &Entry) ||
            (Entry & 1u) == 0)
            return 0;
        if (Level == 0 && (Entry & 0x80u) != 0)
            return 0;
        if ((Level == 1 || Level == 2) && (Entry & 0x80u) != 0)
        {
            const EPT_BP_ADDRESS OffsetMask = (1ull << Shifts[Level]) - 1u;
            *PhysicalAddress = (Entry & AddressMask & ~OffsetMask) | (Address & OffsetMask);
            return 1;
        }
        Table = Entry & AddressMask;
    }
    *PhysicalAddress = Table | (Address & 0xfffu);
    return 1;
}
