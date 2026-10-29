#pragma once

#ifndef HYPERDBG_VMM
#include <stddef.h>
#include <stdint.h>
typedef uint32_t EPT_POOL_COUNT;
typedef uint64_t EPT_POOL_ADDRESS;
#else
typedef UINT32 EPT_POOL_COUNT;
typedef UINT64 EPT_POOL_ADDRESS;
#endif

typedef int (*EPT_READ_LARGE_PAGE_EFFECT)(void *Context,
                                          EPT_POOL_COUNT Core,
                                          EPT_POOL_ADDRESS PhysicalPage,
                                          int *LargePage);

static __inline int
EptCountRequiredSplits(EPT_POOL_ADDRESS PhysicalPage,
                       EPT_POOL_COUNT ProcessorCount,
                       EPT_READ_LARGE_PAGE_EFFECT Read,
                       void *Context,
                       EPT_POOL_COUNT *Required)
{
    EPT_POOL_COUNT Core;
    if (Read == NULL || Required == NULL || ProcessorCount == 0)
    {
        return 0;
    }
    *Required = 0;
    for (Core = 0; Core < ProcessorCount; Core++)
    {
        int LargePage;
        if (!Read(Context, Core, PhysicalPage, &LargePage))
        {
            return 0;
        }
        if (LargePage) { ++*Required; }
    }
    return 1;
}

static __inline int
EptDemandIdentityMatches(EPT_POOL_ADDRESS ExpectedPage,
                         EPT_POOL_ADDRESS ActualPage,
                         EPT_POOL_COUNT ExpectedProcessors,
                         EPT_POOL_COUNT ActualProcessors,
                         EPT_POOL_ADDRESS ExpectedInstance,
                         EPT_POOL_ADDRESS ActualInstance)
{
    return ExpectedPage != 0 && ExpectedPage == ActualPage &&
           ExpectedProcessors != 0 && ExpectedProcessors == ActualProcessors &&
           ExpectedInstance != 0 && ExpectedInstance == ActualInstance;
}

/* The queue effects are shared by the VMM reserve wrappers and local tests.
 * Each callback is attempted even if a previous request could not be queued. */
typedef struct _EPT_POOL_RESERVATION_REQUEST
{
    size_t Size;
    EPT_POOL_COUNT Count;
    EPT_POOL_COUNT Intention;
} EPT_POOL_RESERVATION_REQUEST;

typedef int (*EPT_POOL_ENQUEUE_EFFECT)(void *Context,
                                      size_t Size,
                                      EPT_POOL_COUNT Count,
                                      EPT_POOL_COUNT Intention);

static __inline int
EptQueuePoolReservationBatch(const EPT_POOL_RESERVATION_REQUEST *Requests,
                             EPT_POOL_COUNT RequestCount,
                             EPT_POOL_ENQUEUE_EFFECT Enqueue,
                             void *Context)
{
    EPT_POOL_COUNT Index;
    int Queued = 1;
    if (Requests == NULL || RequestCount == 0 || Enqueue == NULL)
    {
        return 0;
    }
    for (Index = 0; Index < RequestCount; Index++)
    {
        if (Requests[Index].Count != 0)
        {
            if (!Enqueue(Context, Requests[Index].Size,
                         Requests[Index].Count, Requests[Index].Intention))
            {
                Queued = 0;
            }
        }
    }
    return Queued;
}
