#pragma once

#ifndef HYPERDBG_VMM
#include <stddef.h>
#include <stdint.h>
typedef uint32_t EPT_POOL_COUNT;
#else
typedef UINT32 EPT_POOL_COUNT;
#endif

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
