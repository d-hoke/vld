////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - Internal C++ Heap Management
//  Copyright (c) 2005-2014 VLD Team
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//
//  See COPYING.txt for the full terms of the GNU Lesser General Public License.
//
////////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

#define VLDBUILD     // Declares that we are building Visual Leak Detector.
#include "ntapi.h"   // Provides access to NT APIs.
#include "vldheap.h" // Provides access to VLD's internal heap data structures.
#include "criticalsection.h"
#undef new           // Do not map "new" to VLD's new operator in this file

// Global variables.
vldblockheader_t *g_vldBlockList = NULL; // List of internally allocated blocks on VLD's private heap.
vldblockheader_t *g_vldBlockListDelayedFree = NULL;
uint32_t          g_vldDelayedFreeCount = 0;
HANDLE            g_vldHeap;             // VLD's private heap.
CriticalSection   g_vldHeapLock;         // Serializes access to VLD's private heap.

// Local helper functions.
inline void* vldnew (size_t size, const char *file, int line);
inline void vlddelete (void *block);

// scalar new operator - New operator used to allocate a scalar memory block
//   from VLD's private heap.
//
//  - size (IN): Size of the memory block to be allocated.
//
//  - file (IN): The name of the file from which this function is being
//      called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    If the allocation succeeds, a pointer to the allocated memory block is
//    returned. If the allocation fails, NULL is returned.
//
void* operator new (size_t size, const char *file, int line)
{
    return vldnew(size, file, line);
}

// vector new operator - New operator used to allocate a vector memory block
//   from VLD's private heap.
//
//  - size (IN): Size of the memory block to be allocated.
//
//  - file (IN): The name of the file from which this function is being
//      called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    If the allocation succeeds, a pointer to the allocated memory block is
//    returned. If the allocation fails, NULL is returned.
//
void* operator new [] (size_t size, const char *file, int line)
{
    return vldnew(size, file, line);
}

// scalar delete operator - Delete operator used to free internally used memory
//   back to VLD's private heap.
//
//  - block (IN): Pointer to the scalar memory block to free.
//
//  Return Value:
//
//    None.
//
void operator delete (void *block)
{
    vlddelete(block);
}

// vector delete operator - Delete operator used to free internally used memory
//   back to VLD's private heap.
//
//  - block (IN): Pointer to the vector memory block to free.
//
//  Return Value:
//
//    None.
//
void operator delete [] (void *block)
{
    vlddelete(block);
}

// scalar delete operator - Delete operator used to free memory partially
//   allocated by new in the event that the corresponding new operator throws
//   an exception.
//
//  Note: This version of the delete operator should never be called directly.
//    The compiler automatically generates calls to this function as needed.
//
void operator delete (void *block, const char *, int)
{
    vlddelete(block);
}

// vector delete operator - Delete operator used to free memory partially
//   allocated by new in the event that the corresponding new operator throws
//   an exception.
//
//  Note: This version of the delete operator should never be called directly.
//    The compiler automatically generates calls to this function as needed.
//
void operator delete [] (void *block, const char *, int)
{
    vlddelete(block);
}

//==========================================================================
CriticalSection g_bktcachecs;
struct POW2BucketCacheAllocator
{
    //std::mutex m_mtx;
    //CriticalSection cs;
    struct overhead
    {
        size_t paddedsz;
        union {
            unsigned bucket;
            overhead *next;
        };
        //const unsigned align = 32;
        //const unsigned fillsz = align - ((sizeof(hd)+align-1) % align);
        //char fill[fillsz];
        char fill[16]; //size this for padding to 32 byte boundary
    };
    unsigned padton(unsigned val, unsigned padtomultipleval)
    {
        //return padto - ((n + padto) % padto);
        return val + padtomultipleval - 1 - (val + padtomultipleval - 1) % padtomultipleval;
    }
    POW2BucketCacheAllocator()
    {
        //cs.Initialize();
        memset(CacheLists, 0, sizeof(CacheLists));
        memset(CacheListCounts, 0, sizeof(CacheListCounts));
    }
    void *alloc(size_t n);
#if 1
    ;
#else
    {
        const unsigned align = 32;
        size_t paddedn = n + padton(sizeof(overhead), align);
        unsigned hibit = 1;

        size_t modpaddedn = paddedn;
        unsigned bucket = 0;
        while ((modpaddedn >>= 1) && modpaddedn)
        {
            hibit <<= 1;
            ++bucket;
        }

        if (bucket < 5) //granularity on x64 windows
            bucket = 5;
#if 0
        size_t amt = 1 << (hibit + 1);
        unsigned nexthibit = 1;
        if (modpaddedn)// && (paddedn & amt))
        {
            unsigned nexthibit = 1;
            while (modpaddedn >>= 1 && modpaddedn)
                nexthibit <<= 1;
            size_t lesseramt = 1 << nexthibit;

        }
#endif
        void *pitem = CacheLists[bucket];
        if (!pitem)
        {
            pitem = malloc(paddedn);
            (*(overhead *)pitem).paddedsz = paddedn;
            (*(overhead *)pitem).bucket = bucket;
        }
        else
        {
            CacheLists[bucket] = ((overhead*)CacheLists[bucket])->next;
            ((overhead*)pitem)->bucket = bucket;
            CacheListCounts[bucket]--;
        }
        //hmm, prob. need to deal with alignment...
        return (char*)pitem + padton(sizeof(overhead), 32);
    }
#endif

    void dealloc(void *p)
#if 1
        ;
#else
    {
        overhead *itemtofree = (overhead*)((char*)p - padton(sizeof(overhead), 32));
        auto bucket = itemtofree->bucket;
        itemtofree->next = CacheLists[bucket];
        CacheLists[bucket] = itemtofree;
        CacheListCounts[bucket]++;
    }
#endif
    overhead *CacheLists[65];
    size_t CacheListCounts[65];
};

const bool passthrough = false;

//done here (at least for now) instead of in class to avoid massive rebuild time...
uint64_t cntTotalAllocs[65];
uint64_t cntTotalDeallocs[65];
uint64_t cntOutstandingAllocs[65];
uint64_t cntPeakAllocs[65];
uint64_t cntCacheHits[65];
uint64_t cntCacheMisses[65];

struct POW2BucketCacheAllocator g_POW2BucketCacheAllocator;
const unsigned align = 32;
#if 01
void *POW2BucketCacheAllocator::alloc(size_t n)
{
    if (passthrough) //return malloc(n);
        return RtlAllocateHeap(g_vldHeap, 0x0, n);

    if (n > UINT_MAX)
        __debugbreak();

    //if (n > 1000000000)
    //	__debugbreak();

    size_t paddedn = n + padton(sizeof(overhead), align);
    unsigned hibit = 1;

    if (paddedn - n < align)
        __debugbreak();

    size_t modpaddedn = paddedn;
    unsigned bucket = 0;
    while ((modpaddedn >>= 1) && modpaddedn)
    {
        hibit <<= 1;
        ++bucket;
    }

    if (bucket < 5) //granularity 32 bytes on x64 windows
        bucket = 5;
    else if (bucket > 63) //we double, so 63 is max...
        __debugbreak();
#if 0
    size_t amt = 1 << (hibit + 1);
    unsigned nexthibit = 1;
    if (modpaddedn)// && (paddedn & amt))
    {
        unsigned nexthibit = 1;
        while (modpaddedn >>= 1 && modpaddedn)
            nexthibit <<= 1;
        size_t lesseramt = 1 << nexthibit;

    }
#endif
    overhead *pitem;
    //std::unique_lock<decltype(m_mtx)> ul(m_mtx);
    CriticalSectionLocker<> scopelock(g_bktcachecs); // (this->cs);
    ++cntTotalAllocs[bucket];
    if (++cntOutstandingAllocs[bucket] > cntPeakAllocs[bucket])
        cntPeakAllocs[bucket] = cntTotalAllocs[bucket];
    pitem = (overhead *)CacheLists[bucket];
    if (!pitem)
    {
        //ul.unlock();
        //pitem = (overhead *)malloc(paddedn);
        auto allocamt = 1llu << (bucket + 1);
        if (allocamt < paddedn)
            __debugbreak();
        cntCacheMisses[bucket] += 1;
        //if (!(pitem = (overhead *)malloc(allocamt)))
        //header = (vldblockheader_t*)RtlAllocateHeap(g_vldHeap, 0x0, size + sizeof(vldblockheader_t));
        if(!(pitem = (overhead *)RtlAllocateHeap(g_vldHeap, 0x0, allocamt) ))
        {
            //Logging::ODSPrintf(L"excessive malloc, %llu user request, bucket req %llu failed!\n", n, allocamt);
            if (pitem = (overhead *)malloc(paddedn))
            {
                pitem->paddedsz = paddedn;
                pitem->bucket = 128;
                auto retaddr = (char*)pitem + padton(sizeof(overhead), align);
                return retaddr; // (char*)pitem + padton(sizeof(overhead), align);
            }
            __debugbreak();
            //Logging::ODSPrintf(L"excessive malloc, %llu paddedn request, bucket req %llu complete failure!\n", paddedn, allocamt);
            return 0;
        }
        pitem->paddedsz = paddedn;
        pitem->bucket = bucket;
        if (sizeof(pitem->fill))
        {
            memset(pitem->fill, '\xfc', sizeof(pitem->fill));
        }
    }
    else
    {
        if (paddedn > (1 << (bucket + 1)))
            __debugbreak();
        cntCacheHits[bucket] -= 1;
        //if (pitem->bucket != bucket)
        //	__debugbreak();
        CacheLists[bucket] = (overhead*)CacheLists[bucket]->next; //((overhead*)CacheLists[bucket])->next;
        CacheListCounts[bucket]--;
        //ul.unlock();
        pitem->bucket = bucket;
        pitem->paddedsz = paddedn;
    }
    //hmm, prob. need to deal with alignment...
    auto retaddr = (char*)pitem + padton(sizeof(overhead), align);
    return retaddr; // (char*)pitem + padton(sizeof(overhead), align);
}
#endif

#if 1
void POW2BucketCacheAllocator::dealloc(void *p)
{
    if (passthrough)
    {
        //free(p);
        RtlFreeHeap(g_vldHeap, 0x0, p);
        return;
    }
    overhead *itemtofree = (overhead*)((char*)p - padton(sizeof(overhead), align));
    auto bucket = itemtofree->bucket;
    if ((bucket > 63) || (itemtofree->paddedsz > (1llu << (bucket + 1))))
    {
        if (bucket == 128)
        {
            free(itemtofree);
            //std::unique_lock<decltype(m_mtx)> ul(m_mtx);
            CriticalSectionLocker<> scopeLock(g_bktcachecs); // (this->cs);
            --cntOutstandingAllocs[bucket];
            return;
        }
        __debugbreak();

    }
    {
        //std::unique_lock<decltype(m_mtx)> ul(m_mtx);
        CriticalSectionLocker<> scopeLock(g_bktcachecs); // (this->cs);
        --cntOutstandingAllocs[bucket];
        ++cntTotalDeallocs[bucket];
        itemtofree->next = CacheLists[bucket];
        //memset(p, '\xdb', itemtofree->paddedsz); //'DeletedBlock'
        CacheLists[bucket] = itemtofree;
        CacheListCounts[bucket]++;
    }
}
#endif

//============================================================================


// vldnew - Local helper function that actually allocates memory from VLD's
//   private heap. Prepends a header, which is used for bookkeeping information
//   that allows VLD to detect and report internal memory leaks, to the returned
//   block, but the header is transparent to the caller because the returned
//   pointer points to the usable section of memory requested by the caller, it
//   does not point to the block header.
//
//  - size (IN): Size of the memory block to be allocated.
//
//  - file (IN): Name of the file that called the new operator.
//
//  - line (IN): Line, in the above file, at which the new operator was called.
//
//  Return Value:
//
//    If the memory allocation succeeds, a pointer to the allocated memory
//    block is returned. If the allocation fails, NULL is returned.
//
static SIZE_T     serialnumber = 0;
//Note: VLD_SIZET and SIZE_T may not be same, ignoring that...
//VLD_SIZET is at this typing, 'size_t'
extern "C"
__declspec(dllexport) size_t AllocSeqNumber() { return serialnumber; } //provide external visibility

vldblockheader_t *vldbhcache ;
void* vldnew (size_t size, const char *file, int line)
{
    vldblockheader_t *header;
    //header = (vldblockheader_t*)RtlAllocateHeap(g_vldHeap, 0x0, size + sizeof(vldblockheader_t));
    header = (vldblockheader_t*)g_POW2BucketCacheAllocator.alloc(size + sizeof(vldblockheader_t));

    if (header == NULL) {
        // Out of memory.
        return NULL;
    }

    // Fill in the block's header information.
    header->file         = file;
    header->line         = line;
    header->serialNumber = serialnumber++;
    header->size         = size;

    // Link the block into the block list.
    CriticalSectionLocker<> cs(g_vldHeapLock);
    header->next         = g_vldBlockList;
    if (header->next != NULL) {
        header->next->prev = header;
    }
    header->prev         = NULL;
    g_vldBlockList       = header;

    // Return a pointer to the beginning of the data section of the block.
    return (void*)VLDBLOCKDATA(header);
}

// vlddelete - Local helper function that actually frees memory back to VLD's
//   private heap.
//
//  - block (IN): Pointer to a memory block being freed.
//
//  Return Value:
//
//    None.
//
void vlddelete (void *block)
{
    if (block == NULL)
        return;

    BOOL              freed;
    vldblockheader_t *header = VLDBLOCKHEADER((LPVOID)block);
    // Unlink the block from the block list.
    CriticalSectionLocker<> cs(g_vldHeapLock);
    //'active' list is not circular...
    if (header->prev) {
        header->prev->next = header->next;
    }
    else {
        g_vldBlockList = header->next;
    }

    if (header->next) {
        header->next->prev = header->prev;
    }

#if 0
    //'delayedfree' list will be circular
    //uint32_t          g_vldDelayedFreeCount = 0;
    uint32_t const maxdelayed = 12000;
    const char fillfreebyte = 0xfb;
    if (g_vldDelayedFreeCount < maxdelayed)
    {
        ++g_vldDelayedFreeCount;
        if (!g_vldBlockListDelayedFree)
        {
            g_vldBlockListDelayedFree = header;
            header->next = header->prev = header;
        }
        else
        {
            header->next = g_vldBlockListDelayedFree;
            header->next->prev = header;
            g_vldBlockListDelayedFree = header;
        }
        memset(block, fillfreebyte, header->size);
        return;
    }
    else
    {
        //fill most recent block to be delay freed...
        memset(block, fillfreebyte, header->size);

        //Adding to 'head' of list, removing from 'tail' of list to free...

        header->next = g_vldBlockListDelayedFree;
        header->prev = g_vldBlockListDelayedFree->prev->prev;
        header->next->prev = header;
        g_vldBlockListDelayedFree = header;
        std::swap(header->prev->next, header);
        block = VLDBLOCKDATA(header);
        for (auto i = 0; i < header->size; ++i)
        {
            if (((char*)block)[i] != fillfreebyte)
                __debugbreak();
        }
    }
#endif

    if (1)
    {
        //header->next = vldbhcache;
        //vldbhcache = header;
        g_POW2BucketCacheAllocator.dealloc(header);
    }
    else
        // Free the block.
    {
        freed = RtlFreeHeap(g_vldHeap, 0x0, header);
        //g_POW2BucketCacheAllocator.dealloc(header);

        assert(freed);
    }
}

#if 0
//cpp allocator_traits style interface, doesn't want to compile with vs version used in vld build ATM...
#if 0
template <class T>
struct vld_custom_allocator {
    using value_type = T;
    vld_custom_allocator() noexcept;
    template <class U> vld_custom_allocator(const custom_allocator<U>&) noexcept;
    T* allocate(std::size_t n);
    void deallocate(T* p, std::size_t n);
};

template <class T, class U>
constexpr bool operator== (const vld_custom_allocator<T>&, const vld_custom_allocator<U>&) noexcept;

template <class T, class U>
constexpr bool operator!= (const vld_custom_allocator<T>&, const vld_custom_allocator<U>&) noexcept;
#endif

template<class T>
vld_custom_allocator::vld_custom_allocator()
{

}

template<class T>
vld_custom_allocator::vld_custom_allocator(const custom_allocator<U>& that)
{
    *this = that;
}

template <class T>
vld_custom_allocator::allocate(std::size_t n)
{
    return vldnew(n, __FILE__, __LINE__);
}
template <class T>
vld_custom_allocator::deallocate(T* p, std::size_t n)
{
    vlddelete(p);
}

template <class T, class U>
constexpr bool operator== (const vld_custom_allocator<T>& a, const vld_custom_allocator<U>& b) noexcept
{
    return &a == &b;
}

template <class T, class U>
constexpr bool operator!= (const vld_custom_allocator<T>& a, const vld_custom_allocator<U>&b) noexcept
{
    return &a != &b;
}
#endif

