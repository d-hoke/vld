////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - VisualLeakDetector Class Implementation
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

#pragma comment(lib, "dbghelp.lib")

#include <sys/stat.h>

#include <vector>
#include <algorithm>

#define VLDBUILD         // Declares that we are building Visual Leak Detector.
#include "callstack.h"   // Provides a class for handling call stacks.
#include "crtmfcpatch.h" // Provides CRT and MFC patch functions.
#include "map.h"         // Provides a lightweight STL-like map template.
#include "ntapi.h"       // Provides access to NT APIs.
#include "set.h"         // Provides a lightweight STL-like set template.
#include "utility.h"     // Provides various utility functions.
#include "vldheap.h"     // Provides internal new and delete operators.
#include "vldint.h"      // Provides access to the Visual Leak Detector internals.
#include "loaderlock.h"

extern HANDLE           g_currentProcess;
extern CriticalSection  g_heapMapLock;
extern DbgHelp g_DbgHelp;
extern HANDLE            g_vldHeap;

////////////////////////////////////////////////////////////////////////////////
//
// Debug CRT and MFC IAT Replacement Functions
//
// The addresses of these functions are not actually directly patched into the
// import address tables, but these functions do get indirectly called by the
// patch functions that are placed in the import address tables.
//
////////////////////////////////////////////////////////////////////////////////

// GetProcessHeap - Calls to GetProcessHeap are patched through to this function. This
//   function is just a wrapper around the real GetProcessHeap.
//
//  Return Value:
//
//    Returns the value returned by GetProcessHeap.
//
HANDLE VisualLeakDetector::_GetProcessHeap()
{
    PRINT_HOOKED_FUNCTION();
    // Get the process heap.
    HANDLE heap = m_GetProcessHeap();

    CriticalSectionLocker<> cs(g_heapMapLock);
    HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
    if (heapit == g_vld.m_heapMap->end())
    {
        g_vld.mapHeap(heap);
        heapit = g_vld.m_heapMap->find(heap);
    }

    return heap;
}

// _HeapCreate - Calls to HeapCreate are patched through to this function. This
//   function is just a wrapper around the real HeapCreate that calls VLD's heap
//   creation tracking function after the heap has been created.
//
//  - options (IN): Heap options.
//
//  - initsize (IN): Initial size of the heap.
//
//  - maxsize (IN): Maximum size of the heap.
//
//  Return Value:
//
//    Returns the value returned by HeapCreate.
//
static uint64_t cnt_HeapCreateCalls = 0;
HANDLE VisualLeakDetector::_HeapCreate (DWORD options, SIZE_T initsize, SIZE_T maxsize)
{
	++cnt_HeapCreateCalls;
    PRINT_HOOKED_FUNCTION();
    // Create the heap.
    HANDLE heap = m_HeapCreate(options, initsize, maxsize);

    CriticalSectionLocker<> cs(g_heapMapLock);

    // Map the created heap handle to a new block map.
    g_vld.mapHeap(heap);

    HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
    assert(heapit != g_vld.m_heapMap->end());

    return heap;
}

// _HeapDestroy - Calls to HeapDestroy are patched through to this function.
//   This function is just a wrapper around the real HeapDestroy that calls
//   VLD's heap destruction tracking function after the heap has been destroyed.
//
//  - heap (IN): Handle to the heap to be destroyed.
//
//  Return Value:
//
//    Returns the valued returned by HeapDestroy.
//
static uint64_t cnt_HeapDestroyCalls = 0;
BOOL VisualLeakDetector::_HeapDestroy (HANDLE heap)
{
	++cnt_HeapDestroyCalls;
    PRINT_HOOKED_FUNCTION();
    // After this heap is destroyed, the heap's address space will be unmapped
    // from the process's address space. So, we'd better generate a leak report
    // for this heap now, while we can still read from the memory blocks
    // allocated to it.
    if (!(g_vld.m_options & VLD_OPT_SKIP_HEAPFREE_LEAKS))
        g_vld.reportHeapLeaks(heap);

    g_vld.unmapHeap(heap);

    return HeapDestroy(heap);
}

// _RtlAllocateHeap - Calls to RtlAllocateHeap are patched through to this
//   function. This function invokes the real RtlAllocateHeap and then calls
//   VLD's allocation tracking function. Pretty much all memory allocations
//   will eventually result in a call to RtlAllocateHeap, so this is where we
//   finally map the allocated block.
//
//  - heap (IN): Handle to the heap from which to allocate memory.
//
//  - flags (IN): Heap allocation control flags.
//
//  - size (IN): Size, in bytes, of the block to allocate.
//
//  Return Value:
//
//    Returns the return value from RtlAllocateHeap.
//
static uint64_t cnt_RtlAllocateHeapCalls = 0;
static uint64_t cnt_RtlAllocateHeapSkippedLock = 0;
LPVOID VisualLeakDetector::_RtlAllocateHeap (HANDLE heap, DWORD flags, SIZE_T size)
{
	++cnt_RtlAllocateHeapCalls;
    PRINT_HOOKED_FUNCTION2();
    // Allocate the block.
//alternate path for CACHING 
#if 01
    LPVOID block = RtlAllocateHeap(heap, flags, size);
#elif 0
    HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
    //assert(heapit != ?);
    //SIZE_T paddedsz = heapit->second.cache.paddedsz(size);
    //LPVOID block = heapit->second.cache.obtain(paddedsz);
    MultsOfHeapBucketCacher::reqinfo ri;
    ri.reqsz = size;
    LPVOID block = (*heapit).second->cache.obtain(ri);
    if (!block)
    {
        //none cached, alloc another
        block = RtlAllocateHeap(heap, flags, ri.adjmultsz);
        //update bookkeeping
        (*heapit).second->cache.updateOverhead((MultsOfHeapBucketCacher::overhead *)block, ri);
        (*heapit).second->cache.incrAllocCount(ri);

        //(char *)block += paddedsz - size;
        block = (*heapit).second->cache.adj2userdata(block);
    }
#endif

    if ((g_vld.refOptions() & VLD_OPT_TRACKING_PAUSED))
        return block;
    if ((block == NULL) || !g_vld.enabled())
        return block;

	if (!g_DbgHelp.IsLockedByCurrentThread()) { // skip dbghelp.dll calls
		CAPTURE_CONTEXT();
		CaptureContext cc(RtlAllocateHeap, context_);
		cc.Set(heap, block, NULL, size);
	}
	else
		++cnt_RtlAllocateHeapSkippedLock;
    return block;
}

extern HeapMap::Iterator findOrMapBlock(HANDLE heap);
static uint64_t cnt_HeapAllocCalls = 0;
static uint64_t cnt_HeapAllocSkippedLock = 0;
// HeapAlloc (kernel32.dll) call RtlAllocateHeap (ntdll.dll)
LPVOID VisualLeakDetector::_HeapAlloc (HANDLE heap, DWORD flags, SIZE_T size)
{
	++cnt_HeapAllocCalls;
	//TBD: fragmentation exploration
	//SIZE_T minsize = 512;
	//if (size < minsize) size = minsize; //searching for possible fragmentation avoidance... (even against 'low-fragmentation' heap)
	PRINT_HOOKED_FUNCTION2();
    //alternate path for CACHING 
#if 01
    //original vld default path
    // Allocate the block.
    LPVOID block = HeapAlloc(heap, flags, size);
#elif 0
	SIZE_T multsz = 64;
	SIZE_T rem = size % multsz;
	SIZE_T allocmult = (size / multsz);
    if (rem) allocmult += 1;
	SIZE_T allocsz = allocmult * multsz;
	if (allocsz >= 0x12cc80 && allocsz <= 0x12fe00)
	{
		static int skipbreaks = 1;
		if(!skipbreaks)
		{
			__debugbreak();
		}
	}
	LPVOID block = HeapAlloc(heap, flags, allocsz);
#elif 0 //needs machine caching section in matching free routine
	HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
	//assert(heapit != ?);
	//SIZE_T paddedsz = heapit->second.cache.paddedsz(size);
	//LPVOID block = heapit->second.cache.obtain(paddedsz);
    MultsOfHeapBucketCacher::reqinfo ri;
    ri.reqsz = size;
    LPVOID block = (*heapit).second->cache.obtain(ri);
    if (!block)
	{
		//none cached, alloc another
        block = HeapAlloc(heap, flags, ri.adjmultsz);
        //update bookkeeping
        (*heapit).second->cache.updateOverhead((MultsOfHeapBucketCacher::overhead *)block, ri);
        (*heapit).second->cache.incrAllocCount(ri);

		//(char *)block += paddedsz - size;
        block = (*heapit).second->cache.adj2userdata(block);
	}
#endif

    if ((g_vld.refOptions() & VLD_OPT_TRACKING_PAUSED))
        return block;
    if ((block == NULL) || !g_vld.enabled())
        return block;

	if (!g_DbgHelp.IsLockedByCurrentThread()) { // skip dbghelp.dll calls
		CAPTURE_CONTEXT();
		CaptureContext cc(HeapAlloc, context_);
		cc.Set(heap, block, NULL, size);
	}
	else
		++cnt_HeapAllocSkippedLock;

    return block;
}

// _RtlFreeHeap - Calls to RtlFreeHeap are patched through to this function.
//   This function calls VLD's free tracking function and then invokes the real
//   RtlFreeHeap. Pretty much all memory frees will eventually result in a call
//   to RtlFreeHeap, so this is where we finally unmap the freed block.
//
//  - heap (IN): Handle to the heap to which the block being freed belongs.
//
//  - flags (IN): Heap control flags.
//
//  - mem (IN): Pointer to the memory block being freed.
//
//  Return Value:
//
//    Returns the value returned by RtlFreeHeap.
//
//dlh - seems can get to RtlFreeHeap from/via
// Deallocate() -> delete -> free -> imp_free
#if 01
template<class _Kty,
	class _Ty,
	//class _Pr = std::less<_Kty>,
	class Hash = std::hash<_Kty>,
	class KeyEqual = std::equal_to<_Kty>,
	//class _Alloc = vld_stl_allocator<std::pair<const _Kty, _Ty> > >
	class _Alloc = VLDCustomAlloc<std::pair<const _Kty, _Ty> > >
	class vldunordered_map
	//: public std::unordered_map<_Kty, _Ty, _Pr, _Alloc>
	: public std::unordered_map<_Kty, _Ty, Hash, KeyEqual, _Alloc>
{
};
#endif
struct DelayFreeItem_s
{
	//DelayFreeItem_s() {}
	HANDLE heap;
	DWORD flags;
	LPVOID mem;
	//TBD: capture the freeing callstack...
	CallStack* stack_at_free; //= CallStack::Create();
};
template <typename T>
class vldvector : public std::vector<T, VLDCustomAlloc<T> >
{
};
const size_t maxDelayFreeItems = 12000; // 500000; // 250000; // 12000;
//std::vector<DelayFreeItem_s> x(maxDelayFreeItems);
static vldvector < DelayFreeItem_s> delayedFrees; // (maxDelayFreeItems);
static int nextdelayfreeitem = 0;
vldunordered_map<LPVOID, unsigned, std::hash<LPVOID>> RtlFreeHeapItemsMap;
static uint64_t cnt_RtlFreeHeapCalls = 0;
static uint64_t cnt_RtlFreeHeapSkippedLock = 0;
BYTE VisualLeakDetector::_RtlFreeHeap (HANDLE heap, DWORD flags, LPVOID mem)
{
	++cnt_RtlFreeHeapCalls;
    PRINT_HOOKED_FUNCTION2();
    BYTE status;

    CriticalSectionLocker<> cs(g_heapMapLock);
#if 0
    static unsigned long entryCount = 0;
    InterlockedIncrement(&entryCount);

    static CRITICAL_SECTION critsect;
    static bool inited = false;
    if (!inited)
    {
        InitializeCriticalSection(&critsect);
        inited = true;
    }
    struct onExit_c {
        //onExit_c() {
        ~onExit_c() {
            InterlockedDecrement(&entryCount);
            LeaveCriticalSection(&critsect);
        }
    } onExit;
    EnterCriticalSection(&critsect); //TBD: don't remember, does this hang within on thread, or not? Either way, prob. still have problem...
    if (entryCount > 1)
    {
        //Could be we corrupting delayedFrees() underneath ourself? (so to speak...)
        //__debugbreak();
    }
#endif
#if 0 //maybe chicken-egg kind of problem init'ing...
	
	if(!RtlFreeHeapItemsMap.size()) //capacity())
		RtlFreeHeapItemsMap.reserve(maxDelayFreeItems);
	//TBD: thread protection needed?
	decltype(RtlFreeHeapItemsMap.find(mem)) itFreeItem = RtlFreeHeapItemsMap.end();// = RtlFreeHeapItemsMap.find(mem);
	if (RtlFreeHeapItemsMap.size())
		itFreeItem = RtlFreeHeapItemsMap.find(mem);

	if (itFreeItem != RtlFreeHeapItemsMap.end())
	{
		++itFreeItem->second;
		char buf[256];
		sprintf(buf, "multi-free heap %u, addr %p\n", heap, mem);
		OutputDebugStringA(buf);
		if (IsDebuggerPresent())
			__debugbreak();
	}
	else
		//RtlFreeHeapItemsMap[mem] = 1;
		RtlFreeHeapItemsMap.insert(std::pair<decltype(mem),unsigned>(mem, 1));
#endif
#if 0 //VLDDELAYEDFREES //delayed freeing or not...
	if (delayedFrees.size() < maxDelayFreeItems)
		delayedFrees.reserve(maxDelayFreeItems);
#if 01 //failures as result of multi-frees, (or is it callstack alloc's on the delay freed items?)
	if(mem)
	{
		decltype(delayedFrees.end()) itFound;
        auto wasEnd = delayedFrees.end();
		//if ((itFound = std::find_if(delayedFrees.begin(), delayedFrees.end(), [mem](const DelayFreeItem_s &v)->bool { return v.mem == mem; })) != delayedFrees.end())
        if ((itFound = std::find_if(delayedFrees.begin(), delayedFrees.end(), [mem](const DelayFreeItem_s &v)->bool { return v.mem == mem; })) != wasEnd)
        //if ((itFound = std::find(delayedFrees.begin(), delayedFrees.end(), [mem](const DelayFreeItem_s &v)->bool { return v.mem == mem; })) != delayedFrees.end())
		{
            auto foundatidx = itFound - delayedFrees.begin();
			//hmm, have seen *same* address assoc'd with *different* heaps, how so, since *we* didn't actually *free* it yet????
			Report(L"multi-free addr %p (heap %p), delayed free pending prev addr %p, heap %p, heaps diff %d, prev idx %llu...\n", mem, heap, itFound->mem, itFound->heap, itFound->heap != heap
				,itFound - delayedFrees.begin());
			Report(L"Orig Freeing Call stack:\n");
			itFound->stack_at_free->dump(FALSE);
			CallStack* stack_here = CallStack::Create();
			CAPTURE_CONTEXT();
			context_.func = NULL;
			stack_here->getStackTrace(g_vld.m_maxTraceFrames, context_);
			Report(L"Current Freeing Call stack:\n");
			stack_here->dump(FALSE);
			ReportFlush();
			delete stack_here;
			if (itFound->heap == heap)
			{
				char buf[256];
				//sprintf(buf, "multi-free addr %p (heap %p), delayed free pending prev addr %p, heap %p...\n", mem, heap, itFound->mem, itFound->heap);
                sprintf(buf, "multi-free addr %p (heap %p), delayed free pending prev addr %p, heap %p, heaps diff %d, prev idx %llu...\n", mem, heap, itFound->mem, itFound->heap, itFound->heap != heap
                    , itFound - delayedFrees.begin());
                OutputDebugStringA(buf);
				if (IsDebuggerPresent())
					__debugbreak();
			}

		}
	}
#endif
	if (mem)
	{
		if (delayedFrees.size() == maxDelayFreeItems)
		{
			//TBD: perform mem fill
			CriticalSectionLocker<> cs(g_heapMapLock);
			HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
			if (heapit == g_vld.m_heapMap->end()) {
				// We don't have a block map for this heap. We must not have monitored
				// this allocation (probably happened before VLD was initialized).
				//(May also be slight possibility that some one init'd free from one thread, and free'd heap from another
				//with the free and our unmapping of the heap occurring before reaching here - but assume lib's sync mech's
				//should prob. prevent that...  maybe thread swapping on exiting of both parts plus other thread swaps
				//could still have us in that situation - or not...
				//TBD: do we (optionally?) report this?
				//ok, at least on startup we get here... __debugbreak();
				//just count 'em...
				static uint64_t howmany = 0;
				++howmany;
				//return TRUE; //sorry, we just lose this one...
				//even tho' we don't recognize it, maybe environ will, continue on
			}
			else
			{
				// Find this block in the block map.
				BlockMap           *blockmap = &(*heapit).second->blockMap;
				//BlockMap::Iterator  blockit = blockmap->find(mem);
                BlockMap::iterator  blockit = blockmap->find(mem);
                const auto freeFillByteVal = '\xfb';
				if (blockit != blockmap->end())
				{
					//Found it, we can fill it...
					blockinfo_t *info = (*blockit).second;
					if (++info->freecnt > 1)
						__debugbreak();
					memset(mem, freeFillByteVal, info->size);

#if 01
					CallStack* stack_here = CallStack::Create();
					CAPTURE_CONTEXT();
					context_.func = NULL;
					stack_here->getStackTrace(g_vld.m_maxTraceFrames, context_);
#endif
					std::swap(delayedFrees[nextdelayfreeitem].heap, heap);
					std::swap(delayedFrees[nextdelayfreeitem].flags, flags);
					std::swap(delayedFrees[nextdelayfreeitem].mem, mem);
#if 01
					std::swap(delayedFrees[nextdelayfreeitem].stack_at_free, stack_here);
					delete stack_here;
#endif
					nextdelayfreeitem = (nextdelayfreeitem + 1) % maxDelayFreeItems;
					//Check filled mem contents for writes
					/*HeapMap::Iterator*/ heapit = g_vld.m_heapMap->find(heap);
					if (heapit == g_vld.m_heapMap->end()) {
						// We don't have a block map for this heap. We must not have monitored
						// this allocation (probably happened before VLD was initialized).
						//TBD: do we (optionally?) report this?
						//is poss. that heap may have been freed
						//TBD: does lib prevent freeing of heap
						//if outstanding allocations?  If so, we could mess up legitimate programs, but don't
						//expect that to be common, we'll just potentially 'leak' this item for which we (now) have
						//no record of its heap...
						//return TRUE; //sorry, we just lose this one...
						//allow to fall thru, and, assuming it's valid block, be  free, even tho' we no (longer?) have record...
						//of course, if now really bogus, could choke the caller, so be it for now...
					}
					else
					{

						// Find this block in the block map.
						/*BlockMap           * */ blockmap = &(*heapit).second->blockMap;
						/*BlockMap::Iterator  */ blockit = blockmap->find(mem);
						if (blockit != blockmap->end())
						{
							//Found it, we can check it...
							blockinfo_t *info = (*blockit).second;
							//memset(mem, info->size, '\xfb');
							char *pbytes = static_cast<char *>(mem);
							for (auto i = 0; i < info->size; ++i)
								if (pbytes[i] != freeFillByteVal)
								{
									char buf[256];
									sprintf(buf, "i %d, pbytes[i] %x, mem %p, size %llu\n", i, pbytes[i], mem, info->size);
									OutputDebugStringA(buf);
									__debugbreak();
								}
						}
					}
					//nextdelayfreeitem = (nextdelayfreeitem + 1) % maxDelayFreeItems;
				}
			}
		}
		else
		{
			//TBD: perform mem fill
			HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
			if (heapit != g_vld.m_heapMap->end()) 
			{
				BlockMap           *blockmap = &(*heapit).second->blockMap;
				BlockMap::iterator  blockit = blockmap->find(mem);
				const auto freeFillByteVal = '\xfb';
				if (blockit != blockmap->end())
				{
					//Found it, we can fill it...
					blockinfo_t *info = (*blockit).second;
					if (++info->freecnt > 1)
						__debugbreak();
					memset(mem, freeFillByteVal, info->size);
				}
			}
			//accum 'til max reached, then other branch will be taken.
#if 0
			delayedFrees.emplace_back(DelayFreeItem_s{ heap, flags, mem, nullptr });
#else //#if 01
			CallStack* stack_here = CallStack::Create();
			CAPTURE_CONTEXT();
			//context_.func = reinterpret_cast<UINT_PTR>(VisualLeakDetector::mapBlock);
			//context_.func = (UINT_PTR)&VisualLeakDetector::mapBlock;
			//context_.func = reinterpret_cast<UINT_PTR>(reinterpret_cast<void*>(&VisualLeakDetector::mapBlock));
			//decltype(&VisualLeakDetector::mapBlock) methptr = &VisualLeakDetector::mapBlock;
			//void *vmethptr = (void *)methptr;
			//typedef decltype(VisualLeakDetector::mapBlock) vldmb_t; VisualLeakDetector::mapBlock;
			//vldmb_t mp = VisualLeakDetector::mapBlock;
			//context_.func = (void*)mp;
			context_.func = NULL;
			stack_here->getStackTrace(g_vld.m_maxTraceFrames, context_);
			//delayedFrees.back().stack_at_free = stack_here;
            delayedFrees.emplace_back(DelayFreeItem_s{ heap, flags, mem, stack_here });
#endif
			//Report(L"CURRENT Call stack.\n");
			//stack_here->dump(FALSE);
			// Now it should be safe to delete our temporary callstack
			//delete stack_here;
			//stack_here = NULL;
			//if (delayedFrees.size() == maxDelayFreeItems)
			//	__debugbreak();
			return TRUE;
		}
	}
#endif

    if(!(g_vld.refOptions() & VLD_OPT_TRACKING_PAUSED))
    {
	    if (!g_DbgHelp.IsLockedByCurrentThread()) // skip dbghelp.dll calls
	    {
		    // Record the current frame pointer.
		    CAPTURE_CONTEXT();
		    context_.func = reinterpret_cast<UINT_PTR>(RtlFreeHeap);

		    // Unmap the block from the specified heap.
		    g_vld.unmapBlock(heap, mem, context_);
	    }
	    else
	    {
		    ++cnt_RtlFreeHeapSkippedLock;

		    //try to unmap address anyway, see if this avoids 'new allocation at already allocated address' path...

		    // Record the current frame pointer.
		    CAPTURE_CONTEXT();
		    context_.func = reinterpret_cast<UINT_PTR>(RtlFreeHeap);

		    // Unmap the block from the specified heap.
		    g_vld.unmapBlock(heap, mem, context_, true);

	    }
    }

#if 0
	if (RtlFreeHeapItemsMap.size())
		itFreeItem = RtlFreeHeapItemsMap.find(mem);
	if (itFreeItem != RtlFreeHeapItemsMap.end())
		RtlFreeHeapItemsMap.erase(itFreeItem);
#endif

	static uint64_t HeapZeroCnt = 0, MemZeroCnt = 0;
	if (!heap) ++HeapZeroCnt;
	if (!mem) ++MemZeroCnt;
#if 0
	if (heap && mem && !HeapValidate(heap, 0, mem))
	{
		status = FALSE;
		__debugbreak();
	}
	else if (heap && mem && !HeapValidate(heap, 0, 0))
	{
		status = FALSE;
		__debugbreak();
	}
	else
#endif

//alternate path for CACHING 
#if 01
	status = RtlFreeHeap(heap, flags, mem);
#elif 0
    if (mem)
    {
    //needs matching section in _RtlHeapAlloc() or whatever it's called...
    HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
    //assert(heapit != ?);
    (*heapit).second->cache.release(mem);
    //HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
    //heapit->second.cache.release(mem);
    }
#endif

    return status;
}

// HeapFree (kernel32.dll) call RtlFreeHeap (ntdll.dll)
const size_t maxDelayFreeItems2 = 12000;
//std::vector<DelayFreeItem_s> x(maxDelayFreeItems);
static vldvector < DelayFreeItem_s> delayedFrees2; // (maxDelayFreeItems);
static int nextdelayfreeitem2 = 0;
vldunordered_map<LPVOID, unsigned, std::hash<LPVOID> > FreeHeapItemsMap;
static uint64_t cnt_HeapFreeCalls = 0;
static uint64_t cnt_HeapFreeSkippedLock = 0;
BOOL VisualLeakDetector::_HeapFree (HANDLE heap, DWORD flags, LPVOID mem)
{
	++cnt_HeapFreeCalls;
    PRINT_HOOKED_FUNCTION2();
    BOOL status;

	class delayedFrees {};
	class nextdelayfreeitem {};
	class maxDelayFreeItems {};
#if 0
	//TBD: thread protection needed?
	if (!FreeHeapItemsMap.size()) //capacity())
		FreeHeapItemsMap.reserve(maxDelayFreeItems2);
	//auto itFreeItem = FreeHeapItemsMap.find(mem);
	decltype(FreeHeapItemsMap.end()) itFreeItem = FreeHeapItemsMap.end();
	if(FreeHeapItemsMap.size())
		itFreeItem = FreeHeapItemsMap.find(mem);
	if (itFreeItem != FreeHeapItemsMap.end())
	{
		++itFreeItem->second;
		char buf[256];
		sprintf(buf, "multi-free heap %u, addr %p\n", heap, mem);
		OutputDebugStringA(buf);
		if (IsDebuggerPresent())
			__debugbreak();
	}
	else
		//FreeHeapItemsMap[mem] = 1;
		FreeHeapItemsMap.insert(std::pair<decltype(mem),unsigned>(mem, 1));
#endif

#if 0 //delayed freeing or not...
	if (delayedFrees2.size() < maxDelayFreeItems2)
		delayedFrees2.reserve(maxDelayFreeItems2);
#if 0 //seem to be failing as result of questionable multi-frees (same addr, diff. heaps), do we run if we avoid this?
	if(mem)
	{
		decltype(delayedFrees2.end()) itFound;
		//if ((itFound = std::find_if(delayedFrees2.begin(), delayedFrees2.end(), mem)) != delayedFrees2.end())
		if ((itFound = std::find_if(delayedFrees2.begin(), delayedFrees2.end(), [mem](const DelayFreeItem_s &v)->bool { return v.mem == mem; })) != delayedFrees2.end())
		{
			Report(L"multi-free addr %p (heap %p), delayed free pending prev addr %p, heap %p, heaps diff %d...\n", mem, heap, itFound->mem, itFound->heap, itFound->heap == heap);
			Report(L"Orig. Freeing Call stack:\n");
			itFound->stack_at_free->dump(FALSE);
			CallStack* stack_here = CallStack::Create();
			CAPTURE_CONTEXT();
			context_.func = NULL;
			stack_here->getStackTrace(g_vld.m_maxTraceFrames, context_);
			Report(L"Current Freeing Call stack:\n");
			stack_here->dump(FALSE);
			ReportFlush();
			if(itFound->heap == heap)
			{
				char buf[256];
				sprintf(buf, "multi-free addr %p (heap %p), delayed free pending...\n", mem, heap);
				OutputDebugStringA(buf);
				if (IsDebuggerPresent())
					__debugbreak();
			}

		}
	}
#endif
	if (mem)
	{
		if (delayedFrees2.size() == maxDelayFreeItems2)
		{
			//TBD: perform mem fill
			CriticalSectionLocker<> cs(g_heapMapLock);
			HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
			if (heapit == g_vld.m_heapMap->end()) {
				// We don't have a block map for this heap. We must not have monitored
				// this allocation (probably happened before VLD was initialized).
				//(May also be slight possibility that some one init'd free from one thread, and free'd heap from another
				//with the free and our unmapping of the heap occurring before reaching here - but assume lib's sync mech's
				//should prob. prevent that...  maybe thread swapping on exiting of both parts plus other thread swaps
				//could still have us in that situation - or not...
				//TBD: do we (optionally?) report this?
				//ok, at least on startup we get here... __debugbreak();
				//just count 'em...
				static uint64_t howmany = 0;
				++howmany;
				//return TRUE; //sorry, we just lose this one...
				//let it fall thru, we may not have it, but could be legit, return to environ if possible
			}
			else
			{
				// Find this block in the block map.
				BlockMap           *blockmap = &(*heapit).second->blockMap;
				BlockMap::iterator  blockit = blockmap->find(mem);
				const auto freeFillByteVal = '\xfb';
				if (blockit != blockmap->end())
				{
					//Found it, we can fill it...
					blockinfo_t *info = (*blockit).second;
					if (++info->freecnt > 1)
						__debugbreak();
					memset(mem, freeFillByteVal, info->size);

					CallStack* stack_here = CallStack::Create();
					CAPTURE_CONTEXT();
					context_.func = NULL;
					stack_here->getStackTrace(g_vld.m_maxTraceFrames, context_);

					std::swap(delayedFrees2[nextdelayfreeitem2].heap, heap);
					std::swap(delayedFrees2[nextdelayfreeitem2].flags, flags);
					std::swap(delayedFrees2[nextdelayfreeitem2].mem, mem);
					std::swap(delayedFrees2[nextdelayfreeitem2].stack_at_free, stack_here);
					delete stack_here;
					nextdelayfreeitem2 = ++nextdelayfreeitem2 % maxDelayFreeItems2;
					//Check filled mem contents for writes
					/*HeapMap::Iterator*/ heapit = g_vld.m_heapMap->find(heap);
					if (heapit == g_vld.m_heapMap->end()) {
						// We don't have a block map for this heap. We must not have monitored
						// this allocation (probably happened before VLD was initialized).
						//TBD: do we (optionally?) report this?
						//is poss. that heap may have been freed
						//TBD: does lib prevent freeing of heap
						//if outstanding allocations?  If so, we could mess up legitimate programs, but don't
						//expect that to be common, we'll just potentially 'leak' this item for which we (now) have
						//no record of its heap...
						//return TRUE; //sorry, we just lose this one...
						//allow to fall thru, and, assuming it's valid block, be  free, even tho' we no (longer?) have record...
						//of course, if now really bogus, could choke the caller, so be it for now...
					}
					else
					{

						// Find this block in the block map.
						/*BlockMap           * */ blockmap = &(*heapit).second->blockMap;
						/*BlockMap::Iterator  */ blockit = blockmap->find(mem);
						if (blockit != blockmap->end())
						{
							//Found it, we can check it...
							blockinfo_t *info = (*blockit).second;
							//memset(mem, info->size, '\xfb');
							char *pbytes = static_cast<char *>(mem);
							for (auto i = 0; i < info->size; ++i)
								if (pbytes[i] != freeFillByteVal)
								{
									char buf[256];
									sprintf(buf, "i %d, pbytes[i] %x, mem %p, size %llu\n", i, pbytes[i], mem, info->size);
									OutputDebugStringA(buf);
									__debugbreak();
								}
						}
					}
					//nextdelayfreeitem2 = ++nextdelayfreeitem2 % maxDelayFreeItems2;
				}

			}
		}
		else
		{
			//TBD: perform mem fill
			HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
			if (heapit != g_vld.m_heapMap->end())
			{
				BlockMap           *blockmap = &(*heapit).second->blockMap;
				BlockMap::iterator  blockit = blockmap->find(mem);
				const auto freeFillByteVal = '\xfb';
				if (blockit != blockmap->end())
				{
					//Found it, we can fill it...
					blockinfo_t *info = (*blockit).second;
					if (++info->freecnt > 1)
						__debugbreak();
					memset(mem, freeFillByteVal, info->size);
				}
			}
			//accum 'til max reached, then other branch will be taken.
			delayedFrees2.emplace_back(DelayFreeItem_s{ heap, flags, mem });
			CallStack* stack_here = CallStack::Create();
			CAPTURE_CONTEXT();
			//context_.func = reinterpret_cast<UINT_PTR>(VisualLeakDetector::mapBlock);
			//context_.func = (UINT_PTR)&VisualLeakDetector::mapBlock;
			//context_.func = reinterpret_cast<UINT_PTR>(reinterpret_cast<void*>(&VisualLeakDetector::mapBlock));
			//decltype(&VisualLeakDetector::mapBlock) methptr = &VisualLeakDetector::mapBlock;
			//void *vmethptr = (void *)methptr;
			//typedef decltype(VisualLeakDetector::mapBlock) vldmb_t; VisualLeakDetector::mapBlock;
			//vldmb_t mp = VisualLeakDetector::mapBlock;
			//context_.func = (void*)mp;
			context_.func = NULL;
			stack_here->getStackTrace(g_vld.m_maxTraceFrames, context_);
			delayedFrees2.back().stack_at_free = stack_here;
			//Report(L"CURRENT Call stack.\n");
			//stack_here->dump(FALSE);
			// Now it should be safe to delete our temporary callstack
			//delete stack_here;
			//stack_here = NULL;
			return TRUE;
		}
	}
#endif

    if (!(g_vld.refOptions() & VLD_OPT_TRACKING_PAUSED) )
    {
        if (!g_DbgHelp.IsLockedByCurrentThread()) // skip dbghelp.dll calls
	    {
		    // Record the current frame pointer.
		    CAPTURE_CONTEXT();
		    context_.func = reinterpret_cast<UINT_PTR>(m_HeapFree);

		    // Unmap the block from the specified heap.
		    g_vld.unmapBlock(heap, mem, context_);
	    }
	    else
	    {
		    ++cnt_HeapFreeSkippedLock;
		    CAPTURE_CONTEXT();
		    context_.func = reinterpret_cast<UINT_PTR>(m_HeapFree);

		    // Unmap the block from the specified heap.
		    g_vld.unmapBlock(heap, mem, context_, true);
	    }
    }

#if 0
	if (FreeHeapItemsMap.size())
		itFreeItem = FreeHeapItemsMap.find(mem);
	if (itFreeItem != FreeHeapItemsMap.end())
		FreeHeapItemsMap.erase(itFreeItem);
#endif

	static uint64_t HeapZeroCnt = 0, MemZeroCnt = 0;
	if (!heap) ++HeapZeroCnt;
	if (!mem) ++MemZeroCnt;
#if 0
	if (heap && mem && !HeapValidate(heap, 0, mem))
	{
		status = FALSE;
		__debugbreak();
	}
	else if (heap && mem && !HeapValidate(heap, 0, 0))
	{
		status = FALSE;
		__debugbreak();
	}
	else
#endif

//alternate path for CACHING 
#if 01
	status = m_HeapFree(heap, flags, mem);
#elif 0
    if(mem)
    {
    HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
    //assert(heapit != ?);
    (*heapit).second->cache.release(mem);
    //HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
	//heapit->second.cache.release(mem);
    }
#endif

    return status;
}//_HeapFree()

// _RtlReAllocateHeap - Calls to RtlReAllocateHeap are patched through to this
//   function. This function invokes the real RtlReAllocateHeap and then calls
//   VLD's reallocation tracking function. All arguments passed to this function
//   are passed on to the real RtlReAllocateHeap without modification. Pretty
//   much all memory re-allocations will eventually result in a call to
//   RtlReAllocateHeap, so this is where we finally remap the reallocated block.
//
//  - heap (IN): Handle to the heap to reallocate memory from.
//
//  - flags (IN): Heap control flags.
//
//  - mem (IN): Pointer to the currently allocated block which is to be
//      reallocated.
//
//  - size (IN): Size, in bytes, of the block to reallocate.
//
//  Return Value:
//
//    Returns the value returned by RtlReAllocateHeap.
//
static uint64_t cnt_RtlReAllocHeapCalls = 0;
static uint64_t cnt_RtlReAllocHeapSkippedLock = 0;
LPVOID VisualLeakDetector::_RtlReAllocateHeap (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size)
{
	++cnt_RtlReAllocHeapCalls;
    PRINT_HOOKED_FUNCTION();
//TBD: with caching need to identify if mem prev. allocd or new alloc (0), and adjust ptr accordingly, retaining
//overhead block to place in re-allocated block (if any), and new addr re-adjusted on way out...
    // Reallocate the block.
//alternate path for CACHING 
#if 01
    LPVOID newmem = RtlReAllocateHeap(heap, flags, mem, size);
#elif 0
    SIZE_T origblkreqsz;
    LPVOID newmem = nullptr;
    if (mem)
    {
        HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
        //assert(heapit != ?);
        //SIZE_T paddedsz = heapit->second.cache.paddedsz(size);
        //LPVOID block = heapit->second.cache.obtain(paddedsz);
        MultsOfHeapBucketCacher::overhead *povrh = (MultsOfHeapBucketCacher::overhead *)(*heapit).second->cache.adj2blkstart(mem);
        //well not really original, but padded sz we ultimately obtained!!!
        origblkreqsz = povrh->nmults*povrh->multofval - ((char*)mem - (char*)povrh);
        //delay until after we copy data!!!... (*heapit).second->cache.release(mem);
        MultsOfHeapBucketCacher::reqinfo ri;
        ri.reqsz = size; //the desired new size
        newmem = (*heapit).second->cache.obtain(ri);
        if (!newmem)
        {
            //TBD: Does HeapReAlloc() accept 0 to indicate a 'new' allocation???
            //Or do we need to call HeapAlloc() instead... ? 
            newmem = RtlReAllocateHeap(heap, flags, 0, size);
            if (newmem)
            {
                (*heapit).second->cache.updateOverhead((MultsOfHeapBucketCacher::overhead *)newmem, ri);
                (*heapit).second->cache.incrAllocCount(ri);
                memcpy((*heapit).second->cache.adj2userdata(newmem), mem, origblkreqsz);
            }
        }
        if (newmem)
        {
            (*heapit).second->cache.release(mem);
            newmem = (*heapit).second->cache.adj2userdata(newmem);
        }
        //else re-alloc failed, return null, orig. mem still there (TBD: Is that correct API behaviour?)
    }
#endif
if (g_vld.refOptions() & VLD_OPT_TRACKING_PAUSED) return newmem;
    if ((newmem == NULL) || !g_vld.enabled())
        return newmem;

	if (!g_DbgHelp.IsLockedByCurrentThread()) { // skip dbghelp.dll calls
		CAPTURE_CONTEXT();
		CaptureContext cc(RtlReAllocateHeap, context_);
		cc.Set(heap, mem, newmem, size);
	}
	else
		++cnt_RtlReAllocHeapSkippedLock;

    return newmem;
}

// for kernel32.dll
static uint64_t cnt_HeapReAllocCalls = 0;
static uint64_t cnt_HeapReAllocSkippedLock = 0;
LPVOID VisualLeakDetector::_HeapReAlloc (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size)
{
	++cnt_HeapReAllocCalls;
    PRINT_HOOKED_FUNCTION();
//alternate path for CACHING 
#if 01
    // Reallocate the block.
    LPVOID newmem = HeapReAlloc(heap, flags, mem, size);
#elif 01
    SIZE_T origblkreqsz;
    LPVOID newmem = nullptr;
    if (mem)
    {
        HeapMap::Iterator heapit = g_vld.findOrMapBlock(heap);
        //assert(heapit != ?);
        //SIZE_T paddedsz = heapit->second.cache.paddedsz(size);
        //LPVOID block = heapit->second.cache.obtain(paddedsz);
        MultsOfHeapBucketCacher::overhead *povrh = (MultsOfHeapBucketCacher::overhead *)(*heapit).second->cache.adj2blkstart(mem);
        //well not really original, but sz we padded to ask for!!!
        origblkreqsz = povrh->nmults*povrh->multofval - ((char*)mem - (char*)povrh);
        //delay until after we copy data!!!... (*heapit).second->cache.release(mem);
        MultsOfHeapBucketCacher::reqinfo ri;
        ri.reqsz = size; //the desired new size
        newmem = (*heapit).second->cache.obtain(ri);
        if (!newmem)
        {
            //TBD: Does HeapReAlloc() accept 0 to indicate a 'new' allocation???
            //Or do we need to call HeapAlloc() instead... ? 
            newmem = HeapReAlloc(heap, flags, 0, size);
            if (newmem)
            {
                (*heapit).second->cache.updateOverhead((MultsOfHeapBucketCacher::overhead *)newmem,ri);
                (*heapit).second->cache.incrAllocCount(ri);
                memcpy((*heapit).second->cache.adj2userdata(newmem), mem, origblkreqsz);
            }
        }
        if (newmem)
        {
            (*heapit).second->cache.release(mem);
            newmem = (*heapit).second->cache.adj2userdata(newmem);
        }
        //else re-alloc failed, return null, orig. mem still there (TBD: Is that correct API behaviour?)
    }
#endif

    if (g_vld.refOptions() & VLD_OPT_TRACKING_PAUSED) return newmem;
    if ((newmem == NULL) || !g_vld.enabled())
        return newmem;

	if (!g_DbgHelp.IsLockedByCurrentThread()) { // skip dbghelp.dll calls
		CAPTURE_CONTEXT();
		CaptureContext cc(HeapReAlloc, context_);
		cc.Set(heap, mem, newmem, size);
	}
	else
		++cnt_HeapReAllocSkippedLock;

    return newmem;
}

////////////////////////////////////////////////////////////////////////////////
//
// COM IAT Replacement Functions
//
////////////////////////////////////////////////////////////////////////////////

// _CoGetMalloc - Calls to CoGetMalloc are patched through to this function.
//   This function returns a pointer to Visual Leak Detector's implementation
//   of the IMalloc interface, instead of returning a pointer to the system
//   implementation. This allows VLD's implementation of the IMalloc interface
//   (which is basically a thin wrapper around the system implementation) to be
//   invoked in place of the system implementation.
//
//  - context (IN): Reserved; value must be 1.
//
//  - imalloc (IN): Address of a pointer to receive the address of VLD's
//      implementation of the IMalloc interface.
//
//  Return Value:
//
//    Always returns S_OK.
//
static uint64_t cnt_CoGetMallocCalls = 0;
HRESULT VisualLeakDetector::_CoGetMalloc (DWORD context, LPMALLOC *imalloc)
{
	++cnt_CoGetMallocCalls;
    PRINT_HOOKED_FUNCTION();
    static CoGetMalloc_t pCoGetMalloc = NULL;

    HRESULT hr = S_OK;

    HMODULE ole32;

    *imalloc = (LPMALLOC)&g_vld;

    if (pCoGetMalloc == NULL) {
        // This is the first call to this function. Link to the real
        // CoGetMalloc and get a pointer to the system implementation of the
        // IMalloc interface.
        ole32 = GetModuleHandleW(L"ole32.dll");
        pCoGetMalloc = (CoGetMalloc_t)g_vld._RGetProcAddress(ole32, "CoGetMalloc");
        hr = pCoGetMalloc(context, &g_vld.m_iMalloc);

        // Increment the library reference count to defer unloading the library,
        // since a call to CoGetMalloc returns the global pointer to the VisualLeakDetector object.
        HMODULE module = NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)g_vld.m_vldBase, &module);
    }
    else
    {
        // wait for different thread initialization
        int c = 0;
        while(g_vld.m_iMalloc == NULL && c < 10)
        {
            Sleep(1);
            c++;
        }
        if (g_vld.m_iMalloc == NULL)
            hr = E_INVALIDARG;
    }

    if (SUCCEEDED(hr)) {
        g_vld.AddRef();
    }
    return hr;
}

// _CoTaskMemAlloc - Calls to CoTaskMemAlloc are patched through to this
//   function. This function is just a wrapper around the real CoTaskMemAlloc
//   that sets appropriate flags to be consulted when the memory is actually
//   allocated by RtlAllocateHeap.
//
//  - size (IN): Size of the memory block to allocate.
//
//  Return Value:
//
//    Returns the value returned from CoTaskMemAlloc.
//
static uint64_t cnt_CoTaskMemAllocCalls = 0;
LPVOID VisualLeakDetector::_CoTaskMemAlloc (SIZE_T size)
{
	++cnt_CoTaskMemAllocCalls;
    PRINT_HOOKED_FUNCTION();
    static CoTaskMemAlloc_t pCoTaskMemAlloc = NULL;

    if (pCoTaskMemAlloc == NULL) {
        // This is the first call to this function. Link to the real
        // CoTaskMemAlloc.
        HMODULE ole32 = GetModuleHandleW(L"ole32.dll");
        pCoTaskMemAlloc = (CoTaskMemAlloc_t)g_vld._RGetProcAddress(ole32, "CoTaskMemAlloc");
    }

    CAPTURE_CONTEXT();
    CaptureContext cc((void*)pCoTaskMemAlloc, context_);

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    return pCoTaskMemAlloc(size);
}

// _CoTaskMemRealloc - Calls to CoTaskMemRealloc are patched through to this
//   function. This function is just a wrapper around the real CoTaskMemRealloc
//   that sets appropriate flags to be consulted when the memory is actually
//   allocated by RtlAllocateHeap.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size, in bytes, of the block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from CoTaskMemRealloc.
//
static uint64_t cnt_CoTaskMemReallocCalls = 0;
LPVOID VisualLeakDetector::_CoTaskMemRealloc (LPVOID mem, SIZE_T size)
{
	++cnt_CoTaskMemReallocCalls;
    PRINT_HOOKED_FUNCTION();
    static CoTaskMemRealloc_t pCoTaskMemRealloc = NULL;

    if (pCoTaskMemRealloc == NULL) {
        // This is the first call to this function. Link to the real
        // CoTaskMemRealloc.
        HMODULE ole32 = GetModuleHandleW(L"ole32.dll");
        pCoTaskMemRealloc = (CoTaskMemRealloc_t)g_vld._RGetProcAddress(ole32, "CoTaskMemRealloc");
    }

    CAPTURE_CONTEXT();
    CaptureContext cc((void*)pCoTaskMemRealloc, context_);

//TBD: with caching need to identify if mem prev. allocd or new alloc (0), and adjust ptr accordingly, retaining
//overhead block to place in re-allocated block (if any), and new addr re-adjusted on way out...

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    return pCoTaskMemRealloc(mem, size);
}

////////////////////////////////////////////////////////////////////////////////
//
// Public COM IMalloc Implementation Functions
//
////////////////////////////////////////////////////////////////////////////////

// AddRef - Calls to IMalloc::AddRef end up here. This function is just a
//   wrapper around the real IMalloc::AddRef implementation.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::AddRef.
//
ULONG VisualLeakDetector::AddRef ()
{
    PRINT_HOOKED_FUNCTION();
    assert(m_iMalloc != NULL);
    if (m_iMalloc) {
        // Increment the library reference count to defer unloading the library,
        // since this function increments the reference count of the IMalloc interface.
        HMODULE module = NULL;
        GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)m_vldBase, &module);
        return m_iMalloc->AddRef();
    }
    return 0;
}

// Alloc - Calls to IMalloc::Alloc end up here. This function is just a wrapper
//   around the real IMalloc::Alloc implementation that sets appropriate flags
//   to be consulted when the memory is actually allocated by RtlAllocateHeap.
//
//  - size (IN): The size of the memory block to allocate.
//
//  Return Value:
//
//    Returns the value returned by the system's IMalloc::Alloc implementation.
//
LPVOID VisualLeakDetector::Alloc (_In_ SIZE_T size)
{
    PRINT_HOOKED_FUNCTION();
    UINT_PTR* cVtablePtr = (UINT_PTR*)((UINT_PTR*)m_iMalloc)[0];
    UINT_PTR iMallocAlloc = cVtablePtr[3];
    CAPTURE_CONTEXT();
    CaptureContext cc((void*)iMallocAlloc, context_);

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->Alloc(size) : NULL;
}

// DidAlloc - Calls to IMalloc::DidAlloc will end up here. This function is just
//   a wrapper around the system implementation of IMalloc::DidAlloc.
//
//  - mem (IN): Pointer to a memory block to inquire about.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::DidAlloc.
//
INT VisualLeakDetector::DidAlloc (_In_opt_ LPVOID mem)
{
    PRINT_HOOKED_FUNCTION();
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->DidAlloc(mem) : 0;
}

// Free - Calls to IMalloc::Free will end up here. This function is just a
//   wrapper around the real IMalloc::Free implementation.
//
//  - mem (IN): Pointer to the memory block to be freed.
//
//  Return Value:
//
//    None.
//
VOID VisualLeakDetector::Free (_In_opt_ LPVOID mem)
{
    PRINT_HOOKED_FUNCTION();
    assert(m_iMalloc != NULL);
    if (m_iMalloc) m_iMalloc->Free(mem);
}

// GetSize - Calls to IMalloc::GetSize will end up here. This function is just a
//   wrapper around the real IMalloc::GetSize implementation.
//
//  - mem (IN): Pointer to the memory block to inquire about.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::GetSize.
//
SIZE_T VisualLeakDetector::GetSize (_In_opt_ LPVOID mem)
{
    PRINT_HOOKED_FUNCTION();
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->GetSize(mem) : 0;
}

// HeapMinimize - Calls to IMalloc::HeapMinimize will end up here. This function
//   is just a wrapper around the real IMalloc::HeapMinimize implementation.
//
//  Return Value:
//
//    None.
//
VOID VisualLeakDetector::HeapMinimize ()
{
    PRINT_HOOKED_FUNCTION();
    assert(m_iMalloc != NULL);
    if (m_iMalloc) m_iMalloc->HeapMinimize();
}

// QueryInterface - Calls to IMalloc::QueryInterface will end up here. This
//   function is just a wrapper around the real IMalloc::QueryInterface
//   implementation.
//
//  - iid (IN): COM interface ID to query about.
//
//  - object (IN): Address of a pointer to receive the requested interface
//      pointer.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::QueryInterface.
//
HRESULT VisualLeakDetector::QueryInterface (REFIID iid, LPVOID *object)
{
    PRINT_HOOKED_FUNCTION();
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->QueryInterface(iid, object) : E_UNEXPECTED;
}

// Realloc - Calls to IMalloc::Realloc will end up here. This function is just a
//   wrapper around the real IMalloc::Realloc implementation that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size, in bytes, of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::Realloc.
//
LPVOID VisualLeakDetector::Realloc (_In_opt_ LPVOID mem, _In_ SIZE_T size)
{
    PRINT_HOOKED_FUNCTION();
    UINT_PTR* cVtablePtr = (UINT_PTR*)((UINT_PTR*)m_iMalloc)[0];
    UINT_PTR iMallocRealloc = cVtablePtr[4];
    CAPTURE_CONTEXT();
    CaptureContext cc((void*)iMallocRealloc, context_);

//TBD: with caching need to identify if mem prev. allocd or new alloc (0), and adjust ptr accordingly, retaining
//overhead block to place in re-allocated block (if any), and new addr re-adjusted on way out...

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->Realloc(mem, size) : NULL;
}

// Release - Calls to IMalloc::Release will end up here. This function is just
//   a wrapper around the real IMalloc::Release implementation.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::Release.
//
ULONG VisualLeakDetector::Release ()
{
    PRINT_HOOKED_FUNCTION();
    assert(m_iMalloc != NULL);
    ULONG nCount = 0;
    if (m_iMalloc) {
        nCount = m_iMalloc->Release();

        // Decrement the library reference count.
        FreeLibrary(m_vldBase);
    }
    return nCount;
}

void ReportHookCallCounts()
{
//static uint64_t cnt_HeapAllocCalls = 0;
//static uint64_t cnt_RtlFreeHeapCalls = 0;
//static uint64_t cnt_HeapFreeCalls = 0;
//static uint64_t cnt_RtlReAllocHeapCalls = 0;
//static uint64_t cnt_HeapReAllocCalls = 0;
//static uint64_t cnt_CoGetMallocCalls = 0;
//static uint64_t cnt_CoTaskMemAllocCalls = 0;
//static uint64_t cnt_CoTaskMemReallocCalls = 0;
	Report(L"Hook call (and other) counts:\n");
	Report(L"\t cnt_RtlAllocateCalls %llu, SkipLock %llu\n", cnt_RtlAllocateHeapCalls, cnt_RtlAllocateHeapSkippedLock);
	Report(L"\t cnt_HeapAllocCalls %llu, SkipLock %llu\n", cnt_HeapAllocCalls, cnt_HeapAllocSkippedLock);
	Report(L"\t cnt_RtlFreeHeapCalls %llu, SkipLock %llu\n", cnt_RtlFreeHeapCalls, cnt_RtlFreeHeapSkippedLock);
	Report(L"\t cnt_HeapFreeCalls %llu, SkipLock %llu\n", cnt_HeapFreeCalls, cnt_HeapFreeSkippedLock);
	Report(L"\t cnt_RtlReAllocHeapCalls %llu, SkipLock %llu\n", cnt_RtlReAllocHeapCalls, cnt_RtlReAllocHeapSkippedLock);
	Report(L"\t cnt_HeapReAllocCalls %llu, SkipLock %llu\n", cnt_HeapReAllocCalls, cnt_HeapReAllocSkippedLock);
	Report(L"\t cnt_HeapCreateCalls %llu\n", cnt_HeapCreateCalls);
	Report(L"\t cnt_HeapDestroyCalls %llu\n", cnt_HeapDestroyCalls);
	Report(L"\t cnt_CoGetMallocCalls %llu\n", cnt_CoGetMallocCalls);
	Report(L"\t cnt_CoTaskMemAllocCalls %llu\n", cnt_CoTaskMemAllocCalls);
	Report(L"\t cnt_CoTaskMemReallocCalls %llu\n", cnt_CoTaskMemReallocCalls);
    Report(L"vld internal Heap Handle %p (so can visually filter from windbg !heap -p -all or !heap 0 -a)\n",g_vldHeap);
	PrintFlush();
}