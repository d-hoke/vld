////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - VisualLeakDetector Class Definition
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

#pragma once

#ifndef VLDBUILD
#error \
    "This header should only be included by Visual Leak Detector when building it from source. \
    Applications should never include this header."
#endif

#include <cstdio>
#pragma push_macro("new")
#undef new
#include <string>
#include <memory>
#include "Allocator.h"
#pragma pop_macro("new")
#include <windows.h>
#include "vld_def.h"
#include "version.h"
#include "callstack.h"  // Provides a custom class for handling call stacks.
#include "map.h"        // Provides a custom STL-like map template.
#include "ntapi.h"      // Provides access to NT APIs.
#include "set.h"        // Provides a custom STL-like set template.
#include "utility.h"    // Provides miscellaneous utility functions.
#include "vldallocator.h"   // Provides internal allocator.
#include "btree_container.h"
#include "btree_map.h"
//didn't seem to help btree key_compare_checker issues... #include <functional>

#define MAXMODULELISTLENGTH 512     // Maximum module list length, in characters.
#define SELFTESTTEXTA       "Memory Leak Self-Test"
#define SELFTESTTEXTW       L"Memory Leak Self-Test"
#define VLDREGKEYPRODUCT    L"Software\\Visual Leak Detector"
#ifndef WIN64
#define VLDDLL				"vld_x86.dll"
#else
#define VLDDLL				"vld_x64.dll"
#endif

// The Visual Leak Detector APIs.
extern "C" __declspec(dllexport) void VLDReportStats();
extern "C" __declspec(dllexport) std::size_t VLDNextAllocSeqNum();
extern "C" __declspec(dllexport) void VLDDisable ();
extern "C" __declspec(dllexport) void VLDEnable ();
extern "C" __declspec(dllexport) void VLDRestore ();
extern "C" __declspec(dllexport) UINT VLDBumpCheckPoint();
extern "C" __declspec(dllexport) UINT VLDBumpReportCheckPoint(CONST WCHAR *blurb);
extern "C" __declspec(dllexport) UINT VLDBumpReportCheckPointA(CONST char *ablurb);
extern "C" __declspec(dllexport) void VLDPauseTracking();
extern "C" __declspec(dllexport) void VLDResumeTracking();

// Function pointer types for explicit dynamic linking with functions listed in
// the import patch table.
typedef HANDLE(__stdcall *GetProcessHeap_t) ();
typedef HANDLE(__stdcall *HeapCreate_t) (DWORD, SIZE_T, SIZE_T);
typedef BOOL(__stdcall *HeapFree_t) (HANDLE, DWORD, LPVOID);
typedef FARPROC(__stdcall *GetProcAddress_t) (HMODULE, LPCSTR);
typedef FARPROC(__stdcall *GetProcAddressForCaller_t) (HMODULE, LPCSTR, LPVOID);

typedef void* (__cdecl *_calloc_dbg_t) (size_t, size_t, int, const char*, int);
typedef void* (__cdecl *_malloc_dbg_t) (size_t, int, const char *, int);
typedef void* (__cdecl *_realloc_dbg_t) (void *, size_t, int, const char *, int);
typedef void* (__cdecl *_recalloc_dbg_t) (void *, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *calloc_t) (size_t, size_t);
typedef HRESULT (__stdcall *CoGetMalloc_t) (DWORD, LPMALLOC *);
typedef LPVOID (__stdcall *CoTaskMemAlloc_t) (SIZE_T);
typedef LPVOID (__stdcall *CoTaskMemRealloc_t) (LPVOID, SIZE_T);
typedef void* (__cdecl *malloc_t) (size_t);
typedef void* (__cdecl *new_t) (size_t);
typedef void* (__cdecl *new_dbg_crt_t) (size_t, int, const char *, int);
typedef void* (__cdecl *new_dbg_mfc_t) (size_t, const char *, int);
typedef void* (__cdecl *realloc_t) (void *, size_t);
typedef void* (__cdecl *_recalloc_t) (void *, size_t, size_t);
typedef char* (__cdecl *_strdup_t) (const char*);
typedef char* (__cdecl *_strdup_dbg_t) (const char*, int, const char* ,int);
typedef wchar_t* (__cdecl *_wcsdup_t) (const wchar_t*);
typedef wchar_t* (__cdecl *_wcsdup_dbg_t) (const wchar_t*, int, const char* ,int);
typedef void* (__cdecl *_aligned_malloc_t) (size_t, size_t);
typedef void* (__cdecl *_aligned_offset_malloc_t) (size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_realloc_t) (void *, size_t, size_t);
typedef void* (__cdecl *_aligned_offset_realloc_t) (void *, size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_recalloc_t) (void *, size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_offset_recalloc_t) (void *, size_t, size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_malloc_dbg_t) (size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_offset_malloc_dbg_t) (size_t, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_realloc_dbg_t) (void *, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_offset_realloc_dbg_t) (void *, size_t, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_recalloc_dbg_t) (void *, size_t, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_offset_recalloc_dbg_t) (void *, size_t, size_t, size_t, size_t, int, const char *, int);

// Data is collected for every block allocated from any heap in the process.
// The data is stored in this structure and these structures are stored in
// a BlockMap which maps each of these structures to its corresponding memory
// block.
//#pragma push_macro("new")
//#undef new
struct blockinfo_t {
    static Allocator blockinfopool;
    std::unique_ptr<CallStack> callStack;
    //std::unique_ptr<CallStack, void (*)(void *p)> callStack;
    DWORD      threadId;
    SIZE_T     serialNumber;
    SIZE_T     size;
    bool       reported;
    bool       debugCrtAlloc;
    bool       ucrt;
    LPCVOID    memaddr; //sanity check, looking for 'new allocation at already allocated address'
    UINT_PTR   funcaddr;
    int        freecnt;
    unsigned   checkpointval;
#if 0
    void * operator new(size_t size)
    {
        void * p = blockinfopool.Allocate(size);

        return p;
    }
    void operator delete(void * p)
    {
        blockinfopool.Deallocate(p);
    }
#endif
};
//#pragma pop_macro("new")

// BlockMaps map memory blocks (via their addresses) to blockinfo_t structures.
//typedef Map<LPCVOID, blockinfo_t*> BlockMap; //TBD: unordered_map any faster?  (ordered_)map necessary?
//typedef std::unordered_map<LPCVOID, blockinfo_t*> BlockMap; //TBD: unordered_map any faster?  (ordered_)map necessary?
//typedef btree::btree_map<LPCVOID, blockinfo_t *> BlockMap2;
#define ALTBLKMAP 1
//typedef btree::btree_map<LPCVOID, blockinfo_t *, std::less<LPCVOID> > BlockMap;
typedef btree::btree_map<LPCVOID, blockinfo_t *, std::less<LPCVOID>, vld_stl_allocator<char> > BlockMap;
//typedef btree::btree_map<INT64, blockinfo_t *> BlockMap2;
//typedef btree::btree_map<int, int> BlockMap2;
//typedef btree::btree_map<int32_t, int32_t, std::less<int32_t>> BlockMap2;
//using namespace btree;
//typedef btree_map<int, int> BlockMap2;



struct POW2HeapBucketCacher
{
	//instead of powersof2, consider steps, maybe powers of 2 (min being 32, 2**5) up to 512/1024,
	//or maybe just 32, 64, 128, 256 maybe to 1024
	//or maybe just multiples of 32 to 1024... (32 buckets)
	//then maybe
	//multiples of 1024 to say 32k, (32 buckets)
	//then multiples of 1024 to 64k, (32 buckets)
	//then multiples of 2048 to 128k, (32 buckets)
	//then multiples of 4096 to 256k (32 buckets)
	//then multiples of 8192 to 512k (32 buckets)
	//then multiples of 16384 to 1024k (1M) (32 buckets)
	//then multiples of 32768 to 2048k (32 buckets)
	//then multiples of 65536 to 4096k (32 buckets)
	//then multiples of 128k to 8192k (32 buckets)
	//then multiples of 256k to 16384k (32 buckets)
	//then multiples of 512k to 32768k (32 buckets)
	//multiples of 1024k for anything beyond?
	//then what?
	//std::mutex m_mtx;
	CriticalSection cs;
	static const size_t align = 32;
	struct overhead
	{
		HANDLE heap;
		size_t paddedsz;
		union {
			unsigned bucket;
			overhead *next;
		};
		char fill[8]; // 16]; //size this for padding to 32 byte boundary (on x64 windows)
	};
	static HANDLE heapFromPointer(void *p)
	{
		return ((overhead *)((char*)p - padton(sizeof(overhead),align)))->heap;
	}
	static unsigned padton(unsigned val, unsigned padtomultipleval)
	{
		//return padto - ((n + padto) % padto);
		return val + padtomultipleval - 1 - (val + padtomultipleval - 1) % padtomultipleval;
	}
	unsigned bucketfrompaddedn(size_t paddedn)
	{
		unsigned bucket = 0;
		while ((paddedn >>= 1) && paddedn)
		{
			//hibit <<= 1;
			++bucket;
		}
		return bucket;
	}
	POW2HeapBucketCacher()
	{
		//cs.Initialize();
		memset(CacheLists, 0, sizeof(CacheLists));
		memset(CacheListCounts, 0, sizeof(CacheListCounts));
	}
	size_t paddedsz(size_t n)
	{
		//const unsigned align = 32;
		size_t paddedn = n + padton(sizeof(overhead), align);
		return paddedn;
	}
	void *obtain(size_t paddedn)
#if 0
	;
#else
	{
		unsigned bucket = bucketfrompaddedn(paddedn);

		//FIXME: TBD: hmm, if bucket not right, then sz requested prob. isn't right...
		//(and we'll be putting undersized item in bucket that would indicate its larger)
		if (bucket < 5) //granularity on x64 windows
		{
			__debugbreak(); //TBD: See if this is reached...
			bucket = 5;
		}
		else if (bucket > 63) //we double, so 63 is max...
			__debugbreak();

		void *pitem = CacheLists[bucket];
		if (!pitem)
		{
			return nullptr ; //none currently cached
			//pitem = malloc(paddedn);
			//(*(overhead *)pitem).paddedsz = paddedn;
			//(*(overhead *)pitem).bucket = bucket;
		}
		else
		{
			CacheLists[bucket] = ((overhead*)CacheLists[bucket])->next;
			((overhead*)pitem)->bucket = bucket;
			CacheListCounts[bucket]--;
		}
		//hmm, prob. need to deal with alignment...
		//return (char*)pitem + padton(sizeof(overhead), 32);
		return (char*)pitem + padton(sizeof(overhead), align);
	}
#endif

	//void dealloc(void *p)
	void release(void *p)
#if 0
		;
#else
	{
		//overhead *itemtofree = (overhead*)((char*)p - padton(sizeof(overhead), 32));
		overhead *itemtofree = (overhead*)((char*)p - padton(sizeof(overhead), align));
		auto bucket = itemtofree->bucket;
		itemtofree->next = CacheLists[bucket];
		CacheLists[bucket] = itemtofree;
		CacheListCounts[bucket]++;
	}
#endif
	overhead *CacheLists[65];
	size_t CacheListCounts[65];
}; //POW2HeapBucketCacher

#pragma optimize("", off)
struct MultsOfHeapBucketCacher
{
    //instead of powersof2, consider steps, maybe powers of 2 (min being 32, 2**5) up to 512/1024,
    //or maybe just 32, 64, 128, 256 maybe to 1024
    //or maybe just multiples of 32 to 1024... (32 buckets)
    //then maybe
    //multiples of 1024 to say 32k, (32 buckets)
    //then multiples of 1024 to 64k, (32 buckets)
    //then multiples of 2048 to 128k, (32 buckets)
    //then multiples of 4096 to 256k (32 buckets)
    //then multiples of 8192 to 512k (32 buckets)
    //then multiples of 16384 to 1024k (1M) (32 buckets)
    //then multiples of 32768 to 2048k (32 buckets)
    //then multiples of 65536 to 4096k (32 buckets)
    //then multiples of 128k to 8192k (32 buckets)
    //then multiples of 256k to 16384k (32 buckets)
    //then multiples of 512k to 32768k (32 buckets)
    //multiples of 1024k for anything beyond?
    //then what?
    //std::mutex m_mtx;
    CriticalSection cs;
    static const size_t align = 32;
    struct overhead
    {
        HANDLE heap;
        //size_t multsz;
        uint32_t multofval;
        uint32_t nmults;
        union {
            unsigned bucket;
            overhead *next;
        };
        char fill[8]; // 16]; //size this for padding to 32 byte boundary (on x64 windows)
    };
    struct reqinfo
    {
        size_t reqsz; //user provided
        size_t adjreqsz; //sz of overhead added in
        size_t adjmultsz; //adjusted to some multiple of multofval, should == multofval * nmults
        size_t multofval;
        size_t nmults;
        size_t bkt;
    };
    static HANDLE heapFromPointer(void *p)
    {
        return ((overhead *)((char*)p - padton(sizeof(overhead), align)))->heap;
    }
    static unsigned padton(unsigned val, unsigned padtomultipleval)
    {
        //return padto - ((n + padto) % padto);
        return val + padtomultipleval - 1 - (val + padtomultipleval - 1) % padtomultipleval;
    }
#if 0
    unsigned bucketfrompaddedn(size_t paddedn)
    {
        unsigned bucket = 0;
        while ((paddedn >>= 1) && paddedn)
        {
            //hibit <<= 1;
            ++bucket;
        }
        return bucket;
    }
#endif
    MultsOfHeapBucketCacher()
    {
        //cs.Initialize();
        memset(CacheLists, 0, sizeof(CacheLists));
        memset(CacheListCounts, 0, sizeof(CacheListCounts));
    }
    size_t paddedsz(size_t n)
    {
        //const unsigned align = 32;
        size_t paddedn = n + padton(sizeof(overhead), align);
        return paddedn;
    }

    //void compvals(uint32_t &bkt, uint32_t &multof, uint32_t &nmult, size_t &size)
    void compvals(reqinfo &ri)
    {
        //std::remove_reference<decltype(size)>::type adjsize1 = paddedsz(ri.reqsz);
        ri.adjreqsz = paddedsz(ri.reqsz);
        //std::remove_reference<decltype(size)>::type adjmultsize;
        auto & adjsize1 = ri.adjreqsz;
        auto & adjmultsize = ri.adjmultsz;
        auto & bkt = ri.bkt;
        auto & multof = ri.multofval;
        auto & nmult = ri.nmults;
        if (adjsize1 <= 1024)
        {
            bkt = 0;
            multof = 32;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if(adjsize1 <= (1024 * 32)) //32k
        {
            bkt = 1;
            multof = 1024;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 64)) //64k
        {
            bkt = 2;
            multof = 1024; //yes, same as 32k
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 128))
        {
            bkt = 3;
            multof = 2048; 
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 256))
        {
            bkt = 4;
            multof = 4096;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 512))
        {
            bkt = 5;
            multof = 8192;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 1024))
        {
            bkt = 6;
            multof = 16384;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 2048))
        {
            bkt = 7;
            multof = 32768;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 4096))
        {
            bkt = 8;
            multof = 65536; //1024*64
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 8192))
        {
            bkt = 9;
            multof = 1024*128;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 16384))
        {
            bkt = 10;
            multof = 1024 * 256;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else if (adjsize1 <= (1024 * 32768))
        {
            bkt = 11;
            multof = 1024 * 512;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        else //if (adjsize1 <= (1024 * 32768))
        {
            bkt = 12;
            multof = 1024 * 1024;
            //adjmultsize = padton(32, align);
            adjmultsize = padton(adjsize1, multof);
            nmult = adjmultsize / multof;
        }
        if (nmult < 1 || (adjsize1 <= (1024 * 32768) && nmult > 32))
            __debugbreak(); //diagnostic
    }

    void updateOverhead(overhead *poh, reqinfo &ri)
    {
        ((overhead*)poh)->bucket = ri.bkt;
        ((overhead*)poh)->multofval = ri.multofval;
        ((overhead*)poh)->nmults = ri.nmults;
    }
    //void *obtain(size_t &reqsz, overhead *&povrh)
    void *obtain(reqinfo &ri)
#if 0
        ;
#else
    {
        //unsigned bucket = bucketfrompaddedn(paddedn);
        //unsigned bkt, multof, nmult;
        //compvals(bkt, multof, nmult, reqsz);
        compvals(ri);
        auto &bkt = ri.bkt;
        auto &nmult = ri.nmults;
        auto &multof = ri.multofval;

        void *pitem = CacheLists[bkt][nmult];
        if (!pitem)
        {
            return nullptr; //none currently cached
                            //pitem = malloc(paddedn);
                            //(*(overhead *)pitem).paddedsz = paddedn;
                            //(*(overhead *)pitem).bucket = bucket;
        }
        else
        {
            auto slot = nmult;
            if (multof >= 1024 * 1024)
                slot = 0;
            CacheLists[bkt][slot] = ((overhead*)CacheLists[bkt][slot])->next;
            //These actually ought to already be set!!! (tho' client has to do it, or req it be done!!!)
            //maybe assert/warn if they are different? well, bkt needs to be set, others should be same...
            //((overhead*)pitem)->bucket = bkt;
            //((overhead*)pitem)->multofval = multof;
            //((overhead*)pitem)->nmults = nmult;
            updateOverhead((overhead *)pitem, ri);
            CacheListCounts[bkt][slot]--;
            CacheAllocCounts[bkt][slot]++;
        }
        //hmm, prob. need to deal with alignment...
        //return (char*)pitem + padton(sizeof(overhead), 32);
        return (char*)pitem + padton(sizeof(overhead), align);
    }
    void *adj2userdata(void *pblk)
    {
        //user writeable area
        return (char*)pblk + padton(sizeof(overhead), align);
    }
    void *adj2blkstart(void *pblk)
    {
        //addr of prefix overhead
        return (char*)pblk - padton(sizeof(overhead), align);
    }

    void incrAllocCount(reqinfo &ri)
    {
        auto slot = ri.nmults;
        if (ri.multofval >= 1024 * 1024)
            slot = 0;
        auto &bkt = ri.bkt;
        CacheAllocCounts[bkt][slot]++;
    }
#endif
    void setovrh(void *p, overhead *povrhsrc)
    {
        overhead *povrh2set = (overhead*)((char*)p - padton(sizeof(overhead), align));
        povrh2set->bucket    = povrhsrc->bucket;
        povrh2set->multofval = povrhsrc->multofval;
        povrh2set->nmults    = povrhsrc->nmults;
    }
    //void dealloc(void *p)
    void release(void *p)
#if 0
        ;
#else
    {
        //overhead *itemtofree = (overhead*)((char*)p - padton(sizeof(overhead), 32));
        overhead *itemtofree = (overhead*)((char*)p - padton(sizeof(overhead), align));
        auto bucket = itemtofree->bucket;
        auto slot = itemtofree->nmults;
        if (slot >= 1024 * 1024)
            slot = 0;
        itemtofree->next = CacheLists[bucket][slot];
        CacheLists[bucket][slot] = itemtofree;
        CacheListCounts[bucket][slot]++;
        CacheAllocCounts[bucket][slot]--;
    }
#endif
    overhead *CacheLists[16][33]; //32+1 so don't have to zero-base nmult(s) value
    size_t CacheListCounts[16][33]; //same here
    size_t CacheAllocCounts[16][33];
}; //MultsOfHeapBucketCacher

// Information about each heap in the process is kept in this map. Primarily
// this is used for mapping heaps to all of the blocks allocated from those
// heaps.
struct heapinfo_t {
    BlockMap blockMap;   // Map of all blocks allocated from this heap.
    UINT32   flags;      // Heap status flags
	//POW2HeapBucketCacher cache;
    MultsOfHeapBucketCacher cache;
};

// HeapMaps map heaps (via their handles) to BlockMaps.
typedef Map<HANDLE, heapinfo_t*> HeapMap; //TBD: unordered_map any faster?  (ordered_)map necessary?
//typedef std::unordered_map<HANDLE, heapinfo_t*> HeapMap; //TBD: unordered_map any faster?  (ordered_)map necessary?
typedef std::basic_string<wchar_t, std::char_traits<wchar_t>, vldallocator<wchar_t> > vldstring;


// This structure stores information, primarily the virtual address range, about
// a given module and can be used with the Set template because it supports the
// '<' operator (sorts by virtual address range).
struct moduleinfo_t {
    BOOL operator < (const struct moduleinfo_t& other) const
    {
        if (addrHigh < other.addrLow) {
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    SIZE_T addrLow;                  // Lowest address within the module's virtual address space (i.e. base address).
    SIZE_T addrHigh;                 // Highest address within the module's virtual address space (i.e. base + size).
    UINT32 flags;                    // Module flags:
#define VLD_MODULE_EXCLUDED      0x1 //   If set, this module is excluded from leak detection.
#define VLD_MODULE_SYMBOLSLOADED 0x2 //   If set, this module's debug symbols have been loaded.
    vldstring name;                  // The module's name (e.g. "kernel32.dll").
    vldstring path;                  // The fully qualified path from where the module was loaded.
};

// ModuleSets store information about modules loaded in the process.
typedef Set<moduleinfo_t> ModuleSet;

typedef Set<VLD_REPORT_HOOK> ReportHookSet;

// Thread local storage structure. Every thread in the process gets its own copy
// of this structure. Thread specific information, such as the current leak
// detection status (enabled or disabled) and the address that initiated the
// current allocation is stored here.
struct tls_t {
    context_t	context;       	  // Address of return address at the first call that entered VLD's code for the current allocation.
    UINT32	    flags;            // Thread-local status flags:
#define VLD_TLS_DEBUGCRTALLOC 0x1 //   If set, the current allocation is a CRT allocation.
#define VLD_TLS_DISABLED 0x2 	  //   If set, memory leak detection is disabled for the current thread.
#define VLD_TLS_ENABLED  0x4 	  //   If set, memory leak detection is enabled for the current thread.
#define VLD_TLS_UCRT     0x8      //   If set, the current allocation is a UCRT allocation.
    UINT32	    oldFlags;         // Thread-local status old flags
    DWORD 	    threadId;         // Thread ID of the thread that owns this TLS structure.
    HANDLE      heap;
    LPVOID      blockWithoutGuard; // Store pointer to block.
    LPVOID      newBlockWithoutGuard;
    SIZE_T      size;
    SIZE_T      oldsize;
};

// Allocation state:
// 1. Allocation function set tls->context and tls->blockWithoutGuard = NULL
// 2. HeapAlloc set tls->heap, tls->blockWithoutGuard, tls->newBlockWithoutGuard and tls->size
// 3. Allocation function reset tls data, map block and capture callstack to tls->blockWithoutGuard

// The TlsSet allows VLD to keep track of all thread local storage structures
// allocated in the process.
typedef Map<DWORD,tls_t*> TlsMap;

class CaptureContext {
public:
    CaptureContext(void* func, context_t& context, BOOL debug = FALSE, BOOL ucrt = FALSE);
    ~CaptureContext();
    __forceinline void Set(HANDLE heap, LPVOID mem, LPVOID newmem, SIZE_T size);
private:
    // Disallow certain operations
    CaptureContext();
    CaptureContext(const CaptureContext&);
    CaptureContext& operator=(const CaptureContext&);
private:
    BOOL IsExcludedModule();
    void Reset();
private:
    tls_t *m_tls;
    BOOL m_bFirst;
    const context_t& m_context;
    DWORD m_ThreadId;
    HANDLE m_hThread;
};

class CallStack;

////////////////////////////////////////////////////////////////////////////////
//
// The VisualLeakDetector Class
//
//   One global instance of this class is instantiated. Upon construction it
//   patches the import address table (IAT) of every other module loaded in the
//   process (see the "patchimport" utility function) to allow key Windows heap
//   APIs to be patched through to, or redirected to, functions provided by VLD.
//   Patching the IATs in this manner allows VLD to be made aware of all
//   relevant heap activity, making it possible for VLD to detect and trace
//   memory leaks.
//
//   The one global instance of this class is constructed within the context of
//   the process' main thread during process initialization and is destroyed in
//   the same context during process termination.
//
//   When the VisualLeakDetector object is destroyed, it consults its internal
//   data structures, looking for any memory that has not been freed. A memory
//   leak report is then generated, indicating any memory leaks that may have
//   been identified.
//
//   This class is derived from IMalloc so that it can provide an implementation
//   of the IMalloc COM interface in order to support detection of COM-based
//   memory leaks. However, this implementation of IMalloc is actually just a
//   thin wrapper around the system's implementation of IMalloc.
//
class VisualLeakDetector : public IMalloc
{
    friend class CallStack;
    friend class CaptureContext;
public:
    VisualLeakDetector();
    ~VisualLeakDetector();

    ////////////////////////////////////////////////////////////////////////////////
    // Public IMalloc methods - for support of COM-based memory leak detection.
    ////////////////////////////////////////////////////////////////////////////////
    ULONG   __stdcall AddRef ();
    LPVOID  __stdcall Alloc (_In_ SIZE_T size);
    INT     __stdcall DidAlloc (_In_opt_ LPVOID mem);
    VOID    __stdcall Free (_In_opt_ LPVOID mem);
    SIZE_T  __stdcall GetSize (_In_opt_ LPVOID mem);
    VOID    __stdcall HeapMinimize ();
    HRESULT __stdcall QueryInterface (REFIID iid, LPVOID *object);
    LPVOID  __stdcall Realloc (_In_opt_ LPVOID mem, _In_ SIZE_T size);
    ULONG   __stdcall Release ();

    void DisableLeakDetection ();
    void EnableLeakDetection ();
    void RestoreLeakDetectionState ();
    void GlobalDisableLeakDetection ();
    void GlobalEnableLeakDetection ();

    VOID RefreshModules();
    SIZE_T GetLeaksCount();
    SIZE_T GetThreadLeaksCount(DWORD threadId);
    SIZE_T ReportLeaks();
    SIZE_T ReportThreadLeaks(DWORD threadId);
    VOID MarkAllLeaksAsReported();
    VOID MarkThreadLeaksAsReported(DWORD threadId);
    VOID EnableModule(HMODULE module);
    VOID DisableModule(HMODULE module);
    UINT32 GetOptions();
    const UINT32 &refOptions() const { return m_options; }
    VOID GetReportFilename(WCHAR *filename);
    VOID SetOption(UINT32 option);
    VOID ClearOption(UINT32 option);
    VOID SetOptions(UINT32 option_mask, SIZE_T maxDataDump, UINT32 maxTraceFrames);
    VOID SetReportOptions(UINT32 option_mask, CONST WCHAR *filename);
    int  SetReportHook(int mode, VLD_REPORT_HOOK pfnNewHook);
    VOID SetModulesList(CONST WCHAR *modules, BOOL includeModules);
    bool GetModulesList(WCHAR *modules, UINT size);
    int ResolveCallstacks();
    const wchar_t* GetAllocationResolveResults(void* alloc, BOOL showInternalFrames);

    static NTSTATUS __stdcall _LdrLoadDll (LPWSTR searchpath, PULONG flags, unicodestring_t *modulename,
        PHANDLE modulehandle);
    static NTSTATUS __stdcall _LdrLoadDllWin8 (DWORD_PTR reserved, PULONG flags, unicodestring_t *modulename,
        PHANDLE modulehandle);
    static FARPROC __stdcall _RGetProcAddress(HMODULE module, LPCSTR procname);
    static FARPROC __stdcall _RGetProcAddressForCaller(HMODULE module, LPCSTR procname, LPVOID caller);

    static NTSTATUS NTAPI _LdrGetDllHandle(IN PWSTR DllPath OPTIONAL, IN PULONG DllCharacteristics OPTIONAL, IN PUNICODE_STRING DllName, OUT PVOID *DllHandle OPTIONAL);
    static NTSTATUS NTAPI _LdrGetProcedureAddress(IN PVOID BaseAddress, IN PANSI_STRING Name, IN ULONG Ordinal, OUT PVOID * ProcedureAddress);
    static NTSTATUS NTAPI _LdrUnloadDll(IN PVOID BaseAddress);
    static NTSTATUS NTAPI _LdrLockLoaderLock(IN ULONG Flags, OUT PULONG Disposition OPTIONAL, OUT PULONG_PTR Cookie OPTIONAL);
    static NTSTATUS NTAPI _LdrUnlockLoaderLock(IN ULONG Flags, IN ULONG_PTR Cookie OPTIONAL);

    std::size_t nextAllocSeq() {
		return m_requestCurr;
	};

    void reportSomeStats();
    void reportHeapCacheStats(HANDLE heap);
    void reportCacheStats();

    bool m_avoidFills;
    uint32_t m_checkpointval;
    decltype(m_checkpointval) BumpCheckPoint() { return ++m_checkpointval; }

	HeapMap::Iterator findOrMapBlock(HANDLE heap);

private:
    ////////////////////////////////////////////////////////////////////////////////
    // Private leak detection functions - see each function definition for details.
    ////////////////////////////////////////////////////////////////////////////////
    VOID   attachToLoadedModules (ModuleSet *newmodules);
    UINT32 getModuleState(ModuleSet::Iterator& it, UINT32 &moduleFlags);
    LPWSTR buildSymbolSearchPath();
    BOOL GetIniFilePath(LPTSTR lpPath, SIZE_T cchPath);
    VOID   configure ();
    BOOL   enabled ();
    //SIZE_T eraseDuplicates (const BlockMap::Iterator &element, Set<blockinfo_t*> &aggregatedLeak);
    SIZE_T eraseDuplicates(const BlockMap::iterator &element, Set<blockinfo_t*> &aggregatedLeak);
    //SIZE_T eraseDuplicates(blockinfo_t *elementinfo, Set<blockinfo_t*> &aggregatedLeak);
    tls_t* getTls ();
	VOID   mapBlock (HANDLE heap, LPCVOID mem, SIZE_T size, bool crtalloc, bool ucrt, DWORD threadId, blockinfo_t* &pblockInfo, const context_t &context, unsigned flags=0);
    VOID   mapHeap (HANDLE heap);
    VOID   remapBlock (HANDLE heap, LPCVOID mem, LPCVOID newmem, SIZE_T size,
        bool crtalloc, bool ucrt, DWORD threadId, blockinfo_t* &pblockInfo, const context_t &context);
    VOID   reportConfig ();
    static bool   isDebugCrtAlloc(LPCVOID block, blockinfo_t* info);
    SIZE_T reportHeapLeaks (HANDLE heap);
    static int    getCrtBlockUse (LPCVOID block, bool ucrt);
    static size_t getCrtBlockSize(LPCVOID block, bool ucrt);
    SIZE_T getLeaksCount (heapinfo_t* heapinfo, DWORD threadId = (DWORD)-1);
    SIZE_T reportLeaks(heapinfo_t* heapinfo, bool &firstLeak, Set<blockinfo_t*> &aggregatedLeaks, DWORD threadId = (DWORD)-1, SIZE_T cntOfBlocks = 0);
    VOID   markAllLeaksAsReported (heapinfo_t* heapinfo, DWORD threadId = (DWORD)-1);
    VOID   unmapBlock (HANDLE heap, LPCVOID mem, const context_t &context, bool avoidContextUse=false);
    VOID   unmapHeap (HANDLE heap);
    int    resolveStacks(heapinfo_t* heapinfo);

    // Static functions (callbacks)
    static BOOL __stdcall addLoadedModule (PCWSTR modulepath, DWORD64 modulebase, ULONG modulesize, PVOID context);
    static BOOL __stdcall detachFromModule (PCWSTR modulepath, DWORD64 modulebase, ULONG modulesize, PVOID context);

    // Utils
    static bool isModuleExcluded (UINT_PTR returnaddress);
    blockinfo_t* findAllocedBlock(LPCVOID, __out HANDLE& heap);
    blockinfo_t* getAllocationBlockInfo(void* alloc);
    void setupReporting();
    void checkInternalMemoryLeaks();
    bool waitForAllVLDThreads();

    ////////////////////////////////////////////////////////////////////////////////
    // IAT replacement functions - see each function definition for details.
    //
    // Because there are so many virtually identical CRT and MFC replacement
    // functions, they are excluded from the class to reduce the amount of noise
    // within this class's code. See crtmfcpatch.cpp for those functions.
    ////////////////////////////////////////////////////////////////////////////////
    // Win32 IAT replacement functions
    static FARPROC  __stdcall _GetProcAddress(HMODULE module, LPCSTR procname);
    static FARPROC  __stdcall _GetProcAddressForCaller(HMODULE module, LPCSTR procname, LPVOID caller);

    static HANDLE   __stdcall _GetProcessHeap();

    static HANDLE   __stdcall _HeapCreate (DWORD options, SIZE_T initsize, SIZE_T maxsize);
    static BOOL     __stdcall _HeapDestroy (HANDLE heap);
    static LPVOID   __stdcall _HeapAlloc (HANDLE heap, DWORD flags, SIZE_T size);
    static BOOL     __stdcall _HeapFree (HANDLE heap, DWORD flags, LPVOID mem);
    static LPVOID   __stdcall _HeapReAlloc (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size);

    static LPVOID   __stdcall _RtlAllocateHeap (HANDLE heap, DWORD flags, SIZE_T size);
    static BYTE     __stdcall _RtlFreeHeap (HANDLE heap, DWORD flags, LPVOID mem);
    static LPVOID   __stdcall _RtlReAllocateHeap (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size);

    // COM IAT replacement functions
    static HRESULT __stdcall _CoGetMalloc (DWORD context, LPMALLOC *imalloc);
    static LPVOID  __stdcall _CoTaskMemAlloc (SIZE_T size);
    static LPVOID  __stdcall _CoTaskMemRealloc (LPVOID mem, SIZE_T size);

    ////////////////////////////////////////////////////////////////////////////////
    // Private data
    ////////////////////////////////////////////////////////////////////////////////
    WCHAR                m_forcedModuleList [MAXMODULELISTLENGTH]; // List of modules to be forcefully included in leak detection.
    HeapMap             *m_heapMap;           // Map of all active heaps in the process.
    IMalloc             *m_iMalloc;           // Pointer to the system implementation of IMalloc.

    SIZE_T               m_requestCurr;       // Current request number.
    SIZE_T               m_totalAlloc;        // Grand total - sum of all allocations.
    SIZE_T               m_curAlloc;          // Total amount currently allocated.
    SIZE_T               m_maxAlloc;          // Largest ever allocated at once.
    ModuleSet           *m_loadedModules;     // Contains information about all modules loaded in the process.
    SIZE_T               m_maxDataDump;       // Maximum number of user-data bytes to dump for each leaked block.
    UINT32               m_maxTraceFrames;    // Maximum number of frames per stack trace for each leaked block.
    CriticalSection      m_modulesLock;       // Protects accesses to the "loaded modules" ModuleSet.
    CriticalSection      m_optionsLock;       // Serializes access to the heap and block maps.
    UINT32               m_options;           // Configuration options.

    static patchentry_t  m_kernelbasePatch [];
    static patchentry_t  m_kernel32Patch [];
    static patchentry_t  m_ntdllPatch [];
    static patchentry_t  m_ole32Patch [];
    static moduleentry_t m_patchTable [58];   // Table of imports patched for attaching VLD to other modules.
    FILE                *m_reportFile;        // File where the memory leak report may be sent to.
    WCHAR                m_reportFilePath [MAX_PATH]; // Full path and name of file to send memory leak report to.
	WCHAR                m_reportFileOutputDirectory[MAX_PATH]; // Full path and name of file to send memory leak report to.
	const char          *m_selfTestFile;      // Filename where the memory leak self-test block is leaked.
    int                  m_selfTestLine;      // Line number where the memory leak self-test block is leaked.
    UINT32               m_status;            // Status flags:
#define VLD_STATUS_DBGHELPLINKED        0x1   //   If set, the explicit dynamic link to the Debug Help Library succeeded.
#define VLD_STATUS_INSTALLED            0x2   //   If set, VLD was successfully installed.
#define VLD_STATUS_NEVER_ENABLED        0x4   //   If set, VLD started disabled, and has not yet been manually enabled.
#define VLD_STATUS_FORCE_REPORT_TO_FILE 0x8   //   If set, the leak report is being forced to a file.
    DWORD                m_tlsIndex;          // Thread-local storage index.
    CriticalSection      m_tlsLock;           // Protects accesses to the Set of TLS structures.
    TlsMap              *m_tlsMap;            // Set of all thread-local storage structures for the process.
    HMODULE              m_vldBase;           // Visual Leak Detector's own module handle (base address).
    HMODULE              m_dbghlpBase;

    VOID __stdcall ChangeModuleState(HMODULE module, bool on);
    static GetProcAddress_t m_GetProcAddress;
    static GetProcAddressForCaller_t m_GetProcAddressForCaller;
    static GetProcessHeap_t m_GetProcessHeap;
    static HeapCreate_t m_HeapCreate;
    static HeapFree_t m_HeapFree;

};


// Configuration option default values
#define VLD_DEFAULT_MAX_DATA_DUMP    256
#define VLD_DEFAULT_MAX_TRACE_FRAMES 64
#define VLD_DEFAULT_REPORT_FILE_NAME L".\\memory_leak_report.txt"
