////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - Internal C++ Heap Management Definitions
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

#include <windows.h>

#include <new> //for custom allocator placement new ref's
#include <unordered_map>

#define GAPSIZE 4

// Memory block header structure used internally by the debug CRT. All blocks
// allocated by the CRT are allocated from the CRT heap and, in debug mode, they
// have this header pretended to them (there's also a trailer appended at the
// end, but we're not interested in that).
struct crtdbgblockheader_t
{
    struct crtdbgblockheader_t *next;       // Pointer to the next block in the list of blocks allocated from the CRT heap.
    struct crtdbgblockheader_t *prev;       // Pointer to the previous block in the list of blocks allocated from the CRT heap.
    char const                 *file;          // Source file where this block was allocated.
    int                      line;          // Line of code, within the above file, where this block was allocated.
#ifdef _WIN64
    int                      use;           // This block's "use type": see below.
    size_t                   size;          // Size of the data portion of the block.
#else
    size_t                   size;          // Size of the data portion of the block.
    int                      use;           // This block's "use type":
#endif // _WIN64
#define CRT_USE_FREE     0                  //   This block has been freed.
#define CRT_USE_NORMAL   1                  //   This is a normal (user) block.
#define CRT_USE_INTERNAL 2                  //   This block is used internally by the CRT.
#define CRT_USE_IGNORE   3                  //   This block is a specially tagged block that is ignored during some debug error checking.
#define CRT_USE_CLIENT   4                  //   This block is a specially tagged block with special use defined by the user application.
    long                     request;       // This block's "request" number. Basically a serial number.
    unsigned char            gap [GAPSIZE]; // No-man's land buffer zone, for buffer overrun/underrun checking.
};

typedef char checkDebugHeapBlockAlignment[
	(sizeof(crtdbgblockheader_t) % MEMORY_ALLOCATION_ALIGNMENT == 0) ? 1 : -1];

// Same for UCRT.
struct crtdbgblockheaderucrt_t
{
    struct crtdbgblockheaderucrt_t *next;       // Pointer to the next block in the list of blocks allocated from the CRT heap.
    struct crtdbgblockheaderucrt_t *prev;       // Pointer to the previous block in the list of blocks allocated from the CRT heap.
    char const              *file;          // Source file where this block was allocated.
    int                      line;          // Line of code, within the above file, where this block was allocated.
    int                      use;           // This block's "use type": see below.
    size_t                   size;          // Size of the data portion of the block.
    long                     request;       // This block's "request" number. Basically a serial number.
    unsigned char            gap[GAPSIZE]; // No-man's land buffer zone, for buffer overrun/underrun checking.
};

typedef char checkDebugUcrtHeapBlockAlignment[
    (sizeof(crtdbgblockheaderucrt_t) % MEMORY_ALLOCATION_ALIGNMENT == 0) ? 1 : -1];

typedef char checkDebugHeapBlockSize[
    (sizeof(crtdbgblockheader_t) == sizeof(crtdbgblockheaderucrt_t)) ? 1 : -1];

// Macro to strip off any sub-type information stored in a block's "use type".
#define CRT_USE_TYPE(use) (use & 0xFFFF)
#define _BLOCK_TYPE_IS_VALID(use) (_BLOCK_TYPE(use) == _CLIENT_BLOCK || (use) == _NORMAL_BLOCK || _BLOCK_TYPE(use) == _CRT_BLOCK || (use) == _IGNORE_BLOCK)

// Memory block header structure used internally by VLD. All internally
// allocated blocks are allocated from VLD's private heap and have this header
// pretended to them.
struct vldblockheader_t
{
    struct vldblockheader_t *next;          // Pointer to the next block in the list of internally allocated blocks.
    struct vldblockheader_t *prev;          // Pointer to the preceding block in the list of internally allocated blocks.
    const char              *file;          // Name of the file where this block was allocated.
    int                      line;          // Line number within the above file where this block was allocated.
    size_t                   size;          // The size of this memory block, not including this header.
    size_t                   serialNumber;  // Each block is assigned a unique serial number, starting from zero.
};

// Data-to-Header and Header-to-Data conversion
#define VLDBLOCKHEADER(d) (vldblockheader_t*)(((PBYTE)d) - sizeof(vldblockheader_t))
#define VLDBLOCKDATA(h) (LPVOID)(((PBYTE)h) + sizeof(vldblockheader_t))
#define CRTDBGBLOCKHEADER(d) (crtdbgblockheader_t*)(((PBYTE)d) - sizeof(crtdbgblockheader_t))
#define CRTDBGBLOCKDATA(h) (LPVOID)(((PBYTE)h) + sizeof(crtdbgblockheader_t))

// new and delete operators for allocating from VLD's private heap.
void operator delete (void *block);
void operator delete [] (void *block);
void operator delete (void *block, const char *file, int line);
void operator delete [] (void *block, const char *file, int line);
void* operator new (size_t size, const char *file, int line);
void* operator new [] (size_t size, const char *file, int line);

//void* operator new (size_t size, void *where);

// All calls to the new operator from within VLD are mapped to the version of
// new that allocates from VLD's private heap.
#define new new(__FILE__, __LINE__)

#pragma push_macro("new")
#undef new

#if 0
//from https ://github.com/ros2/ros2/wiki/Allocator-Template-Tutorial
template <class T>
struct vld_custom_allocator {
    using value_type = T;
    vld_custom_allocator() noexcept;
    //hmm, think I'm compiling with vs2013 or so, that's prob. why it doesn't like this...
    template <class U> 
    vld_custom_allocator(const custom_allocator<U>&) noexcept;
    T* allocate(std::size_t n);
    void deallocate(T* p, std::size_t n);
};

template <class T, class U>
constexpr bool operator== (const vld_custom_allocator<T>&, const vld_custom_allocator<U>&) noexcept;

template <class T, class U>
constexpr bool operator!= (const vld_custom_allocator<T>&, const vld_custom_allocator<U>&) noexcept;
#endif

#if 01
//older cpp-11 style allocator interface
//from https ://www.codeproject.com/articles/1089905/a-custom-stl-std-allocator-replacement-improves-pe
extern void* vldnew(size_t size, const char *file, int line);
extern void vlddelete(void *block);
template <typename T>
class vld_stl_allocator
{
public:
    typedef size_t size_type;
    typedef ptrdiff_t difference_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef T value_type;

    vld_stl_allocator() {}
    ~vld_stl_allocator() {}

    template <class U> struct rebind { typedef vld_stl_allocator<U> other; };
    template <class U> vld_stl_allocator(const vld_stl_allocator<U>&) {}

    pointer address(reference x) const { return &x; }
    const_pointer address(const_reference x) const { return &x; }
    size_type max_size() const throw() { return size_t(-1) / sizeof(value_type); }

    //pointer allocate(size_type n, vld_stl_allocator<void>::const_pointer hint = 0)
    //pointer allocate(size_type n, vld_stl_allocator<T>::const_pointer hint = 0)
    pointer allocate(size_type n, const_pointer hint = 0)
    {
        //return static_cast<pointer>(xmalloc(n * sizeof(T)));
        return static_cast<pointer>(vldnew(n * sizeof(T), __FILE__, __LINE__));
    }

    void deallocate(pointer p, size_type n)
    {
        //xfree(p);
        vlddelete(p);
    }

    void construct(pointer p, const T& val)
    {
        new(static_cast<void*>(p)) T(val);
    }

    void construct(pointer p)
    {
        new(static_cast<void*>(p)) T();
    }

    void destroy(pointer p)
    {
        p->~T();
    }
};
#endif

#if 01
//from https://blogs.msdn.microsoft.com/calvin_hsia/2010/03/16/use-a-custom-allocator-for-your-stl-container/ circa posted 2010

template <class T>

class VLDCustomAlloc
    /*
    A custom allocator: given a pool of memory to start, just dole out consecutive memory blocks.
    this could be faster than a general purpose allocator.
    E.G. it could take advantage of constant sized requests (as in a RedBlack tree)
    */
{

public:
    typedef T          value_type;
    typedef size_t     size_type;
    typedef ptrdiff_t  difference_type;

    typedef T*         pointer;
    typedef const T*   const_pointer;

    typedef T&         reference;
    typedef const T&   const_reference;

#if 0
    VLDCustomAlloc(byte *pool, int nPoolSize)
    {
        Init();
        m_pool = pool;
        m_nPoolSize = nPoolSize;
    }

    VLDCustomAlloc(int n)
    {
        Init();
    }

#endif

    VLDCustomAlloc()

    {
        Init();
    }

    void Init()
    {
        m_pool = 0;
        m_nPoolSize = 0;
//        g_nCnt = 0;
//        g_nTot = 0;
    }

    VLDCustomAlloc(const VLDCustomAlloc &obj) // copy constructor
    {
        Init();
        m_pool = obj.m_pool;
        m_nPoolSize = obj.m_nPoolSize;
    }

private:
    void operator =(const VLDCustomAlloc &);

public:

    byte * m_pool;
    unsigned  m_nPoolSize;

    template <class _Other>
    VLDCustomAlloc(const VLDCustomAlloc<_Other> &other)
    {
        Init();
        m_pool = other.m_pool;
        m_nPoolSize = other.m_nPoolSize;
    }

    ~VLDCustomAlloc()
    {
    }

    template <class U>
    struct rebind
    {
        typedef VLDCustomAlloc<U> other;
    };

    pointer
        address(reference r) const
    {
        return &r;
    }

    const_pointer
        address(const_reference r) const
    {
        return &r;
    }

    pointer
        allocate(size_type n, const void* /*hint*/ = 0)
    {
        pointer p;
#if 1
        //p = vldnew(n, __FILE__, __LINE__);
        //p = new  T;
        p = new (__FILE__, __LINE__) T [n];
#else
        unsigned nSize = n * sizeof(T);
        if (m_pool) // if we have a mem pool from which to allocated
        {
            p = (pointer)m_pool;// just return the next available mem in the pool

            if (g_nTot + nSize > m_nPoolSize)
            {
                _ASSERT(0);//,"out of mem pool");
                return 0;
            }
            m_pool += nSize;  // and bump the pointer
        }
        else
        {
            p = (pointer)malloc(nSize);// no pool: just use malloc
        }
        g_nCnt += 1;
        g_nTot += nSize;
        _ASSERTE(p);
#endif
        return p;
    }

    void
        deallocate(pointer p, size_type /*n*/)
    {
#if 1
        //vlddelete(p);
        //delete p;
        delete [] p;
        //delete(p, __FILE__, __LINE__); //hopefully gets vld's internal 'delete'
        //delete (__FILE__, __LINE__) p;
        //delete p ( __FILE__, __LINE__); //hopefully gets vld's internal 'delete'
#else
        if (!m_pool)// if there's a pool, nothing to do
        {
            free(p);
        }
#endif
    }

    void
        //construct(pointer p, const T& val)
        construct(void *p, const T& val)
    {
        //aha! - The macro 'new()' must be screwing up these references...
        //::new (p) T(val);
        //::new ((void*)p) T(val);
        //new(static_cast<void*>(p)) T(val);
        //::new (&*p) T; // (val);
        //new (static_cast<void*>(p)) T;
        //::new (p) T();
        ::new (p) T(val);
    }

    void
        destroy(pointer p)
    {
        p->~T();
    }

    size_type
        max_size() const
    {
        return ULONG_MAX / sizeof(T);
    }

};

template <class T>
bool
operator==(const VLDCustomAlloc<T>& left, const VLDCustomAlloc<T>& right)
{
    if (left.m_pool == right.m_pool)
    {
        return true;
    }
    return false;
}

template <class T>
bool
operator!=(const VLDCustomAlloc<T>& left, const VLDCustomAlloc<T>& right)
{
    if (left.m_pool != right.m_pool)
    {
        return true;
    }

    return false;
}

// </VLDCustomAlloc>
#if 0
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

#pragma pop_macro("new")

#endif
