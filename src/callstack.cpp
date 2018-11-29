////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - CallStack Class Implementations
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

#include <unordered_map>
#include <stdint.h>
#include <malloc.h>

#include <new>

#define VLDBUILD
#include "callstack.h"  // This class' header.
#include "utility.h"    // Provides various utility functions.
#include "vldheap.h"    // Provides internal new and delete operators.
#include "vldint.h"     // Provides access to VLD internals.
#include "cppformat\format.h"

// Imported global variables.
extern HANDLE             g_currentProcess;
extern HANDLE             g_currentThread;
extern CriticalSection    g_heapMapLock;
extern VisualLeakDetector g_vld;
extern DbgHelp g_DbgHelp;

// Helper function to compare the begin of a string with a substring
//
template <size_t N>
bool beginWith(const LPCWSTR filename, size_t len, wchar_t const (&substr)[N])
{
    size_t count = N - 1;
    return ((len >= count) && wcsncmp(filename, substr, count) == 0);
}

// Helper function to compare the end of a string with a substring
//
template <size_t N>
bool endWith(const LPCWSTR filename, size_t len, wchar_t const (&substr)[N])
{
    size_t count = N - 1;
    return ((len >= count) && wcsncmp(filename + len - count, substr, count) == 0);
}

Allocator CallStack::chunk_t::chunk_tpool(sizeof(SafeCallStack), 0, NULL, "chunk_tpool");
CallStack::chunk_t *chunk_tCacheHead = nullptr;

void release_chunk_t_cache()
{
    decltype(chunk_tCacheHead) chunk;
    while (chunk = chunk_tCacheHead)
    {
        chunk_tCacheHead = chunk_tCacheHead->next;
        delete chunk;
    }
}
// Constructor - Initializes the CallStack with an initial size of zero and one
//   Chunk of capacity.
//
CallStack::CallStack ()
{
    m_capacity   = CALLSTACK_CHUNK_SIZE;
    m_size       = 0;
    m_status     = 0x0;
    m_store.next = NULL;
    m_topChunk   = &m_store;
    m_topIndex   = 0;
    m_resolved   = NULL;
    m_resolvedCapacity   = 0;
    m_resolvedLength = 0;
}
#if 0
CallStack::CallStack(void (*pdeleteme)(void*))
    : CallStack()
    
{
    deleteme = pdeleteme;
}
#endif

// Destructor - Frees all memory allocated to the CallStack.
//
CallStack::~CallStack ()
{
    CallStack::chunk_t *chunk = m_store.next;
    CallStack::chunk_t *temp;

	{
		CriticalSectionLocker<> cs(g_heapMapLock);
		while (chunk) {
			temp = chunk;
			chunk = temp->next;
#if 0
			delete temp;
#else
			temp->next = chunk_tCacheHead;
			chunk_tCacheHead = temp;
#endif
		}
	}

    if (m_resolved != reinterpret_cast<decltype(m_resolved)>(1))
        delete [] m_resolved;

    m_resolved = NULL;
    m_resolvedCapacity = 0;
    m_resolvedLength = 0;
}

Allocator SafeCallStack::safepool(sizeof(SafeCallStack), 0, NULL, "SafeCallStackPool");
Allocator FastCallStack::fastpool(sizeof(SafeCallStack), 0, NULL, "FastCallStackPool");

SafeCallStack *SafeCallStackCache = nullptr;
FastCallStack *FastCallStackCache = nullptr;
void release_safecallstack_cache()
{
    decltype(SafeCallStackCache) chunk;
    while (chunk = SafeCallStackCache)
    {
        //SafeCallStackCache = SafeCallStackCache->next;
        SafeCallStackCache = *(SafeCallStack**)SafeCallStackCache;
        delete chunk;
    }
}
void release_fastcallstack_cache()
{
    decltype(FastCallStackCache) chunk;
    while (chunk = FastCallStackCache)
    {
        FastCallStackCache = *(FastCallStack**)FastCallStackCache;
        delete chunk;
    }
}
//#pragma push_macro("new")
//#undef new
CallStack* CallStack::Create()
{
    //TBD: Is there ever more than one of these outstanding?  *YES*.
    //(so can't..) If not, dispense with dynamic allocation, just placement 'new' on top of local static and return...
    CallStack* result = NULL;
    if (g_vld.GetOptions() & VLD_OPT_SAFE_STACK_WALK) {
        __debugbreak(); //TBD: don't think this branch is being taken with (my) current settings...
        result = new SafeCallStack();
        //result = new SafeCallStack(SafeCallStack::operator delete );
    }
    else {
#if 0
        result = new FastCallStack();
        //result = new FastCallStack(FastCallStack::operator delete);
#else
        if (FastCallStackCache)
        {
            result = FastCallStackCache;
            FastCallStackCache = *(FastCallStack**)FastCallStackCache;
            #pragma push_macro("new")
            #undef new
            new (result) FastCallStack();
            #pragma pop_macro("new")
        }
        else
        {
            result = new FastCallStack();
        }
#endif
    }
    return result;
}
//#pragma pop_macro("new")

// operator == - Equality operator. Compares the CallStack to another CallStack
//   for equality. Two CallStacks are equal if they are the same size and if
//   every frame in each is identical to the corresponding frame in the other.
//
//  other (IN) - Reference to the CallStack to compare the current CallStack
//    against for equality.
//
//  Return Value:
//
//    Returns true if the two CallStacks are equal. Otherwise returns false.
//
BOOL CallStack::operator == (const CallStack &other) const
{
    if (m_size != other.m_size) {
        // They can't be equal if the sizes are different.
        return FALSE;
    }

    // Walk the chunk list and within each chunk walk the frames array until we
    // either find a mismatch, or until we reach the end of the call stacks.
    const CallStack::chunk_t *prevChunk = NULL;
    const CallStack::chunk_t *chunk = &m_store;
    const CallStack::chunk_t *otherChunk = &other.m_store;
    while (prevChunk != m_topChunk) {
        UINT32 size = (chunk == m_topChunk) ? m_topIndex : CALLSTACK_CHUNK_SIZE;
        for (UINT32 index = 0; index < size; index++) {
            if (chunk->frames[index] != otherChunk->frames[index]) {
                // Found a mismatch. They are not equal.
                return FALSE;
            }
        }
        prevChunk = chunk;
        chunk = chunk->next;
        otherChunk = otherChunk->next;
    }

    // Reached the end of the call stacks. They are equal.
    return TRUE;
}

// operator [] - Random access operator. Retrieves the frame at the specified
//   index.
//
//   Note: We give up a bit of efficiency here, in favor of efficiency of push
//     operations. This is because walking of a CallStack is done infrequently
//     (only if a leak is found), whereas pushing is done very frequently (for
//     each frame in the program's call stack when the program allocates some
//     memory).
//
//  - index (IN): Specifies the index of the frame to retrieve.
//
//  Return Value:
//
//    Returns the program counter for the frame at the specified index. If the
//    specified index is out of range for the CallStack, the return value is
//    undefined.
//
UINT_PTR CallStack::operator [] (UINT32 index) const
{
    UINT32                    chunknumber = index / CALLSTACK_CHUNK_SIZE;
    const CallStack::chunk_t *chunk = &m_store;

    for (UINT32 count = 0; count < chunknumber; count++) {
        chunk = chunk->next;
    }

    return chunk->frames[index % CALLSTACK_CHUNK_SIZE];
}

// clear - Resets the CallStack, returning it to a state where no frames have
//   been pushed onto it, readying it for reuse.
//
//   Note: Calling this function does not release any memory allocated to the
//     CallStack. We give up a bit of memory-usage efficiency here in favor of
//     performance of push operations.
//
//  Return Value:
//
//    None.
//
VOID CallStack::clear ()
{
    m_size     = 0;
    m_topChunk = &m_store;
    m_topIndex = 0;
    if (m_resolved)
    {
        if (m_resolved != reinterpret_cast<decltype(m_resolved)>(1))
            delete [] m_resolved;
        m_resolved = NULL;
    }
    m_resolvedCapacity = 0;
    m_resolvedLength = 0;
}

LPCWSTR CallStack::getFunctionName(SIZE_T programCounter, DWORD64& displacement64,
    SYMBOL_INFO* functionInfo, CriticalSectionLocker<DbgHelp>& locker) const
{
    // Initialize structures passed to the symbol handler.
    functionInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    functionInfo->MaxNameLen = MAX_SYMBOL_NAME_LENGTH;

    // Try to get the name of the function containing this program
    // counter address.
    displacement64 = 0;
    LPCWSTR functionName;
    DbgTrace(L"dbghelp32.dll %i: SymFromAddrW\n", GetCurrentThreadId());
    if (g_DbgHelp.SymFromAddrW(g_currentProcess, programCounter, &displacement64, functionInfo, locker)) {
        functionName = functionInfo->Name;
    }
    else {
        // GetFormattedMessage( GetLastError() );
        fmt::WArrayWriter wf(functionInfo->Name, MAX_SYMBOL_NAME_LENGTH);
        wf.write(L"" ADDRESSCPPFORMAT, programCounter);
        functionName = wf.c_str();
        displacement64 = 0;
    }
    return functionName;
}

DWORD CallStack::resolveFunction(SIZE_T programCounter, IMAGEHLP_LINEW64* sourceInfo, DWORD displacement,
    LPCWSTR functionName, LPWSTR stack_line, DWORD stackLineSize) const
{
    WCHAR callingModuleName[260];
    HMODULE hCallingModule = GetCallingModule(programCounter);
    LPWSTR moduleName = L"(Module name unavailable)";
    if (hCallingModule &&
        GetModuleFileName(hCallingModule, callingModuleName, _countof(callingModuleName)) > 0)
    {
        moduleName = wcsrchr(callingModuleName, L'\\');
        if (moduleName == NULL)
            moduleName = wcsrchr(callingModuleName, L'/');
        if (moduleName != NULL)
            moduleName++;
        else
            moduleName = callingModuleName;
    }

    fmt::WArrayWriter w(stack_line, stackLineSize);
    // Display the current stack frame's information.
    if (sourceInfo)
    {
        if (displacement == 0)
        {
            w.write(L"    {} ({}): {}!{}()\n",
                sourceInfo->FileName, sourceInfo->LineNumber, moduleName,
                functionName);
        }
        else
        {
            w.write(L"    {} ({}): {}!{}() + 0x{:X} bytes\n",
                sourceInfo->FileName, sourceInfo->LineNumber, moduleName,
                functionName, displacement);
        }
    }
    else
    {
        if (displacement == 0)
        {
            w.write(L"    {}!{}()\n",
                moduleName, functionName);
        }
        else
        {
            w.write(L"    {}!{}() + 0x{:X} bytes\n",
                moduleName, functionName, displacement);
        }
    }
    DWORD NumChars = (DWORD)w.size();
    stack_line[NumChars] = '\0';
    return NumChars;
}


// isCrtStartupAlloc - Determines whether the memory leak was generated from crt startup code.
// This is not an actual memory leaks as it is freed by crt after the VLD object has been destroyed.
//
//  Return Value:
//
//    true if isCrtStartupModule for any callstack frame returns true.
//
bool CallStack::isCrtStartupAlloc()
{
    if (m_status & CALLSTACK_STATUS_STARTUPCRT) {
        return true;
    } else if (m_status & CALLSTACK_STATUS_NOTSTARTUPCRT) {
        return false;
    }

    IMAGEHLP_LINE64  sourceInfo = { 0 };
    sourceInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    BYTE symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYMBOL_NAME_SIZE] = { 0 };
    CriticalSectionLocker<DbgHelp> locker(g_DbgHelp);

    // Iterate through each frame in the call stack.
    for (UINT32 frame = 0; frame < m_size; frame++) {
        // Try to get the source file and line number associated with
        // this program counter address.
        SIZE_T programCounter = (*this)[frame];
        DWORD64 displacement64;
        LPCWSTR functionName = getFunctionName(programCounter, displacement64, (SYMBOL_INFO*)&symbolBuffer, locker);

        m_status |= isCrtStartupFunction(functionName);
        if (m_status & CALLSTACK_STATUS_STARTUPCRT) {
            return true;
        } else if (m_status & CALLSTACK_STATUS_NOTSTARTUPCRT) {
            return false;
        }
    }

    m_status |= CALLSTACK_STATUS_NOTSTARTUPCRT;
    return false;
}


// dump - Dumps a nicely formatted rendition of the CallStack, including
//   symbolic information (function names and line numbers) if available.
//
//   Note: The symbol handler must be initialized prior to calling this
//     function.
//
//  - showinternalframes (IN): If true, then all frames in the CallStack will be
//      dumped. Otherwise, frames internal to the heap will not be dumped.
//
//  Return Value:
//
//    None.
//
void CallStack::dump(BOOL showInternalFrames)
{
    //if leak report requested > 1 time same execution context, seems you *will* encounter these __debugbreak()s!
	if (++m_dumpCount > 1)
		if (IsDebuggerPresent())
			__debugbreak();

    if (!m_resolved) {
        resolve(showInternalFrames);
    }

    // The stack was resolved already
    if (m_resolved) { //TBD: Can we free m_resolved after printing, but leave m_resolved non-zero... (to avoid huge memory allocations growing while we're leak reporting???)
		//presumably redundant, but we'll check anyway....
		if (++m_resolvedPrintCount > 1)
			if (IsDebuggerPresent())
				__debugbreak();
		//TBD: It *appears* that it may be possible to safely
		//{
		// auto retrn = Print(m_resolved);
		// delete [] m_resolved;
		// m_resolved = static_cast<decltype(m_resolved)>(1);
		// return retrn;
		//}
		//to avoid accum'ing all of the m_resolved items which can be *quite* *large* in total (as I type this I'm watching
		//a process that has so far added about 28Gb from ReportLeaks(), seemingly due to these allocations....  The application only
		//had 10-12Gb upon starting to ReportLeaks(), is now up to about 39Gb.
        //Such a change will require touching the various places that 'delete [] m_resolved' and make them subject to if(m_resolved != (whatevercast)1)!!!
        //return Print(m_resolved); //Wow! Never noticed that possibility before (return functionreturningvoid())
        if(m_resolved != reinterpret_cast<decltype(m_resolved)>(1))
        {
            auto nchars = wcslen(m_resolved);
            Print(m_resolved, nchars);
            delete [] m_resolved;
            m_resolved = reinterpret_cast<decltype(m_resolved)>(1);
        }
        return;
    }
}

// Resolve - Creates a nicely formatted rendition of the CallStack, including
//   symbolic information (function names and line numbers) if available. and
//   saves it for later retrieval.
//
//   Note: The symbol handler must be initialized prior to calling this
//     function.
//
//  - showInternalFrames (IN): If true, then all frames in the CallStack will be
//      dumped. Otherwise, frames internal to the heap will not be dumped.
//
//  Return Value:
//
//    None.
//
//std::unordered_map<DWORD, uint64_t> stdframesMapped;
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
//vldunordered_map<DWORD, unsigned long long> framesMapped;
//vld's heap not init'd before trying to init this in global space, so, delay into resolve() so
//it will only be constructed after vld's internal heap is available.
//vldunordered_map<unsigned, unsigned long long> framesMapped;

static uint64_t nextResolvedCount = 0;
int CallStack::resolve(BOOL showInternalFrames)
{
    static vldunordered_map<unsigned, unsigned long long> framesMapped;
    
    if (++m_resolvedCount > 1)
		if (IsDebuggerPresent())
			__debugbreak();

    if (m_resolved)
    {
        // already resolved, no need to do it again
        // resolving twice may report an incorrect module for the stack frames
        // if the memory was leaked in a dynamic library that was already unloaded.
        return 0;
    }

    if (m_status & CALLSTACK_STATUS_STARTUPCRT) {
        // there is no need to resolve a leak that will not be reported
        return 0;
    }

    if (m_status & CALLSTACK_STATUS_INCOMPLETE) {
        // This call stack appears to be incomplete. Using StackWalk64 may be
        // more reliable.
        Report(L"    HINT: The following call stack may be incomplete. Setting \"StackWalkMethod\"\n"
            L"      in the vld.ini file to \"safe\" instead of \"fast\" may result in a more\n"
            L"      complete stack trace.\n");
    }

    int unresolvedFunctionsCount = 0;
    IMAGEHLP_LINE64  sourceInfo = { 0 };
    sourceInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    bool skipStartupLeaks = !!(g_vld.GetOptions() & VLD_OPT_SKIP_CRTSTARTUP_LEAKS);

    // Use static here to increase performance, and avoid heap allocs.
    // It's thread safe because of g_heapMapLock lock.
    static WCHAR stack_line[MAXREPORTLENGTH + 1] = L"";
    bool isPrevFrameInternal = false;
    DWORD NumChars = 0;
    CriticalSectionLocker<DbgHelp> locker(g_DbgHelp);

    const size_t max_line_length = MAXREPORTLENGTH + 1;
    m_resolvedCapacity = m_size * max_line_length;
    const size_t allocedBytes = m_resolvedCapacity * sizeof(WCHAR);
    m_resolved = new WCHAR[m_resolvedCapacity];
    if (m_resolved) {
        ZeroMemory(m_resolved, allocedBytes);
#if 0 //starting to not trust this... are crc's close enough to be misleading???
        //A crude attempt to avoid re-resolving same stackframes repeatedly, as it seems pretty slow...
        //downside:  If crc's for two differing stack frames are same, we'll not correctly report.

        DWORD crc = 0;
        for (UINT32 frameidx = 0; frameidx < m_size; frameidx++)
        {
            SIZE_T programCounter = (*this)[frameidx];
            crc = CalculateCRC32(programCounter, crc);
        }
        //.find() blowing up when empty...
        //auto mappedFrame = framesMapped.find(crc);
        //See if can avoid the 'empty' .find failure...
        decltype(framesMapped.find(crc)) mappedFrameIt = framesMapped.end();
        if (framesMapped.size())
        {
            mappedFrameIt = framesMapped.find(crc);
        }
        if( mappedFrameIt != framesMapped.end() )
        {
            //We've mapped this frame before, just output reference to it and return
            swprintf(m_resolved, L"crc %u, prev stackframe resolution #%llu\n", crc, mappedFrameIt->second);
            return 0;
        }
        else
        {
            //not seem this crc, record it, assign and report frame number, and proceed to resolve
            framesMapped[crc] = ++nextResolvedCount;
            swprintf(m_resolved, L"crc %u, new stackframe resolution #%llu\n", crc, nextResolvedCount);
        }
#endif
    }

    // Iterate through each frame in the call stack.
    for (UINT32 frame = 0; frame < m_size; frame++)
    {
        // Try to get the source file and line number associated with
        // this program counter address.
        SIZE_T programCounter = (*this)[frame];
        if (GetCallingModule(programCounter) == g_vld.m_vldBase)
            continue;

        DWORD64 displacement64;
        BYTE symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYMBOL_NAME_SIZE];
        LPCWSTR functionName = getFunctionName(programCounter, displacement64, (SYMBOL_INFO*)&symbolBuffer, locker);

        if (skipStartupLeaks) {
            if (!(m_status & (CALLSTACK_STATUS_STARTUPCRT | CALLSTACK_STATUS_NOTSTARTUPCRT))) {
                m_status |= isCrtStartupFunction(functionName);
            }
            if (m_status & CALLSTACK_STATUS_STARTUPCRT) {
                if (m_resolved != reinterpret_cast<decltype(m_resolved)>(1))
                    delete[] m_resolved;
                m_resolved = NULL;
                m_resolvedCapacity = 0;
                m_resolvedLength = 0;
                return 0;
            }
        }

        // It turns out that calls to SymGetLineFromAddrW64 may free the very memory we are scrutinizing here
        // in this method. If this is the case, m_Resolved will be null after SymGetLineFromAddrW64 returns.
        // When that happens there is nothing we can do except crash.
        DWORD            displacement = 0;
        DbgTrace(L"dbghelp32.dll %i: SymGetLineFromAddrW64\n", GetCurrentThreadId());
        BOOL foundline = g_DbgHelp.SymGetLineFromAddrW64(g_currentProcess, programCounter, &displacement, &sourceInfo, locker);

        bool isFrameInternal = false;
        if (foundline && !showInternalFrames) {
            if (isInternalModule(sourceInfo.FileName)) {
                // Don't show frames in files internal to the heap.
                isFrameInternal = true;
            }
        }

        // show one allocation function for context
        if (NumChars > 0 && !isFrameInternal && isPrevFrameInternal) {
            m_resolvedLength += NumChars;
            if (m_resolved) {
                wcsncat_s(m_resolved, m_resolvedCapacity, stack_line, NumChars);
            }
        }
        isPrevFrameInternal = isFrameInternal;

        if (!foundline)
            displacement = (DWORD)displacement64;
        NumChars = resolveFunction( programCounter, foundline ? &sourceInfo : NULL,
            displacement, functionName, stack_line, _countof( stack_line ));

        if (NumChars > 0 && !isFrameInternal) {
            m_resolvedLength += NumChars;
            if (m_resolved) {
                wcsncat_s(m_resolved, m_resolvedCapacity, stack_line, NumChars);
            }
        }
    } // end for loop

    m_status |= CALLSTACK_STATUS_NOTSTARTUPCRT;
    return unresolvedFunctionsCount;
}

const WCHAR* CallStack::getResolvedCallstack( BOOL showinternalframes )
{
    resolve(showinternalframes);
    return m_resolved;
}

// push_back - Pushes a frame's program counter onto the CallStack. Pushes are
//   always appended to the back of the chunk list (aka the "top" chunk).
//
//   Note: This function will allocate additional memory as necessary to make
//     room for new program counter addresses.
//
//  - programcounter (IN): The program counter address of the frame to be pushed
//      onto the CallStack.
//
//  Return Value:
//
//    None.
//
//#pragma push_macro("new")
//#undef new
VOID CallStack::push_back (const UINT_PTR programcounter)
{
    if (m_size == m_capacity) {
        // At current capacity. Allocate additional storage.
#if 0
        CallStack::chunk_t *chunk = new CallStack::chunk_t;
#else
        CallStack::chunk_t *chunk;
		{
			CriticalSectionLocker<> cs(g_heapMapLock);
			if (chunk_tCacheHead)
			{
				chunk = chunk_tCacheHead;
				chunk_tCacheHead = chunk_tCacheHead->next;
			}
			else
			{
				chunk = new CallStack::chunk_t;
			}
		}
#endif
        chunk->next = NULL;
        m_topChunk->next = chunk;
        m_topChunk = chunk;
        m_topIndex = 0;
        m_capacity += CALLSTACK_CHUNK_SIZE;
    }
    else if (m_topIndex >= CALLSTACK_CHUNK_SIZE) {
        // There is more capacity, but not in this chunk. Go to the next chunk.
        // Note that this only happens if this CallStack has previously been
        // cleared (clearing resets the data, but doesn't give up any allocated
        // space).
        m_topChunk = m_topChunk->next;
        m_topIndex = 0;
    }

    m_topChunk->frames[m_topIndex++] = programcounter;
    m_size++;
}
//#pragma pop_macro("new")

UINT CallStack::isCrtStartupFunction( LPCWSTR functionName ) const
{
    size_t len = wcslen(functionName);

    if (beginWith(functionName, len, L"_malloc_crt")
        || beginWith(functionName, len, L"_calloc_crt")
        || endWith(functionName, len, L"CRT_INIT")
        || endWith(functionName, len, L"initterm_e")
        || beginWith(functionName, len, L"_cinit")
        || beginWith(functionName, len, L"std::`dynamic initializer for '")
        // VS2008 Release
        || (wcscmp(functionName, L"std::locale::facet::facet_Register") == 0)
        // VS2010 Release
        || (wcscmp(functionName, L"std::locale::facet::_Facet_Register") == 0)
        // VS2012 Release
        || beginWith(functionName, len, L"std::locale::_Init()")
        || beginWith(functionName, len, L"std::basic_streambuf<")
        // VS2015
        || beginWith(functionName, len, L"common_initialize_environment_nolock<")
        || beginWith(functionName, len, L"common_configure_argv<")
        || beginWith(functionName, len, L"__acrt_initialize")
        || beginWith(functionName, len, L"__acrt_allocate_buffer_for_argv")
        || beginWith(functionName, len, L"_register_onexit_function")
        // VS2015 Release
        || (wcscmp(functionName, L"setlocale") == 0)
        || (wcscmp(functionName, L"_wsetlocale") == 0)
        || (wcscmp(functionName, L"_Getctype") == 0)
        || (wcscmp(functionName, L"std::_Facet_Register") == 0)
        || endWith(functionName, len, L">::_Getcat")
        ) {
        return CALLSTACK_STATUS_STARTUPCRT;
    }

    if (endWith(functionName, len, L"DllMainCRTStartup")
        || endWith(functionName, len, L"mainCRTStartup")
        || beginWith(functionName, len, L"`dynamic initializer for '")) {
        // When we reach this point there is no reason going further down the stack
        return CALLSTACK_STATUS_NOTSTARTUPCRT;
    }

    return NULL;
}

bool CallStack::isInternalModule( const PWSTR filename ) const
{
    size_t len = wcslen(filename);
    return
        // VS2015
        endWith(filename, len, L"\\atlmfc\\include\\atlsimpstr.h") ||
        endWith(filename, len, L"\\atlmfc\\include\\cstringt.h") ||
        endWith(filename, len, L"\\atlmfc\\src\\mfc\\afxmem.cpp") ||
        endWith(filename, len, L"\\atlmfc\\src\\mfc\\strcore.cpp") ||
        endWith(filename, len, L"\\vcstartup\\src\\heap\\new_scalar.cpp") ||
        endWith(filename, len, L"\\vcstartup\\src\\heap\\new_array.cpp") ||
        endWith(filename, len, L"\\vcstartup\\src\\heap\\new_debug.cpp") ||
        endWith(filename, len, L"\\ucrt\\src\\appcrt\\heap\\align.cpp") ||
        endWith(filename, len, L"\\ucrt\\src\\appcrt\\heap\\malloc.cpp") ||
        endWith(filename, len, L"\\ucrt\\src\\appcrt\\heap\\debug_heap.cpp") ||
        // VS2013
        beginWith(filename, len, L"f:\\dd\\vctools\\crt\\crtw32\\") ||
        //endWith(filename, len, L"\\crt\\crtw32\\misc\\dbgheap.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\misc\\dbgnew.cpp") ||
        //endWith(filename, len, L"\\crt\\crtw32\\misc\\dbgmalloc.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\misc\\dbgrealloc.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\heap\\new.cpp") ||
        //endWith(filename, len, L"\\crt\\crtw32\\heap\\new2.cpp") ||
        //endWith(filename, len, L"\\crt\\crtw32\\heap\\malloc.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\heap\\realloc.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\heap\\calloc.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\heap\\calloc_impl.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\string\\strdup.c") ||
        //endWith(filename, len, L"\\crt\\crtw32\\string\\wcsdup.c") ||
        // VS2010
        endWith(filename, len, L"\\crt\\src\\afxmem.cpp") ||
        endWith(filename, len, L"\\crt\\src\\dbgheap.c") ||
        endWith(filename, len, L"\\crt\\src\\dbgnew.cpp") ||
        endWith(filename, len, L"\\crt\\src\\dbgmalloc.c") ||
        endWith(filename, len, L"\\crt\\src\\dbgcalloc.c") ||
        endWith(filename, len, L"\\crt\\src\\dbgrealloc.c") ||
        endWith(filename, len, L"\\crt\\src\\dbgdel.cp") ||
        endWith(filename, len, L"\\crt\\src\\new.cpp") ||
        endWith(filename, len, L"\\crt\\src\\newaop.cpp") ||
        endWith(filename, len, L"\\crt\\src\\malloc.c") ||
        endWith(filename, len, L"\\crt\\src\\realloc.c") ||
        endWith(filename, len, L"\\crt\\src\\free.c") ||
        endWith(filename, len, L"\\crt\\src\\strdup.c") ||
        endWith(filename, len, L"\\crt\\src\\wcsdup.c") ||
        endWith(filename, len, L"\\vc\\include\\xmemory0") ||
        // default
        (false);
}

// getStackTrace - Traces the stack as far back as possible, or until 'maxdepth'
//   frames have been traced. Populates the CallStack with one entry for each
//   stack frame traced.
//
//   Note: This function uses a very efficient method to walk the stack from
//     frame to frame, so it is quite fast. However, unconventional stack frames
//     (such as those created when frame pointer omission optimization is used)
//     will not be successfully walked by this function and will cause the
//     stack trace to terminate prematurely.
//
//  - maxdepth (IN): Maximum number of frames to trace back.
//
//  - framepointer (IN): Frame (base) pointer at which to begin the stack trace.
//      If NULL, then the stack trace will begin at this function.
//
//  Return Value:
//
//    None.
//
VOID FastCallStack::getStackTrace (UINT32 maxdepth, const context_t& context)
{
    UINT32  count = 0;
    UINT_PTR function = context.func;
    if (function != NULL)
    {
        count++;
        push_back(function);
    }

/*#if defined(_M_IX86)
    UINT_PTR* framePointer = (UINT_PTR*)context.BPREG;
    while (count < maxdepth) {
        if (*framePointer < (UINT_PTR)framePointer) {
            if (*framePointer == NULL) {
                // Looks like we reached the end of the stack.
                break;
            }
            else {
                // Invalid frame pointer. Frame pointer addresses should always
                // increase as we move up the stack.
                m_status |= CALLSTACK_STATUS_INCOMPLETE;
                break;
            }
        }
        if (*framePointer & (sizeof(UINT_PTR*) - 1)) {
            // Invalid frame pointer. Frame pointer addresses should always
            // be aligned to the size of a pointer. This probably means that
            // we've encountered a frame that was created by a module built with
            // frame pointer omission (FPO) optimization turned on.
            m_status |= CALLSTACK_STATUS_INCOMPLETE;
            break;
        }
        if (IsBadReadPtr((UINT*)*framePointer, sizeof(UINT_PTR*))) {
            // Bogus frame pointer. Again, this probably means that we've
            // encountered a frame built with FPO optimization.
            m_status |= CALLSTACK_STATUS_INCOMPLETE;
            break;
        }
        count++;
        push_back(*(framePointer + 1));
        framePointer = (UINT_PTR*)*framePointer;
    }
#elif defined(_M_X64)*/
    UINT32 maxframes = min(62, maxdepth + 10);
    //UINT_PTR* myFrames = new UINT_PTR[maxframes];
    UINT_PTR *myFrames = (UINT_PTR *)_alloca(maxframes*sizeof(UINT_PTR));
    ZeroMemory(myFrames, sizeof(UINT_PTR) * maxframes);
    ULONG BackTraceHash;
    maxframes = RtlCaptureStackBackTrace(0, maxframes, reinterpret_cast<PVOID*>(myFrames), &BackTraceHash);
    m_hashValue = BackTraceHash;
    UINT32  startIndex = 0;
    while (count < maxframes) {
        if (myFrames[count] == 0)
            break;
        //TBD: So, possibility of context.fp appearing > 1 time, or could we break' on first one found???
        if (myFrames[count] == context.fp)
            startIndex = count;
        count++;
    }
    count = startIndex;
    //TBD: Speed up somehow... avoid funccall overhead?...  append(&myFrames, count, maxframes);
    while (count < maxframes) {
        if (myFrames[count] == 0)
            break;
        push_back(myFrames[count]);
        count++;
    }
    //delete [] myFrames;
//#endif
}

// getStackTrace - Traces the stack as far back as possible, or until 'maxdepth'
//   frames have been traced. Populates the CallStack with one entry for each
//   stack frame traced.
//
//   Note: This function uses a documented Windows API to walk the stack. This
//     API is supposed to be the most reliable way to walk the stack. It claims
//     to be able to walk stack frames that do not follow the conventional stack
//     frame layout. However, this robustness comes at a cost: it is *extremely*
//     slow compared to walking frames by following frame (base) pointers.
//
//  - maxdepth (IN): Maximum number of frames to trace back.
//
//  - framepointer (IN): Frame (base) pointer at which to begin the stack trace.
//      If NULL, then the stack trace will begin at this function.
//
//  Return Value:
//
//    None.
//
VOID SafeCallStack::getStackTrace (UINT32 maxdepth, const context_t& context)
{
    UINT32 count = 0;
    UINT_PTR function = context.func;
    if (function != NULL)
    {
        count++;
        push_back(function);
    }

    if (context.IPREG == NULL)
    {
        return;
    }

    count++;
    push_back(context.IPREG);

    DWORD   architecture   = X86X64ARCHITECTURE;

    // Get the required values for initialization of the STACKFRAME64 structure
    // to be passed to StackWalk64(). Required fields are AddrPC and AddrFrame.
    CONTEXT currentContext;
    memset(&currentContext, 0, sizeof(currentContext));
    currentContext.SPREG = context.SPREG;
    currentContext.BPREG = context.BPREG;
    currentContext.IPREG = context.IPREG;

    // Initialize the STACKFRAME64 structure.
    STACKFRAME64 frame;
    memset(&frame, 0x0, sizeof(frame));
    frame.AddrPC.Offset       = currentContext.IPREG;
    frame.AddrPC.Mode         = AddrModeFlat;
    frame.AddrStack.Offset    = currentContext.SPREG;
    frame.AddrStack.Mode      = AddrModeFlat;
    frame.AddrFrame.Offset    = currentContext.BPREG;
    frame.AddrFrame.Mode      = AddrModeFlat;
    frame.Virtual             = TRUE;

    CriticalSectionLocker<> cs(g_heapMapLock);
    CriticalSectionLocker<DbgHelp> locker(g_DbgHelp);

    // Walk the stack.
    while (count < maxdepth) {
        count++;
        DbgTrace(L"dbghelp32.dll %i: StackWalk64\n", GetCurrentThreadId());
        if (!g_DbgHelp.StackWalk64(architecture, g_currentProcess, g_currentThread, &frame, &currentContext, NULL,
            SymFunctionTableAccess64, SymGetModuleBase64, NULL, locker)) {
                // Couldn't trace back through any more frames.
                break;
        }
        if (frame.AddrFrame.Offset == 0) {
            // End of stack.
            break;
        }

        // Push this frame's program counter onto the CallStack.
        push_back((UINT_PTR)frame.AddrPC.Offset);
    }
}

// getHashValue - Generate callstack hash value.
//
//  Return Value:
//
//    None.
//
DWORD SafeCallStack::getHashValue() const
{
    DWORD       hashcode = 0xD202EF8D;

    // Iterate through each frame in the call stack.
    for (UINT32 frame = 0; frame < m_size; frame++) {
        UINT_PTR programcounter = (*this)[frame];
        hashcode = CalculateCRC32(programcounter, hashcode);
    }
    return hashcode;
}
