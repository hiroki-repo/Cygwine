// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"
#include "windows.h"
#include "subauth.h"
#include <stdlib.h>
#include "winternl.h"
#include <malloc.h>

#ifdef _WIN64
typedef UINT64 UNATIVE;
typedef INT64 INATIVE;
#else
#ifdef _WIN32
typedef UINT32 UNATIVE;
typedef INT32 INATIVE;
#else
typedef UINT16 UNATIVE;
typedef INT16 INATIVE;
#endif
#endif

typedef LPWSTR WINAPI tWin32_GetCommandLineW();
typedef LPSTR WINAPI tWin32_GetCommandLineA();
typedef INATIVE tUnixSyscallHandler(UNATIVE, UNATIVE, UNATIVE, UNATIVE, UNATIVE, UNATIVE, UNATIVE);
tUnixSyscallHandler* _UnixSyscallHandler;
tWin32_GetCommandLineW* Win32_GetCommandLineW;
tWin32_GetCommandLineA* Win32_GetCommandLineA;
HMODULE k32 = 0;
__declspec(align(4096)) char UnixSyscallHandler[] = {
#ifdef ARMWOW64
    /*
    mov eax,esp
    jmp calling
    mov eax,0x11223344
    calling:
    in eax,0xe6
    ret
    */
    0x89 ,0xE0 ,0xEB ,0x05 ,0xB8 ,0x44 ,0x33 ,0x22 ,0x11 ,0xE5 ,0xE6 ,0xC3,
    /*
    mov x8,x0
    ldr w0,[x8,#4]
    ldr w1,[x8,#8]
    ldr w2,[x8,#12]
    ldr w3,[x8,#16]
    ldr w4,[x8,#20]
    ldr w5,[x8,#24]
    ldr w8,[x8,#0]
    svc #0
    ret
    */
    0xE8 ,0x03 ,0x00 ,0xAA ,0x00 ,0x05 ,0x40 ,0xB9 ,0x01 ,0x09 ,0x40 ,0xB9 ,0x02 ,0x0D ,0x40 ,0xB9 ,0x03 ,0x11 ,0x40 ,0xB9 ,0x04 ,0x15 ,0x40 ,0xB9 ,0x05 ,0x19 ,0x40 ,0xB9 ,0x08 ,0x01 ,0x40 ,0xB9 ,0x01 ,0x00 ,0x00 ,0xD4 ,0xC0 ,0x03 ,0x5F ,0xD6
#else
#ifdef _WIN64
#ifdef _M_AMD64
    /*
    push rdi
    push rsi
    mov rax,rcx
    mov rcx,rsp
    add rcx,16
    mov rdi,rdx
    mov rsi,r8
    mov rdx,r9
    mov r10,[rcx + 8*4]
    mov r8,[rcx + 8*5]
    mov r9,[rcx + 8*6]
    syscall
    pop rdi
    pop rsi
    ret
    */
    0x57 ,0x56 ,0x48 ,0x89 ,0xC8 ,0x48 ,0x89 ,0xE1 ,0x48 ,0x83 ,0xC1 ,0x10 ,0x48 ,0x89 ,0xD7 ,0x4C ,0x89 ,0xC6 ,0x4C ,0x89 ,0xCA ,0x4C ,0x8B ,0x51 ,0x20 ,0x4C ,0x8B ,0x41 ,0x28 ,0x4C ,0x8B ,0x49 ,0x30 ,0x0F ,0x05 ,0x5F ,0x5E ,0xC3
#else
#ifdef _M_ARM64
    /*
    mov x8,x0
    mov x0,x1
    mov x1,x2
    mov x2,x3
    mov x3,x4
    mov x4,x5
    mov x5,x6
    svc #0
    ret
    */
    0xE8 ,0x03 ,0x00 ,0xAA ,0xE0 ,0x03 ,0x01 ,0xAA ,0xE1 ,0x03 ,0x02 ,0xAA ,0xE2 ,0x03 ,0x03 ,0xAA ,0xE3 ,0x03 ,0x04 ,0xAA ,0xE4 ,0x03 ,0x05 ,0xAA ,0xE5 ,0x03 ,0x06 ,0xAA ,0x01 ,0x00 ,0x00 ,0xD4 ,0xC0 ,0x03 ,0x5F ,0xD6
#endif
#endif
#else
#ifdef _M_IX86
    /*
    push esi
    mov esi,esp
    add esi,4
    push ebx
    push edi
    push ebp
    mov eax, dword ptr [esi + 4]
    mov ebx, dword ptr [esi + 8]
    mov ecx, dword ptr [esi + 12]
    mov edx, dword ptr [esi + 16]
    mov edi, dword ptr [esi + 24]
    mov ebp, dword ptr [esi + 28]
    mov esi, dword ptr [esi + 20]
    int 0x80
    pop ebp
    pop edi
    pop ebx
    pop esi
    ret
    */
    0x56 ,0x89 ,0xE6 ,0x83 ,0xC6 ,0x04 ,0x53 ,0x57 ,0x55 ,0x8B ,0x46 ,0x04 ,0x8B ,0x5E ,0x08 ,0x8B ,0x4E ,0x0C ,0x8B ,0x56 ,0x10 ,0x8B ,0x7E ,0x18 ,0x8B ,0x6E ,0x1C ,0x8B ,0x76 ,0x14 ,0xCD ,0x80 ,0x5D ,0x5F ,0x5B ,0x5E ,0xC3
#else
#ifdef _M_ARM
    /*
    push {r4-r7}
    add sp,16
    mov r7,r0
    mov r0,r1
    mov r1,r2
    mov r2,r3
    pop {r3-r5}
    svc #0
    push {r3-r5}
    sub sp,16
    pop {r4-r7}
    bx lr
    svctmp:
    */
    0xF0 ,0xB4 ,0x04 ,0xB0 ,0x07 ,0x46 ,0x08 ,0x46 ,0x11 ,0x46 ,0x1A ,0x46 ,0x38 ,0xBC ,0x00 ,0xDF ,0x38 ,0xB4 ,0x84 ,0xB0 ,0xF0 ,0xBC ,0x70 ,0x47
#endif
#endif
#endif
#endif
};

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
#ifdef ARMWOW64
        * (UINT32*)(&UnixSyscallHandler[5]) = ((UINT32)&UnixSyscallHandler[12]);
#endif
        DWORD tmp;
        VirtualProtect(&UnixSyscallHandler, sizeof(UnixSyscallHandler), 0x40, &tmp);
        _UnixSyscallHandler = ((tUnixSyscallHandler*)&UnixSyscallHandler);
        k32 = LoadLibraryA("kernel32.dll");
        Win32_GetCommandLineW = (tWin32_GetCommandLineW*)GetProcAddress(k32, "GetCommandLineW");
        Win32_GetCommandLineA = (tWin32_GetCommandLineA*)GetProcAddress(k32, "GetCommandLineA");
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#ifdef ARMWOW64
#define _M_ARM64
#endif

#ifdef _M_ARM64
#define SYS_accept 202
#define SYS_exit 93
#define SYS_lseek 64
#else
#ifdef _M_ARM
#define SYS__llseek 140
#define SYS__newselect 142
#define SYS__sysctl 149
#define SYS_accept 285
#define SYS_exit 1
#define SYS_lseek 19
#else
#ifdef _M_AMD64
#define SYS__sysctl 156
#define SYS_accept 43
#define SYS_exit 60
#define SYS_lseek 8
#else
#ifdef _M_IX86
#define SYS__llseek 140
#define SYS__newselect 142
#define SYS__sysctl 149
#define SYS_exit 1
#define SYS_lseek 19
#endif
#endif
#endif
#endif

/* Cygwin replacement for GetCommandLineW.  Returns a concatenated wide string
   representing the argv list, constructed using roughly the same mechanism as
   child_info_spawn::worker */
extern "C" __declspec(dllexport) LPWSTR WINAPI GetCommandLineW(void)
{
    return Win32_GetCommandLineW();
}

/* Cygwin replacement for GetCommandLineA.  Returns a concatenated string
   representing the argv list, constructed using roughly the same mechanism
   as child_info_spawn::worker */
extern "C" __declspec(dllexport) LPSTR WINAPI GetCommandLineA(void)
{
    return Win32_GetCommandLineA();
}
