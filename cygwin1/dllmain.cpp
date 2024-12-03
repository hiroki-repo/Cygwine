// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"
#include "windows.h"
#include "subauth.h"
#include <stdlib.h>
#include <malloc.h>
#include <math.h>
#include <stdio.h>

#pragma warning(disable : 4996)

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
typedef INATIVE tvforkarm();
tvforkarm* _vforkarm;
tWin32_GetCommandLineW* Win32_GetCommandLineW;
tWin32_GetCommandLineA* Win32_GetCommandLineA;
HMODULE k32 = 0;
__declspec(align(4096)) char vforkarm[] = {
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
#endif
    /*
    mov x0,0x4111
    mov x1,sp
    mov x8,220
    svc #0
    cmn x0,#4095
    b.cs svcerror
    ret
    svcerror:
    mov x0,-1
    ret
    */
    0x20,0x22,0x88,0xD2,0xE1,0x03,0x00,0x91,0x88,0x1B,0x80,0xD2,0x01,0x00,0x00,0xD4,0x1F,0xFC,0x3F,0xB1,0x42,0x00,0x00,0x54,0xC0,0x03,0x5F,0xD6,0x00,0x00,0x80,0x92,0xC0,0x03,0x5F,0xD6
};
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
#ifdef ARMWIN86EMU
    /*
    mov eax,esp
    jmp calling
    mov eax,0x11223344
    calling:
    in eax,0xe5
    ret
    */
    0x89 ,0xE0 ,0xEB ,0x05 ,0xB8 ,0x44 ,0x33 ,0x22 ,0x11 ,0xE5 ,0xE5 ,0xC3,
    /*
    push {r4-r7}
    mov r6,r0
    ldr r7,[r6,#0]
    ldr r0,[r6,#4]
    ldr r1,[r6,#8]
    ldr r2,[r6,#12]
    ldr r3,[r6,#16]
    ldr r4,[r6,#20]
    ldr r5,[r6,#24]
    svc #0
    pop {r4-r7}
    bx lr
    */
    0xF0 ,0xB4 ,0x06 ,0x46 ,0x37 ,0x68 ,0x70 ,0x68 ,0xB1 ,0x68 ,0xF2 ,0x68 ,0x33 ,0x69 ,0x74 ,0x69 ,0xB5 ,0x69 ,0x00 ,0xDF ,0xF0 ,0xBC ,0x70 ,0x47
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
#endif
};

extern "C" void cygwin_dll_init() {
#ifdef ARMWOW64
    *(UINT32*)(&UnixSyscallHandler[5]) = ((UINT32)&UnixSyscallHandler[12]);
    *(UINT32*)(&vforkarm[5]) = ((UINT32)&vforkarm[12]);
#else
#ifdef ARMWIN86EMU
    *(UINT32*)(&UnixSyscallHandler[5]) = (((UINT32)&UnixSyscallHandler[12]) | 0x80000001);
#endif
#endif
    DWORD tmp;
    VirtualProtect(&UnixSyscallHandler, sizeof(UnixSyscallHandler), 0x40, &tmp);
    VirtualProtect(&vforkarm, sizeof(vforkarm), 0x40, &tmp);
#ifdef _M_ARM
    _UnixSyscallHandler = ((tUnixSyscallHandler*)(((UINT64)&UnixSyscallHandler) | 1));
#else
    _UnixSyscallHandler = ((tUnixSyscallHandler*)&UnixSyscallHandler);
#endif
    _vforkarm = ((tvforkarm*)&vforkarm);
    k32 = LoadLibraryA("kernel32.dll");
    if (k32 != 0) {
        Win32_GetCommandLineW = (tWin32_GetCommandLineW*)GetProcAddress(k32, "GetCommandLineW");
        Win32_GetCommandLineA = (tWin32_GetCommandLineA*)GetProcAddress(k32, "GetCommandLineA");
    }
    return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#ifdef ARMWOW64
#define _M_ARM64
#else
#ifdef ARMWIN86EMU
#define _M_ARM
#endif
#endif

#ifdef _M_ARM64EC
#include "unistd_64_arm64.h"
#else
#ifdef _M_ARM64
#include "unistd_64_arm64.h"
#else
#ifdef _M_ARM
#define __thumb__
#include "unistd_32_arm.h"
#else
#ifdef _M_AMD64
#include "unistd_64_amd64.h"
#else
#ifdef _M_IX86
#include "unistd_32_x86.h"
#endif
#endif
#endif
#endif
#endif

extern "C" {
    __declspec(dllexport) void _exit(int error_code) { 
        _UnixSyscallHandler(__NR_exit, error_code, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) int __unlink(void* path) {
#ifndef __NR_unlink
        return _UnixSyscallHandler(__NR_unlinkat, -100, (UNATIVE)path, 0, 0, 0, 0);
#else
        return _UnixSyscallHandler(__NR_unlink, (UNATIVE)path, 0, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _fork() {
#ifndef __NR_fork
        UNATIVE ctid = _UnixSyscallHandler(__NR_gettid, 0, 0, 0, 0, 0, 0);
        return _UnixSyscallHandler(__NR_clone, 0x01000000 | 0x00200000 | 17, 0, 0, 0, (UNATIVE)&ctid, 0);
#else
        return _UnixSyscallHandler(__NR_fork, 0, 0, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _vfork() {
#ifndef __NR_vfork
        return _vforkarm();
#else
        return _UnixSyscallHandler(__NR_vfork, 0, 0, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _getcwd(void* buf, unsigned long size) {
        return _UnixSyscallHandler(__NR_getcwd, (UNATIVE)buf, (UNATIVE)size, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getegid() {
        return _UnixSyscallHandler(__NR_getegid, 0, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _geteuid() {
        return _UnixSyscallHandler(__NR_geteuid, 0, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getgid() {
        return _UnixSyscallHandler(__NR_getgid, 0, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getgroups(int gidsetsize, void* grouplist) {
        return _UnixSyscallHandler(__NR_getgroups, (UNATIVE)gidsetsize, (UNATIVE)grouplist, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getitimer(int which, void* value) {
        return _UnixSyscallHandler(__NR_getitimer, (UNATIVE)which, (UNATIVE)value, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getpeername(int which, void* value) {
        return _UnixSyscallHandler(__NR_getpeername, (UNATIVE)which, (UNATIVE)value, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getpgid(UNATIVE pid) {
        return _UnixSyscallHandler(__NR_getpgid, (UNATIVE)pid, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getpgrp(UNATIVE pid) {
#ifndef __NR_getpgrp
        return -1;
#else
        return _UnixSyscallHandler(__NR_getpgrp, (UNATIVE)pid, 0, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _getpid() {
        return _UnixSyscallHandler(__NR_getpid, 0, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getppid() {
        return _UnixSyscallHandler(__NR_getppid, 0, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getpriority(int which, int who) {
        return _UnixSyscallHandler(__NR_getpriority, which, who, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getrandom(char* buf, size_t count, unsigned int flags) {
        return _UnixSyscallHandler(__NR_getrandom, (UNATIVE)buf, count, flags, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getrlimit(unsigned int resource, void* rlim) {
#ifndef __NR_getrlimit
        return -1;
#else
        return _UnixSyscallHandler(__NR_getrlimit, resource, (UNATIVE)rlim, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _getrusage(int who, void* ru) {
        return _UnixSyscallHandler(__NR_getrusage, who, (UNATIVE)ru, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getsid(UNATIVE pid) {
        return _UnixSyscallHandler(__NR_getsid, (UNATIVE)pid, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getsockname(int sockfd, void* addr, void* addrlen) {
        return _UnixSyscallHandler(__NR_getsockname, sockfd, (UNATIVE)addr, (UNATIVE)addrlen, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getsockopt(int fd, int level, int optname, void* optval, void* optlen) {
        return _UnixSyscallHandler(__NR_getsockopt, fd, level, optname, (UNATIVE) optval, (UNATIVE)optlen, 0);
    }
    __declspec(dllexport) UNATIVE _gettimeofday(void* tv, void* tz) {
        return _UnixSyscallHandler(__NR_gettimeofday, (UNATIVE)tv, (UNATIVE)tz, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _getuid() {
        return _UnixSyscallHandler(__NR_getuid, 0, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setgid(UNATIVE gid) {
        return _UnixSyscallHandler(__NR_setgid, gid, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setgroups(int gidsetsize, void* grouplist) {
        return _UnixSyscallHandler(__NR_setgroups, (UNATIVE)gidsetsize, (UNATIVE)grouplist, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setitimer(int which, void* value, void* ovalue) {
        return _UnixSyscallHandler(__NR_setitimer, (UNATIVE)which, (UNATIVE)value, (UNATIVE)ovalue, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setpgid(UNATIVE pid, UNATIVE pgid) {
        return _UnixSyscallHandler(__NR_setpgid, pid, pgid, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setpriority(int which, int who, int niceval) {
        return _UnixSyscallHandler(__NR_setpriority, which, who, niceval, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setrlimit(unsigned int resource, void* rlim) {
#ifndef __NR_setrlimit
        return -1;
#else
        return _UnixSyscallHandler(__NR_setrlimit, resource, (UNATIVE)rlim, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _setsid() {
        return _UnixSyscallHandler(__NR_setsid, 0, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setsockopt(int fd, int level, int optname, void* optval, void* optlen) {
        return _UnixSyscallHandler(__NR_setsockopt, fd, level, optname, (UNATIVE)optval, (UNATIVE)optlen, 0);
    }
    __declspec(dllexport) UNATIVE _settimeofday(void* tv, void* tz) {
        return _UnixSyscallHandler(__NR_settimeofday, (UNATIVE)tv, (UNATIVE)tz, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _setuid(UNATIVE uid) {
        return _UnixSyscallHandler(__NR_setuid, uid, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _read(unsigned int fd, void* buf, size_t count) {
        return _UnixSyscallHandler(__NR_read, fd, (UNATIVE)buf, count, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _write(unsigned int fd, void* buf, size_t count) {
        return _UnixSyscallHandler(__NR_write, fd, (UNATIVE)buf, count, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _open(void* filename, int flags, UNATIVE mode) {
#ifndef __NR_open
        return _UnixSyscallHandler(__NR_openat, -100, (UNATIVE)filename, flags, mode, 0, 0);
#else
        return _UnixSyscallHandler(__NR_open, (UNATIVE)filename, flags, mode, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _openat(int dfd, void* filename, int flags, UNATIVE mode) {
        return _UnixSyscallHandler(__NR_openat, dfd, (UNATIVE)filename, flags, mode, 0, 0);
    }
    __declspec(dllexport) UNATIVE _close(unsigned int fd) {
        return _UnixSyscallHandler(__NR_close, fd, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _stat(void* filename, void* statbuf) {
#ifndef __NR_stat
        UINT64 fddata = _open(filename, 0, 0);
        UINT64 ret = _UnixSyscallHandler(__NR_fstat, fddata, (UNATIVE)statbuf, 0, 0, 0, 0);
        close(fddata);
        return ret;
#else
        return _UnixSyscallHandler(__NR_stat, (UNATIVE)filename, (UNATIVE)statbuf, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _fstat(unsigned int fd, void* statbuf) {
        return _UnixSyscallHandler(__NR_fstat, fd, (UNATIVE)statbuf, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _lstat(void* filename, void* statbuf) {
#ifndef __NR_lstat
        UINT64 fddata = _open(filename, 0, 0);
        UINT64 ret = _UnixSyscallHandler(__NR_fstat, fddata, (UNATIVE)statbuf, 0, 0, 0, 0);
        close(fddata);
        return ret;
#else
        return _UnixSyscallHandler(__NR_lstat, (UNATIVE)filename, (UNATIVE)statbuf, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) int _chroot(void* filename) {
        return _UnixSyscallHandler(__NR_chroot, (UNATIVE)filename, 0, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _chmod(void* filename, UNATIVE mode) {
#ifndef __NR_chmod
        UINT64 fddata = _open(filename, 0, 2);
        UINT64 ret = _UnixSyscallHandler(__NR_fchmod, fddata, mode, 0, 0, 0, 0);
        close(fddata);
        return ret;
#else
        return _UnixSyscallHandler(__NR_chmod, (UNATIVE)filename, mode, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _fchmod(unsigned int fd, UNATIVE mode) {
        return _UnixSyscallHandler(__NR_fchmod, fd, mode, 0, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _chown(void* filename, UNATIVE user, UNATIVE group) {
#ifndef __NR_chown
        UINT64 fddata = _open(filename, 0, 2);
        UINT64 ret = _UnixSyscallHandler(__NR_fchown, fddata, user, group, 0, 0, 0);
        close(fddata);
        return ret;
#else
        return _UnixSyscallHandler(__NR_chown, (UNATIVE)filename, user, group, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _fchown(unsigned int fd, UNATIVE user, UNATIVE group) {
        return _UnixSyscallHandler(__NR_fchown, fd, user, group, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _lchown(void* filename, UNATIVE user, UNATIVE group) {
#ifndef __NR_lchown
        UINT64 fddata = _open(filename, 0, 2);
        UINT64 ret = _UnixSyscallHandler(__NR_fchown, fddata, user, group, 0, 0, 0);
        close(fddata);
        return ret;
#else
        return _UnixSyscallHandler(__NR_lchown, (UNATIVE)filename, user, group, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _creat(void* filename, UNATIVE mode) {
#ifndef __NR_creat
        return _open(filename, 00000100 | 00000001 | 00001000, mode);
#else
        return _UnixSyscallHandler(__NR_creat, (UNATIVE)filename, mode, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _link(void* oldname, void* newname) {
#ifndef __NR_link
        return _UnixSyscallHandler(__NR_linkat, -100, (UNATIVE)oldname, -100, (UNATIVE)newname, 0, 0);
#else
        return _UnixSyscallHandler(__NR_link, (UNATIVE)oldname, (UNATIVE)newname, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _linkat(int olddfd, void* oldname, int newdfd, void* newname, int flags) {
        return _UnixSyscallHandler(__NR_linkat, olddfd, (UNATIVE)oldname, newdfd, (UNATIVE)newname, flags, 0);
    }
    __declspec(dllexport) UNATIVE _symlink(void* oldname, void* newname) {
#ifndef __NR_symlink
        return _UnixSyscallHandler(__NR_symlinkat, (UNATIVE)oldname, -100, (UNATIVE)newname, 0, 0, 0);
#else
        return _UnixSyscallHandler(__NR_symlink, (UNATIVE)oldname, (UNATIVE)newname, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _symlinkat(void* oldname, int newdfd, void* newname) {
        return _UnixSyscallHandler(__NR_symlinkat, (UNATIVE)oldname, newdfd, (UNATIVE)newname, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _readlink(void* path, void* buf, int bufsiz) {
#ifndef __NR_readlink
        return _UnixSyscallHandler(__NR_readlinkat, -100, (UNATIVE)path, (UNATIVE)buf, bufsiz, 0, 0);
#else
        return _UnixSyscallHandler(__NR_readlink, (UNATIVE)path, (UNATIVE)buf, bufsiz, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _readlinkat(int dfd, void* path, void* buf, int bufsiz) {
        return _UnixSyscallHandler(__NR_readlinkat, dfd, (UNATIVE)path, (UNATIVE)buf, bufsiz, 0, 0);
    }
    __declspec(dllexport) UNATIVE _unlinkat(int dfd, void* pathname, int flag) {
        return _UnixSyscallHandler(__NR_unlinkat, dfd, (UNATIVE)pathname, flag, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _rename(void* oldname, void* newname) {
#ifndef __NR_rename
        return _UnixSyscallHandler(__NR_renameat, -100, (UNATIVE)oldname, -100, (UNATIVE)newname, 0, 0);
#else
        return _UnixSyscallHandler(__NR_rename, (UNATIVE)oldname, (UNATIVE)newname, 0, 0, 0, 0);
#endif
    }
    __declspec(dllexport) UNATIVE _renameat(int olddfd, void* oldname, int newdfd, void* newname) {
        return _UnixSyscallHandler(__NR_renameat, olddfd, (UNATIVE)oldname, newdfd, (UNATIVE)newname, 0, 0);
    }
    __declspec(dllexport) UNATIVE _renameat2(int olddfd, void* oldname, int newdfd, void* newname, unsigned int flags) {
        return _UnixSyscallHandler(__NR_renameat2, olddfd, (UNATIVE)oldname, newdfd, (UNATIVE)newname, flags, 0);
    }
    __declspec(dllexport) UNATIVE _fchmodat(int dfd, void* pathname, UNATIVE mode) {
        return _UnixSyscallHandler(__NR_fchmodat, dfd, (UNATIVE)pathname, mode, 0, 0, 0);
    }
    __declspec(dllexport) UNATIVE _fchownat(int dfd, void* filename, UNATIVE user, UNATIVE group, int flag) {
        return _UnixSyscallHandler(__NR_fchownat, dfd, (UNATIVE)filename, user, group, flag, 0);
    }

    __declspec(dllexport) void* _memcpy(void* _Dst, const void* _Src, size_t _Size) { return memcpy(_Dst,_Src,_Size); }
    __declspec(dllexport) int _printf(char const* const _Format, ...) { va_list args; va_start(args, _Format); UNATIVE ret = ((int(*)(char const* const, void*))(&printf))(_Format, (void*)args); va_end(args); return ret; }
    __declspec(dllexport) int _sprintf(char* const _Buffer, char const* const _Format, ...) { va_list args; va_start(args, _Format); UNATIVE ret = ((int(*)(char* const, char const* const, void*))(&sprintf))(_Buffer, _Format, (void*)args); va_end(args); return ret; }
    __declspec(dllexport) int _wsprintf(wchar_t const* const _Format, ...) { va_list args; va_start(args, _Format); UNATIVE ret = ((int(*)(const wchar_t const* const, void*))(&wsprintf))(_Format, (void*)args); va_end(args); return ret; }
    int __swprintf(wchar_t* const _Buffer, size_t count, wchar_t const* const _Format, ...) { va_list args; va_start(args, _Format); UNATIVE ret = ((int(*)(wchar_t* const, size_t, const wchar_t* const, void*, void*))(&_vswprintf_c_l))(_Buffer, count, _Format, 0, (void*)args); va_end(args); return ret; }
    __declspec(dllexport) int _memcmp(void const* _Buf1, void const* _Buf2, size_t      _Size) { return memcmp(_Buf1, _Buf2, _Size); }

    __declspec(dllexport) double _tan(double x) { return tan(x); }
    __declspec(dllexport) double _cos(double x) { return cos(x); }
    __declspec(dllexport) double _sin(double x) { return sin(x); }
    __declspec(dllexport) double _atan(double x) { return atan(x); }
    __declspec(dllexport) double _acos(double x) { return acos(x); }
    __declspec(dllexport) double _asin(double x) { return asin(x); }
    __declspec(dllexport) int _abs(int x) { return abs(x); }
    __declspec(dllexport) long _labs(long x) { return labs(x); }
    __declspec(dllexport) long long _llabs(long x) { return llabs(x); }
    __declspec(dllexport) double _atan2(double y, double x) { return atan2(y, x); }
    __declspec(dllexport) double _cosh(double x) { return cosh(x); }
    __declspec(dllexport) double _exp(double x) { return exp(x); }
    __declspec(dllexport) double _fabs(double x) { return fabs(x); }
    __declspec(dllexport) double _fmod(double x, double y) { return fmod(x, y); }
    __declspec(dllexport) double _log(double x) { return log(x); }
    __declspec(dllexport) double _log10(double x) { return log10(x); }
    __declspec(dllexport) double _pow(double x, double y) { return pow(x, y); }
    __declspec(dllexport) double _sinh(double x) { return sinh(x); }
    __declspec(dllexport) double _sqrt(double x) { return sqrt(x); }
    __declspec(dllexport) double _tanh(double x) { return tanh(x); }
    __declspec(dllexport) double _atanh(double x) { return atanh(x); }
    __declspec(dllexport) double _acosh(double x) { return acosh(x); }
    __declspec(dllexport) double _asinh(double x) { return asinh(x); }
    __declspec(dllexport) double _atof(char const* _String) { return atof(_String); }
    __declspec(dllexport) double __atof_l(char const* _String, _locale_t _Locale) { return _atof_l(_String, _Locale); }
}

/* Cygwin replacement for GetCommandLineW.  Returns a concatenated wide string
   representing the argv list, constructed using roughly the same mechanism as
   child_info_spawn::worker */
extern "C" LPWSTR __stdcall GetCommandLineW(void)
{
    return Win32_GetCommandLineW();
}

/* Cygwin replacement for GetCommandLineA.  Returns a concatenated string
   representing the argv list, constructed using roughly the same mechanism
   as child_info_spawn::worker */
extern "C" LPSTR __stdcall GetCommandLineA(void)
{
    return Win32_GetCommandLineA();
}
