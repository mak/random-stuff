#include "inject.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

void mmap_report(long ret) {
  errno = 0 - ret;
  perror("mmap(): ");
  exit(1);
}

void open_report(long ret) {
  errno = 0 - ret;
  perror("open(): ");
  exit(1);
}

void close_report(long ret) {
  errno = 0 - ret;
  perror("close(): ");
  exit(1);
}


breakpoint mmap_break = {
  .name = "break after mmap",
  .is_fault = generic_fault,
  .report_fault = mmap_report,
};

breakpoint open_break = {
  .name = "break after mmap",
  .is_fault = generic_fault,
  .report_fault = open_report,
};

breakpoint close_break = {
  .name = "break after close",
  .is_fault = generic_fault,
  .report_fault = close_report,
};

breakpoint end_break = {
  .name = "break for read mmaped address",
  .is_fault = generic_fault,
  .report_fault = NULL,
};


long ptrace_mmapfd(pid_t pid,char *path)
{
  size_t size;
  struct stat sb;
  long *ptr,ret;

  char sc64[] =
    /* zero the shit out */
    "\x48\x31\xc0\x48\x31\xc9\x48\x31\xd2"
    /* accutal hellcode */
    "\xeb\x36\x5f\x48\x31\xd2\x48\x31"
    "\xf6\xb0\x02\x0f\x05\xcc\x49\x89"
    "\xc0\x48\xbe\x41\x41\x41\x41\x41"
    "\x41\x41\x41\x48\x31\xff\x4d\x31"
    "\xc9\xb2\x05\xb1\x02\x49\x89\xca"
    "\xb0\x09\x0f\x05\xcc\x50\x4c\x89"
    "\xc7\xb0\x03\x0f\x05\xcc\x58\xcc"
    "\xe8\xc5\xff\xff\xff";

  char sc32[] =
    "\xeb\x29\x5b\x31\xd2\x31\xc9\xb0"
    "\x05\xcd\x80\xcc\x89\xc7\xb9\x41"
    "\x41\x41\x41\x31\xed\x31\xdb\x31"
    "\xf6\x46\x46\xb2\x05\xb0\xc0\xcd"
    "\x80\xcc\x50\x89\xfb\xb0\x06\xcd"
    "\x80\x58\xcc\xe8\xd2\xff\xff\xff";


  char *sce;
  bit_type type = get_type(pid);
  char *sc =  type == BITS32 ? sc32 : sc64;
  size_t scsize = type == BITS32 ? sizeof sc32 : sizeof sc64;
  breakpoint breaks[] = { end_break,close_break,mmap_break,open_break};

  int fd = open(path,0,0);
  fstat(fd,&sb);
  close(fd);
  printf("[*] Prepering shellcode for mmaping %s (size: %lu)\n",path,sb.st_size);
  printf("[*] Attemt to inject read_mmap shellcode (size: %lu)\n",scsize);


  // replace dumy
  ptr  = (long*) memchr(sc,0x41,scsize);
  *ptr = (long) sb.st_size;

  sce = malloc(scsize + strlen(path) + 1);
  memcpy(sce,sc,scsize);
  memcpy(sce+scsize-1,path,strlen(path));
  sce[scsize+strlen(path)] = '\x00';

  /** inject shellcode for mapping **/

  /*  64bit            32bit
                  jmp end
                  begin:   |
     pop rdi ; file_path   |  pop ebx
     xor rdx,rdx           |  xor edx,edx
     xor rsi,rsi           |  xor ecx,ecx
     mov al,0x2            |  mov al,0x5
     syscall               |  int 80h | call gs:0x10
                  int3
     mov r8, rax           |  mov edi,eax
     mov rsi, size         |  mov ecx, x->size
     xor rdi,rdi           |  xor edi,edi
     xor r9,r9             |  xor ebp,ebp
     mov dl,0x5            |  xor esi,esi
     mov cl,0x2            |  inc esi; inc esi;
     mov r10,rcx           |  mov dl, 0x5
     mov al,0x9            |  mov al, 0xc0
     syscall               |  int 80h | call gs:0x10
                  int3
     push rax              |  push eax
     mov rdi, r8           |  mov ebx,edi
     mov al, 0x3           |  mov al,0x6
     syscall               |  int 80h | call gs:0x10
                  int3
     pop rax               |  pop  eax
                  int3
		  call begin
		  /path/to/library.so\x00
  */
  ret = inject_scode(pid,sce,scsize+strlen(path),type,breaks,4);
  free(sce);
  return ret;

}
