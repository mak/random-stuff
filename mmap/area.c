#include "inject.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

void mmap_report(long ret) {
  errno = 0 - ret;
  perror("mmap(): ");
  exit(1);
}

breakpoint mmap_break = {
  .name = "break after mmap",
  .is_fault = generic_fault,
  .report_fault = mmap_report,
};

typedef struct ret {
  unsigned long addr;
  unsigned long  size;
} ret_t;


ret_t * get_free_address(pid_t pid)
{
  char path[20];
  char tmpline[256];

  unsigned long pend;
  unsigned long beg =0, end=0;
  ret_t * ret = NULL;

  char *ptr = NULL , *ptr2 = NULL;

  FILE *fd;

  snprintf(path,sizeof path,"/proc/%d/maps",pid);
  if((fd=fopen(path,"r")) == NULL)
    die("open() ");


  while(!feof(fd)) {

    if((fgets(tmpline,sizeof tmpline,fd)) == NULL)
      die("read() ");

    //    printf("%s\n",tmpline);
    if ((ptr=strchr(tmpline,'-')) == NULL)
      die("strchr()");

    /* if ((ptr2=strchr(tmpline,'-')) == NULL) */
    /*   die("strchr()"); */

    pend = end;

    beg  = strtol(tmpline,NULL,16);
    end  = strtol(ptr+1,NULL,16);

    //    printf("%x - %x\n",beg,end);
    if( beg && pend && pend != beg ) {
      ret = calloc(1,sizeof(ret_t));
      ret->addr = pend;
      ret->size = (beg - pend -1) & 0x0fffffff;
      break;

    }
  }
  fclose(fd);
  return ret;
}


long ptrace_mmap(pid_t pid)
{
  long *ptr;
  ret_t * x;
  char sc64[] =
    "\x48\xbe\x43\x43\x43\x43\x43\x43\x43\x43"
    "\x48\xbf\x42\x42\x42\x42\x42\x42\x42\x42"
    "\x4d\x31\xc9"
    "\x4d\x31\xc0"
    "\xba\x07\x00\x00\x00"
    "\xb9\x32\x00\x00\x00"
    "\xb8\x09\x00\x00\x00"
    "\x49\x89\xca"
    "\x0f\x05"
    "\x90";

  char sc32[] =
    "\x31\xed"
    "\x31\xff"
    "\xbe\x32\x00\x00\x00"
    "\xba\x07\x00\x00\x00"
    "\xc1\xed\x0c"
    "\xb9\x43\x43\x43\x43"
    "\xbb\x42\x42\x42\x42"
    "\xb8\xc0\x00\x00\x00"
    "\xcd\x80"
    "\x90";

  bit_type type =get_type(pid);
  char *sc =  type == BITS32 ? sc32 : sc64;
  size_t scsize = type == BITS32 ? sizeof sc32 : sizeof sc64;
  breakpoint breaks[] = { mmap_break};

  x = get_free_address(pid);
  if (!x) die("get_free_address() ");

  printf("[+] Found nice niche @ %lx (size %lx)\n",x->addr,x->size);
  printf("[+] Attemt to inject mmap shellcode (size: %lu)\n",scsize);

  // replace dummies with real value
  ptr = (long*)memchr(sc,0x43,scsize);
  *ptr = x->size;
  ptr = (long *) memchr(sc,0x42,scsize);
  *ptr = x->addr;

  /** inject shellcode for mapping **/

  /*  64bit                       32bit
     mov rsi, x->size      |  xor ebp, ebp
     xor r9,r9             |  xor edi, edi
     xor r8,r8             |  mov esi, 0x32
     mov edx,0x7           |  mov edx, 0x7
     mov ecx,0x32          |  mov ecx, x->size
     mov rdi, x->addr      |  mov ebx, x->addr
     mov r10,rcx           |  shr ebp, 0xc
     mov eax,0x09          |  mov eax, 0xc0
     syscall               |  int 80h | call gs:0x10
  */
  free(x);
  return inject_scode(pid,sc,scsize,type,breaks,1);
}
