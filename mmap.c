
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <sys/user.h>


typedef struct ret {
  unsigned long addr;
  unsigned long  size;
} ret_t;

void die(char *str) { perror(str);exit(1);}

char sc[] =
  "\x48\xbe\x43\x43\x43\x43\x43\x43\x43\x43"
  "\x48\xbf\x42\x42\x42\x42\x42\x42\x42\x42"
  "\x4d\x31\xc9"
  "\x4d\x31\xc0"
  "\xba\x07\x00\x00\x00"
  "\xb9\x32\x00\x00\x00"
  "\xb8\x09\x00\x00\x00"
  "\x49\x89\xca"
  "\x0f\x05"
  "\xcc";


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


  while(1) {

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
      ret->size = beg - pend -1;
      break;

    }
  }
  fclose(fd);
  return ret;
}

long map(pid_t pid) {
  ret_t * x;
  pid_t  pid;
  int status;
  char *buff[48];
  long *ptr = (long *)buff;
  int i = 0;
  struct user_regs_struct old_regs;
  struct user_regs_struct regs;

  x = get_free_address(pid);
  if (!x) die("get_free_address() ");


  printf("[+] Found nice niche @ %llx (size %llx)\n",x->addr,x->size);

  /** inject shellcode for mapping **/

  /*  64bit                       32bit
     mov rsi, x->size      |  xor ebp, ebp
     xor r9,r9             |  xor edi, edi
     xor r8,r8             |  mov esi, 0x32
     mov edx,0x7           |  mov edx, 0x7
     mov ecx,0x32          |  mov ecx, x->size
     mov rdi, x->addr      |  mov ebx, x->addr
     mov r10,rcx
     mov eax,0x09          |  mov eax, 0xc0
     syscall               |  int 80h | call gs:0x10
  */

  //  ptrace5

  printf("[+] Attemt to inject mmap shellcode (size: %d)\n",sizeof sc);

  if (ptrace(PTRACE_ATTACH,pid,NULL,NULL) < 0)
    die("ptrace(ATTACH)");

  waitpid(pid, &status, 0);
  unsigned long rip;
  if ((rip= ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*RIP,NULL)) <0)
    die("ptrace(PEEK_RIP): ");

  printf("[*] Stopped @ 0x%.16llx\n",rip);

  // make place for shellcode...
  printf("[*] making place for shellcode\n");
  for(i=0;i<sizeof buff;i+=sizeof(void*)){
    *ptr = ptrace(PTRACE_PEEKTEXT,pid,rip+i,NULL);
    ptr++;
  }

  printf("[*] saving registers\n");
  if (ptrace(PTRACE_GETREGS,pid,NULL,&old_regs)<0)
    die("ptrace(SAVEREGS)");


  // replace dummies with real value
  ptr = (long*)memchr(sc,0x43,sizeof sc);
  *ptr = x->size;
  ptr = (long *) memchr(sc,0x42,sizeof sc);
  *ptr = x->addr;


  ptr = (long *) sc;
  printf("[+] Copy mmap shellcode... \n");
  //copy shellcode
  for(i=0;i<sizeof buff;i+=sizeof(void*))
    if(ptrace(PTRACE_POKETEXT,pid,rip+i,*ptr++) < 0)
      die("ptrace(POKE_SHELL)");

  if (ptrace(PTRACE_CONT,pid,NULL,NULL) < 0)
    die("ptrace(CONT)") ;

  waitpid(pid,&status,0);
  if(WSTOPSIG(status)  != SIGTRAP)
    die("uncool somthing interupted..");


  if (ptrace(PTRACE_GETREGS,pid,NULL,&regs)<0)
    die("ptrace(SAVEREGS)");

  if((void*)regs.rax == MAP_FAILED)
    die("[-] mmap() failed :(");

  printf("[+] mapped new area @ %llx\n",regs.rax);

  // restore code
  ptr = (long *) buff;
  for(i=0;i<sizeof buff;i+=sizeof(void*))
    if ( ptrace(PTRACE_POKETEXT,pid,rip+i,*ptr++) <0)
      die("ptrace(RESOTRE)");

  // set rip and regs back
  if (ptrace(PTRACE_SETREGS,pid,NULL,&old_regs)<0)
    die("ptrace(RESOTRE_REGS)");

  if(ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*RIP,&rip)<0)
    die("ptrace(RESOTRE_RIP");

  if(ptrace(PTRACE_DETACH,pid,NULL,NULL))
    die("ptrace(DETACH)");

  return regs.rax
}
int main(int argc,char **argv)
{
  pid_t pid;
  if (argc < 2) die("argv");
  pid = atoi(argv[1]);
  pid = pid == 0 ? getpid() : pid ;
  mmap(pid);
}
