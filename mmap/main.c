

#include <stdlib.h>
#include <stdio.h>
#include "fd.h"


int main(int argc,char **argv)
{
  pid_t pid;
  if (argc < 3) {printf("argv"); exit(1);}
  pid = atoi(argv[1]);
  pid = pid == 0 ? getpid() : pid ;
  //printf("[+] mapped new area @ %lx\n",ptrace_mmap(pid));
  printf("[+] mapped new file @ %lx\n",ptrace_mmapfd(pid,argv[2]));
}
