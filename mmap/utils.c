#include "utils.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void die(char *str) { perror(str);exit(1);}

int generic_fault(long ret) {
  return ret < 1 ? 1 : 0;
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
