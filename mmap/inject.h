#ifndef _INCLUDE_INJECT_H_
#define _INCLUDE_INJECT_H_

#include "utils.h"


typedef struct breakpoint_t {
  char * name;
  int (*is_fault) (long);
  void (*report_fault)(long);
} breakpoint;

long inject_scode(pid_t pid,char *sc,size_t size,bit_type type,breakpoint *breaks,int int_count);




#endif

