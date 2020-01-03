#ifndef __PTRACE_H
#define __PTRACE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <string.h>


void getdata(pid_t child, long addr,
             char *str, int len);

void putdata(pid_t child, long addr,
             char *str, int len);

long freespaceaddr(pid_t pid);

#endif