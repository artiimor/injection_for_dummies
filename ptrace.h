#ifndef __PTRACE_H
#define __PTRACE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <string.h>

struct mem_map_entry
{
    void *addr;
    size_t size;
    uint8_t perms;
    char *pathname;
};

#define mem_map_foreach(ents, ptr) \
    for ((ptr) = (ents); (ptr) < (ents) + mem_map_length(ents); ++(ptr))

#define mem_map_length(ents) *(((uint32_t *)ents) - 1)

#define MEM_PERM_READ (1 << 2)
#define MEM_PERM_WRITE (1 << 1)
#define MEM_PERM_EXEC (1 << 0)

void getdata(pid_t child, long addr,
             char *str, int len);

void putdata(pid_t child, long addr,
             char *str, int len);

long freespaceaddr(pid_t pid);

int ptrace_writemem(pid_t pid, void *addr, void *src, size_t n);

int ptrace_readmem(pid_t pid, void *addr, void *buf, size_t n);

int mommy_am_i_inside_a_SO(pid_t pid);

#endif