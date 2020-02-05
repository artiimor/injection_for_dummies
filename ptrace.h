#ifndef __PTRACE_H
#define __PTRACE_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <string.h>

/**
 * struct which contains a map_entry. It has
 * 
 * The memory address
 * The size of the memory region mapped
 * the permission
 * the path of the memory
 */
struct mem_map_entry
{
  void *addr;
  size_t size;
  uint8_t perms;
  char *pathname;
};

/* For iterate a mem_map_entry, because we don't use a normal array,
  you can notice just by seeing get_process_memory function :) */
#define mem_map_foreach(ents, ptr) \
  for ((ptr) = (ents); (ptr) < (ents) + mem_map_length(ents); ++(ptr))

/* Lenght of a mem_map_entry, for out special loop */
#define mem_map_length(ents) *(((uint32_t *)ents) - 1)

/* Definition of permissions */
#define MEM_PERM_READ (1 << 2)
#define MEM_PERM_WRITE (1 << 1)
#define MEM_PERM_EXEC (1 << 0)

/**
 * gives you a free space address of a process, ideal for injecting and not change the process
 * 
 * @param pid pid of the process
 * 
 * @return the free space address
 */
long freespaceaddr(pid_t pid);

/**
 * allows to write in a process memory.
 * 
 * @param pid pid of the process we want to write inside
 * @param addr address in which we are going to write (must be of the process we are injecting)
 * @param src code we are goint to write
 * @param n size of the src
 * 
 * @return number of bytes written of -1 if something went wrong
 */
int ptrace_writemem(pid_t pid, void *addr, void *src, size_t n);

/**
 * allows to read from a process memory.
 * 
 * @param pid pid of the process we want to read from
 * @param addr address we are going to read
 * @param buf is where the read code is going to be stored
 * @param n how much we want to read
 * 
 * @return number of bytes we just read oe r1 if something went wrong
 */

int ptrace_readmem(pid_t pid, void *addr, void *buf, size_t n);

/*Copied from narhem, he did a good work, check his stuff*/
/************https://github.com/narhen/procjack***********/
/**
 * Check if we are in a SO
 * 
 * @param pid pid of the process we are checking
 * 
 * @return 1 if we are in a SO, 0 if we are not
 */
int mommy_am_i_inside_a_SO(pid_t pid);

void print_memory_map(pid_t pid);

#endif