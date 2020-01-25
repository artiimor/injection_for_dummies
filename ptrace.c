#include <stdio.h>
#include <stdlib.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/reg.h>
#include "sys/user.h"

#include "ptrace.h"

const int long_size = sizeof(long);

void getdata(pid_t child, long addr,
             char *str, int len)
{
    char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    } data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while (i < j)
    {
        data.val = ptrace(PTRACE_PEEKDATA, child,
                          addr + i * 4, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if (j != 0)
    {
        data.val = ptrace(PTRACE_PEEKDATA, child,
                          addr + i * 4, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}
void putdata(pid_t child, long addr,
             char *str, int len)
{
    char *laddr;
    int i, j;
    union u {
        long val;
        char chars[long_size];
    } data;
    i = 0;
    j = len / long_size;
    laddr = str;

    while (i < j)
    {
        printf("ME CAGO EN LA OSTIA PUTA1\n");
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, str[i]);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if (j != 0)
    {
        printf("ME CAGO EN LA OSTIA PUTA2\n");
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child,
               addr + i * 4, str[i]);
    }
}

long freespaceaddr(pid_t pid)
{
    FILE *fp;
    char filename[30];
    char line[85];
    long addr;
    char str[20];
    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        printf("ERROR in freespaceaddr\n");
        exit(1);
    }

    while (fgets(line, 85, fp) != NULL)
    {
        sscanf(line, "%lx-%*lx %*s %*s %s", &addr,
               str, str, str, str);
        if (strcmp(str, "00:00") == 0)
            break;
    }
    fclose(fp);
    return addr;
}

static long write_word(pid_t pid, void *addr, uint32_t word)
{
    return ptrace(PTRACE_POKETEXT, pid, addr, (void *)(uint64_t)word);
}

static uint32_t read_word(pid_t pid, void *addr)
{
    uint32_t ret = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
    if (ret == 0xffffffff && errno)
    {
        perror("peekdata");
    }
    return ret;
}

int ptrace_writemem(pid_t pid, void *addr, void *src, size_t n)
{
    size_t i;
    uint32_t word;
    int wordsize = sizeof(word);
    uint64_t curaddr = (uint64_t)addr;
    uint8_t *srcptr = src;

    for (i = 0; i + wordsize <= n; i += wordsize, curaddr += wordsize, srcptr += wordsize)
    {
        if (write_word(pid, (void *)curaddr, *((uint32_t *)srcptr)) == -1)
            return -1;
    }

    if (i < n)
    {
        word = read_word(pid, (void *)curaddr);
        memcpy(&word, srcptr, n - i);
        if (write_word(pid, (void *)curaddr, *((uint32_t *)srcptr)) == -1)
            return -1;
    }

    return (int)n;
}

int ptrace_readmem(pid_t pid, void *addr, void *buf, size_t n)
{
    size_t i;
    uint32_t word;
    int wordsize = sizeof(word);
    uint64_t curaddr = (uint64_t)addr;
    uint8_t *bufptr = buf;

    for (i = 0; i + wordsize <= n; i += wordsize, curaddr += wordsize)
    {
        word = read_word(pid, (void *)curaddr);
        memcpy(bufptr + i, &word, wordsize);
    }

    if (i < n)
    {
        word = read_word(pid, (void *)curaddr);
        memcpy(bufptr + i, &word, n - i);
    }

    return (int)n;
}

/*********************************************************/
/*********************Some memory stuff*******************/
/*Copied from narhem, he did a good work, check his stuff*/
/************https://github.com/narhen/procjack***********/
/*********************************************************/

/**
 * It allows to free a mem_map_entry struct, it only iterates a mem_map_entry
 * freeing all the stored memory
 */
void mem_maps_free(struct mem_map_entry *ent)
{
    uint32_t *num, i;
    num = ((uint32_t *)ent) - 1;

    for (i = 0; i < *num; i++)
        free(ent[i].pathname);
    free(num);
}

/*
 * So what are we exactly parsing?
 * Well, str contains the /proc/pid/maps file content.
 * 
 * What the hell is here?
 * Well, there are some rows, each row contains:
 *  
 *  0.- ADDRESS:
 *      Here we have the starting and ending address of the region
 *      in the process address space
 *  
 *  1.- PERMISSIONS:
 *      In summary read, write, execute and be shared
 * 
 *  2.- OFFSET:
 *      If the region was mapped from a file (using mmap),
 *      this is the offset where the mapping begins
 * 
 *  3.- DEVICE:
 *      If the region was mapped from a file, 
 *      this is the major and minor device number (in hex) where 
 *      the file lives
 * 
 *  4.- INODE: 
 *      If the region was mapped from a file, this is the file number
 * 
 *  5.- PATHNAME:
 *      If the region was mapped from a file, this is the name of the file.
 * 
 *  so, we only are going to be using the address, permissions and pathname,
 *  and it will be stored in our mem_map_entry struct
 */

static void parse_maps_ent(char *str, struct mem_map_entry *ent)
{

    int i;
    uint64_t start, end;
    char *str2, *token, *saveptr, *tmp;

    /* in this loop we go to one row of the /proc/pid/maps and
       obtain the information described previously */
    for (i = 0, str2 = str;; str2 = NULL, ++i)
    {

        token = strtok_r(str2, " ", &saveptr);
        if (!token)
            break;

        switch (i)
        {
        /*O.- ADDRESS*/
        case 0:
            tmp = strchr(token, '-');
            *tmp++ = 0;

            start = strtoul(token, NULL, 16);
            end = strtoul(tmp, NULL, 16);
            *--tmp = '-';

            ent->addr = (void *)start;
            ent->size = end - start;
            break;
        /*1.- PERMISSIONS*/
        case 1:
            if (token[0] == 'r')
                ent->perms |= MEM_PERM_READ;
            if (token[1] == 'w')
                ent->perms |= MEM_PERM_WRITE;
            if (token[2] == 'x')
                ent->perms |= MEM_PERM_EXEC;
            break;
        /*5.- PATHNAME*/
        case 5:
            ent->pathname = strdup(token);
            break;
        }
    }
}

/*Obtain the process memory*/
/*
 * What is exactly the process memory?
 * Well, we are going to read from /proc/pid/map,
 * we are going to parse all this memory and store it in a uint32_t
 * array and then cast this array into a mem_map_entry, so we can return it.
 * 
 * in summary and making it easy, we parse all the /proc/pid/maps file into a
 * mem_map_entry, in a cool way
 */

struct mem_map_entry *get_process_memory(pid_t pid)
{
    char buf[1024];
    uint32_t *num;
    int num_ents = 20, i;
    struct mem_map_entry *ret, *current;
    FILE *fp;

    /*Of course, we are reading from /proc/pid/maps*/
    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (!fp)
        return NULL;

    /*save memory for the mem_map_entry of the process*/
    num = calloc(1, sizeof(struct mem_map_entry) * num_ents + sizeof(uint32_t));
    ret = current = (struct mem_map_entry *)((uint32_t *)num + 1);

    /*loop while we can still be reading from the file*/
    for (i = 0; fgets(buf, sizeof(buf), fp); ++i, ++current)
    {
        if (i >= num_ents)
        {
            num_ents += 10;
            num = realloc(num, num_ents * sizeof(struct mem_map_entry) + sizeof(uint32_t));
            ret = (struct mem_map_entry *)((uint32_t *)num + 1);
            current = ret + i;
        }

        if (strchr(buf, '\n'))
            *strchr(buf, '\n') = 0;

        /*Parse it*/
        parse_maps_ent(buf, current);
    }

    *num = i;
    return ret;
}

/*Check if we are inside a SO*/
/*
 * This is our last and easier function, here we 
 * get the process memory and then iterates for every entry.
 * 
 * We also have the ìnstruction pointer of the process, so when we are in
 * the same place that the instruction pointer we check if the pathname
 * contains /lic or /usr/lib. 
 * 
 * That's all folks.
 */

int mommy_am_i_inside_a_SO(pid_t pid)
{
    int well_am_i = 0;
    struct mem_map_entry *mem_map, *ptr;
    struct user_regs_struct regs;

    /*Get the process memory*/
    mem_map = get_process_memory(pid);

    if (ptrace(PTRACE_GETREGS, pid,
               NULL, &regs) == -1)
    {
        printf("[ERROR] something went wrong trying to get the registers\n");
        return -1;
    }

    /*iterate the process memory*/
    mem_map_foreach(mem_map, ptr)
    {
        uint64_t page_addr = (uint64_t)ptr->addr;
        if (regs.rip < page_addr || regs.rip >= page_addr + ptr->size)
            continue;

        /*We are in a SO if we are inside /lib of /usr/lic directory :)*/
        if (ptr->pathname != NULL)
        {
            well_am_i = !strncmp(ptr->pathname, "/lib", 4) || !strncmp(ptr->pathname, "/usr/lib", 8);
        }
        break;
    }

    mem_maps_free(mem_map);
    return well_am_i;
}
