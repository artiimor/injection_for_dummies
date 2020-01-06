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

	for (i = 0; i + wordsize <= n; i += wordsize, curaddr += wordsize) {
		word = read_word(pid, (void *)curaddr);
		memcpy(bufptr + i, &word, wordsize);
	}

	if (i < n) {
		word = read_word(pid, (void *)curaddr);
		memcpy(bufptr + i, &word, n - i);
	}

	return (int)n;
}

