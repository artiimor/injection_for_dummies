#include <stdio.h>
#include <stdlib.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "sys/reg.h"
#include "sys/user.h"

#include "ptrace.h"

int main(int argc, char *argv[])
{
       pid_t traced_process;
       struct user_regs_struct oldregs, regs;
       long ins;
       int len = 41;
       char insertcode[] =
           "\xeb\x15\x5e\xb8\x04\x00\x00\x00\xbb\x02\x00\x00\x00\x89\xf1\xba\x0c\x00\x00\x00\xcd\x80\xcc\xe8\xe6\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x0a\x00";
       char backup[len];
       long addr;
       if (argc != 2)
       {
              printf("Usage: %s <pid to be traced>\n",
                     argv[0]);
              exit(1);
       }
       traced_process = atoi(argv[1]);
       printf("PID: %d\n",traced_process);
       
       /*ATTATCH PROCESS*/
       if (ptrace(PTRACE_ATTACH, traced_process,
                  NULL, NULL) == -1)
       {
              printf("[ERROR] something went wrong when attatching\n");
              return -1;
       }
       wait(NULL);

       /*KIDNAP REGISTERS*/
       if (ptrace(PTRACE_GETREGS, traced_process,
                  NULL, &regs) == -1)
       {
              printf("[ERROR] something went wrong trying to get the registers\n");
              return -1;
       }

       addr = freespaceaddr(traced_process);
       
       /*Little backup*/
       getdata(traced_process, addr, backup, len);

       /*Inject evil stuff*/
       putdata(traced_process, addr, insertcode, len);

       /*another little backup*/
       memcpy(&oldregs, &regs, sizeof(regs));

       /*instruction pointer where we injected the code*/
       regs.rip = addr;

       /*new regs with instruction pointer in addr*/
       ptrace(PTRACE_SETREGS, traced_process,
              NULL, &regs);
       ptrace(PTRACE_CONT, traced_process,
              NULL, NULL);
       wait(NULL);
       printf("The process stopped, Putting back "
              "the original instructions\n");

       /*Restore original information*/
       putdata(traced_process, addr, backup, len);
       ptrace(PTRACE_SETREGS, traced_process,
              NULL, &oldregs);
       printf("Letting it continue with "
              "original flow\n");

       /*Detach and end it*/
       ptrace(PTRACE_DETACH, traced_process,
              NULL, NULL);
       return 0;
}
