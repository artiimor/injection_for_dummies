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

       char insertcode[] = "\xB8\x10\x00\x00\x00\xc3";
       char aux[] = "asd";
       int len = sizeof(insertcode);
       char backup[len];
       char pruebesita[len];
       long addr;


       if (argc != 2)
       {
              printf("Usage: %s <pid to be traced>\n",
                     argv[0]);
              exit(1);
       }
       traced_process = atoi(argv[1]);
       printf("PID: %d\n", traced_process);

       /*******************************************/
       /**************ATTATCH PROCESS**************/
       /*******************************************/
       if (ptrace(PTRACE_ATTACH, traced_process,
                  NULL, NULL) == -1)
       {
              printf("[ERROR] something went wrong when attatching\n");
              return -1;
       }
       wait(NULL);

       /*******************************************/
       /**************KIDNAP REGISTERS*************/
       /*******************************************/
       if (ptrace(PTRACE_GETREGS, traced_process,
                  NULL, &regs) == -1)
       {
              printf("[ERROR] something went wrong trying to get the registers\n");
              return -1;
       }

       addr = freespaceaddr(traced_process);

       /*******************************************/
       /***************Little backup***************/
       /*******************************************/
       getdata(traced_process, addr, backup, len);
       
       printf("DATA BEFORE INSERT (ONLY FIRST WORD):\n");
       printf("%x\n", ptrace(PTRACE_PEEKDATA, traced_process,
                          addr, NULL));


       /*******************************************/
       /*************Inject evil stuff*************/
       /*******************************************/
       ptrace_writemem(traced_process, addr, insertcode, len);

       printf("DATA AFTER INSERTION (ONLY FIRST WORD):\n");
       printf("%x\n", ptrace(PTRACE_PEEKDATA, traced_process,
                          addr, NULL));


       /*******************************************/
       /***********another little backup***********/
       /*******************************************/
       memcpy(&oldregs, &regs, sizeof(regs));

       /*look the instruction pointer*/
       printf("RIP in oldregs: %llx\n", oldregs.rip);
       printf("RIP at the begining: %llx\n", regs.rip);

       /*instruction pointer where we injected the code*/
       regs.rip = addr;

       printf("RIP with our code position :) %llx\n\n\n", regs.rip);
       

       /*new regs with instruction pointer in addr*/
       ptrace(PTRACE_SETREGS, traced_process,
              NULL, &regs);


       /*******************************************/
       /************execute our shit***************/
       /*******************************************/
       ptrace(PTRACE_CONT, traced_process,
              NULL, NULL);
       wait(NULL);
       
       printf("The process stopped, Putting back "
              "the original instructions\n");       

       /*******************************************/
       /*********Restore original registers********/
       /*******************************************/
       ptrace(PTRACE_SETREGS, traced_process,
              NULL, &oldregs);
       printf("Letting it continue with "
              "original flow\n");

       /*******************************************/
       /*************Detach and end it*************/
       /*******************************************/
       ptrace(PTRACE_DETACH, traced_process,
              NULL, NULL);
       return 0;
}
