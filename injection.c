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
       int check_SO;

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
       ptrace_readmem(traced_process, addr, backup, len);

       printf("DATA BEFORE INSERT (ONLY FIRST WORD): ");
       printf("%lx\n", ptrace(PTRACE_PEEKDATA, traced_process,
                              addr, NULL));

       printf("RIP at the begining: %llx\n\n", regs.rip);

       /*******************************************/
       /*************Some comprobations************/
       /*******************************************/

       printf("Checking if i am inside a SO\n");

       check_SO = mommy_am_i_inside_a_SO(traced_process);

       if (check_SO == 1)
       {
              printf("Yes, i am certainly a SO. I'm sotty :(");
              return -1;
       }

       printf("So, i am not in a SO boi\n\n");

       /*******************************************/
       /*************Inject evil stuff*************/
       /*******************************************/

       ptrace_writemem(traced_process, addr, insertcode, len);

       printf("DATA AFTER INSERTION (ONLY FIRST WORD):\n");
       printf("%lx\n", ptrace(PTRACE_PEEKDATA, traced_process,
                              addr, NULL));

       /*******************************************/
       /***********another little backup***********/
       /*******************************************/
       memcpy(&oldregs, &regs, sizeof(regs));

       /*look the instruction pointer*/
       printf("backup RIP: %llx\n", oldregs.rip);

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
       /*****Restore the original instructions*****/
       /*******************************************/
       ptrace_writemem(traced_process, addr, backup, len);

       printf("DATA AFTER RESTORING (ONLY FIRST WORD):\n");
       printf("%lx\n", ptrace(PTRACE_PEEKDATA, traced_process,
                              addr, NULL));

       /*******************************************/
       /*********Restore original registers********/
       /*******************************************/
       ptrace(PTRACE_SETREGS, traced_process,
              NULL, &oldregs);

       /*******************************************/
       /************Just for comprobation**********/
       /*******************************************/

       if (ptrace(PTRACE_GETREGS, traced_process,
                  NULL, &regs) == -1)
       {
              printf("[ERROR] something went wrong trying to get the registers\n");
              return -1;
       }

       printf("RIP restored: %llx\n", regs.rip);

       /*******************************************/
       /*************Detach and end it*************/
       /*******************************************/
       ptrace(PTRACE_DETACH, traced_process,
              NULL, NULL);

       printf("\n\nLetting it continue with "
              "original flow\n");

       return 0;
}
