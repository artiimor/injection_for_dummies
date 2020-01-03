/*Print from 0 to 9 in different lines*/
#include <stdio.h>

int main()
{
    int i;
    for (i = 0; i < 100; ++i)
    {
        printf("My counter: %d\n", i);
        sleep(2);
    }
    return 0;
}
