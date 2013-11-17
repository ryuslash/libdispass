#include <stdio.h>
#include <stdlib.h>

#include "dispass.h"

int main(int argc, char *argv[])
{
    char *test1, *test2, *test3, *test4;

    test1 = dispass1("test", "qqqqqqqq", 30, 0);
    test2 = dispass1("test2", "qqqqqqqq", 50, 0);
    test3 = dispass2("test", "qqqqqqqq", 30, 1);
    test4 = dispass2("test2", "qqqqqqqq", 50, 10);

    printf("%s\n", test1);
    printf("%s\n", test2);
    printf("%s\n", test3);
    printf("%s\n", test4);

    free(test1);
    free(test2);
    free(test3);
    free(test4);

    return 0;
}
