#include "pch.h"
#include "tools.h"


void usage(char* argv[])
{
    printf("syntax: %s <interface>\n", argv[0]);
    printf("sample: %s wlp45s0\n", argv[0]);
}


bool parse(Param* param, int argc, char* argv[])
{
    if (argc != 2) {
        usage(argv);
        return false;
    }
    param->dev_ = argv[1];
    return true;
}


void dump(void* p, size_t n)
{
    uint8_t* u8 = static_cast<uint8_t*>(p);
    size_t i = 0;
    while (true) {
        printf("%02X ", *u8++);
        if (++i >= n) break;
        if (i % 8 == 0) printf(" ");
        if (i % 16 == 0) printf("\n");
    }
    printf("\n");
}
