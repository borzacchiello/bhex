#include "tengine.h"

#include <filebuffer.h>
#include <log.h>

#include <stdlib.h>

static void usage(const char* prog)
{
    printf("USAGE: %s <file>\n", prog);
    exit(1);
}

int main(int argc, char** argv)
{
    if (argc < 2)
        usage(argv[0]);

    const char* bin = argv[1];
    FileBuffer* fb  = filebuffer_create(bin, 1);
    if (fb == NULL) {
        error("invalid binary");
        usage(argv[0]);
    }

    int r = TEngine_process_file(fb, stdin);
    filebuffer_destroy(fb);
    return r;
}
