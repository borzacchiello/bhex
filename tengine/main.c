#include "tengine.h"

#include "../filebuffer.h"
#include "../log.h"

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

    TEngine e;
    TEngine_init(&e);

    if (TEngine_process_file(&e, fb, stdin) != 0)
        goto end;

    printf("\n\n");
    TEngine_pp(&e);

end:
    TEngine_deinit(&e);
    return 0;
}
