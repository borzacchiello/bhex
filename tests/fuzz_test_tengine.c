#include "../bhengine/interpreter.h"
#include "../bhengine/scope.h"
#include "filebuffer.h"

#include <display.h>
#include <string.h>
#include <log.h>

#define MAX_SIZE 10000

char input_copy[MAX_SIZE + 1];

static void log_cb(const char* msg) { return; }

FileBuffer* fb;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    fb = filebuffer_create("/bin/true", 1);
    if (!fb)
        return 1;

    register_log_callback(log_cb);
    display_set_print_callback((void (*)(const char*, ...))log_cb);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    if (Size > MAX_SIZE)
        return 1;
    memcpy(input_copy, Data, Size);

    Scope* scope = bhengine_interpreter_run_on_string(fb, input_copy);
    if (scope)
        Scope_free(scope);
    return 0;
}
