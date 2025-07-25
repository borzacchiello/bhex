#include "formatter.h"
#include "formatter_term.h"

#include <alloc.h>
#include <log.h>

Formatter* fmt_new(fmt_t type)
{
    Formatter* obj = bhex_calloc(sizeof(Formatter));

    switch (type) {
        case FMT_TERM:
            fmt_term_new(obj);
            break;
        default:
            bhex_free(obj);
            error("no such formatter type");
            return NULL;
    }
    return obj;
}

void fmt_dispose(Formatter* fmt)
{
    fmt->fmt_dispose(fmt->this);
    bhex_free(fmt);
}
