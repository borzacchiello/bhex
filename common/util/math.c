#include <defs.h>

#include "math.h"

float _log2(float val)
{
    union {
        float val;
        s32_t x;
    } u                  = {val};
    register float log_2 = (float)(((u.x >> 23) & 255) - 128);
    u.x &= ~(255 << 23);
    u.x += 127 << 23;
    log_2 += ((-0.3358287811f) * u.val + 2.0f) * u.val - 0.65871759316667f;
    return (log_2);
}
