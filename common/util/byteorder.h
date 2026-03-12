// Copyright (c) 2022-2026, bageyelet

#ifndef BYTEORDER_H
#define BYTEORDER_H

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

#define cpu_to_be16(v) (((v) << 8) | ((v) >> 8))
#define cpu_to_be32(v)                                                         \
    (((v) >> 24) | (((v) >> 8) & 0xff00) | (((v) << 8) & 0xff0000) |           \
     ((v) << 24))
#define be16_to_cpu(v) cpu_to_be16(v)
#define be32_to_cpu(v) cpu_to_be32(v)

#else

#define cpu_to_be16(v) (v)
#define cpu_to_be32(v) (v)
#define be16_to_cpu(v) (v)
#define be32_to_cpu(v) (v)

#endif

#endif
