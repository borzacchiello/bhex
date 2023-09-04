#ifndef TEMPLATE_ZIP_H
#define TEMPLATE_ZIP_H

typedef struct __attribute__((__packed__)) ZipHeader {
    int   signatute;
    short version;
    short bit_flag;
    short compression_method;
    short time;
    short date;
    int   crc;
    int   compressed_size;
    int   uncompressed_size;
    short name_length;
    short extra_field_length;
} ZipHeader;

typedef struct TarHeader {
    char          name[100];
    char          mode[8];
    char          uid[8];
    char          gid[8];
    char          size[12];
    char          mtime[12];
    char          chksum[8];
    char          typeflag;
    char          linkname[100];
    char          magic[6];
    char          version[2];
    char          uname[32];
    char          gname[32];
    char          devmajor[8];
    char          devminor[8];
    char          prefix[155];
    unsigned char padding[12];
} TarHeader;

#endif
