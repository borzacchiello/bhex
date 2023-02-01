cmake_minimum_required(VERSION 3.19)

project(borzNES)

option(ASAN "Compile with asan (only for debug builds)" OFF)

set(CMAKE_C_STANDARD 99)

set(src
    linenoise/linenoise.c

    cmd/cmd.c
    cmd/hash/md5.c
    cmd/templates/template.c
    cmd/util/byte_to_str.c
    cmd/util/byte_to_num.c
    cmd/util/endian.c
    cmd/util/str.c
    cmd/cmd_template.c
    cmd/cmd_search.c
    cmd/cmd_strings.c
    cmd/cmd_info.c
    cmd/cmd_write.c
    cmd/cmd_delete.c
    cmd/cmd_print.c
    cmd/cmd_seek.c
    cmd/cmd_undo.c
    cmd/cmd_commit.c

    alloc.c
    filebuffer.c
    ll.c
    log.c
    parser.c
    main.c)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall")

if(ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

# Tests
add_executable(test_ll
    ll.c
    alloc.c
    log.c
    tests/test_ll.c)

add_executable(test_parser
    ll.c
    alloc.c
    log.c
    parser.c
    tests/test_parser.c)

# Main executable
add_executable(bhex
    ${src})
