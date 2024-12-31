cmake_minimum_required(VERSION 3.19)

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0075 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0148 OLD)

project(bhex)

option(ASAN "Compile with asan (only for debug builds)" OFF)
option(ENABLE_CAPSTONE "Enable Capstone (disas command)" OFF)
option(ENABLE_KEYSTONE "Enable Keystone (assemble command)" OFF)
option(STATIC_BUILD "Statically link libc" OFF)

set(CMAKE_C_STANDARD 99)

if (ENABLE_CAPSTONE)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_LIBS_ONLY ON)

    set(CAPSTONE_X86_ATT_DISABLE ON)
    set(CAPSTONE_PPC_SUPPORT OFF)
    set(CAPSTONE_SPARC_SUPPORT OFF)
    set(CAPSTONE_SYSZ_SUPPORT OFF)
    set(CAPSTONE_XCORE_SUPPORT OFF)
    set(CAPSTONE_M68K_SUPPORT OFF)
    set(CAPSTONE_TMS320C64X_SUPPORT OFF)
    set(CAPSTONE_M680X_SUPPORT OFF)
    set(CAPSTONE_EVM_SUPPORT OFF)
    set(CAPSTONE_WASM_SUPPORT OFF)
    set(CAPSTONE_MOS65XX_SUPPORT OFF)
    set(CAPSTONE_BPF_SUPPORT OFF)
    set(CAPSTONE_RISCV_SUPPORT OFF)
    set(CAPSTONE_OSXKERNEL_SUPPORT OFF)
    add_subdirectory(capstone)

    include_directories("${CMAKE_SOURCE_DIR}/capstone/include")
else()
    add_compile_definitions(DISABLE_CAPSTONE)
endif()

if (ENABLE_KEYSTONE)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_LIBS_ONLY ON)
    set(LLVM_TARGETS_TO_BUILD "AArch64, ARM, Mips, X86")
    add_subdirectory(keystone)

    include_directories("${CMAKE_SOURCE_DIR}/keystone/include")
else()
    add_compile_definitions(DISABLE_KEYSTONE)
endif()

set(src
    linenoise/linenoise.c

    cmd/cmd.c
    cmd/hash/md5.c
    cmd/templates/template.c
    cmd/util/byte_to_str.c
    cmd/util/byte_to_num.c
    cmd/util/endian.c
    cmd/util/str.c
    cmd/util/print.c
    cmd/cmd_template.c
    cmd/cmd_search.c
    cmd/cmd_strings.c
    cmd/cmd_info.c
    cmd/cmd_write.c
    cmd/cmd_delete.c
    cmd/cmd_print.c
    cmd/cmd_disas.c
    cmd/cmd_assemble.c
    cmd/cmd_seek.c
    cmd/cmd_undo.c
    cmd/cmd_commit.c
    cmd/cmd_diff.c
    cmd/cmd_export.c

    alloc.c
    dlist.c
    filebuffer.c
    tui.c
    ll.c
    log.c
    parser.c
    main.c)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall")

if(ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,undefined")
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

if (STATIC_BUILD)
    set_target_properties(bhex PROPERTIES LINK_SEARCH_START_STATIC ON)
    set_target_properties(bhex PROPERTIES LINK_SEARCH_END_STATIC ON)
    target_link_options(bhex PRIVATE -static-libgcc -static)
endif()

if (ENABLE_CAPSTONE)
    target_link_libraries(bhex LINK_PUBLIC capstone)
endif()
if (ENABLE_KEYSTONE)
    target_link_libraries(bhex LINK_PUBLIC keystone)
endif()

