cmake_minimum_required(VERSION 3.19)

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0075 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0148 OLD)

project(bhex)

option(ASAN "Compile with asan (only for debug builds)" OFF)
option(ENABLE_CAPSTONE "Enable Capstone (disas command)" OFF)
option(ENABLE_KEYSTONE "Enable Keystone (assemble command)" OFF)
option(ENABLE_TESTS "Compile test binary" OFF)
option(STATIC_BUILD "Statically link libc" OFF)

set(CMAKE_C_STANDARD 99)

include_directories("${CMAKE_SOURCE_DIR}/common")

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
    add_subdirectory(keystone EXCLUDE_FROM_ALL)

    include_directories("${CMAKE_SOURCE_DIR}/keystone/include")
else()
    add_compile_definitions(DISABLE_KEYSTONE)
endif()

set(common_src
    common/alloc.c
    common/crc.c
    common/dlist.c
    common/ll.c
    common/log.c
    common/map.c
    common/strbuilder.c
    common/display.c
    common/filebuffer.c
    common/util/byte_to_num.c
    common/util/byte_to_str.c
    common/util/endian.c
    common/util/print.c
    common/util/str.c
    common/util/math.c
    common/hash/md5.c)

set(command_src
    cmd/cmd_arg_handler.c
    cmd/cmd.c
    cmd/cmd_crc.c
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
    cmd/cmd_import.c
    cmd/cmd_entropy.c
    cmd/cmd_interactive.c
    cmd/tui.c)

set(tengine_src
    tengine/ast.c
    tengine/builtin.c
    tengine/scope.c
    tengine/lexer.c
    tengine/parser.c
    tengine/tengine.c
    tengine/value.c)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall -ffunction-sections")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -ffunction-sections")
set(CMAKE_LINKER_FLAGS_RELEASE "${CMAKE_LINKER_FLAGS_RELEASE} -Wl,--gc-sections")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -Wall")

if(ASAN)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

if (ENABLE_TESTS)
    add_executable(bhex_tests
        ${common_src}
        ${tengine_src}
        ${command_src}
        parser.c
        tests/dummy_filebuffer.c
        ${CMAKE_SOURCE_DIR}/tests/main.c)

    add_custom_target(
            always_run_target ALL
            DEPENDS ${CMAKE_SOURCE_DIR}/tests/main.c)

    add_custom_command(
            OUTPUT  ${CMAKE_SOURCE_DIR}/tests/main.c
            COMMAND python ${CMAKE_SOURCE_DIR}/tests/gen_tests.py)
endif()

# Main executable
add_executable(bhex
    ${common_src}
    ${command_src}
    ${tengine_src}
    linenoise/linenoise.c
    parser.c
    completion.c
    main.c)

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

install (TARGETS bhex RUNTIME DESTINATION bin)
install (DIRECTORY templates/
        DESTINATION share/bhex/templates
        FILES_MATCHING PATTERN "*.bhe")
