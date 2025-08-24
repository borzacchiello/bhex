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
option(ENABLE_FUZZ_TESTS "Compile fizz test binaries" OFF)
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
    common/cmdline_parser.c
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

set(bhengine_src
    bhengine/ast.c
    bhengine/builtin.c
    bhengine/scope.c
    bhengine/lexer.c
    bhengine/parser.c
    bhengine/interpreter.c
    bhengine/vm.c
    bhengine/value.c
    bhengine/formatter.c
    bhengine/formatter_term.c
    bhengine/formatter_xml.c)

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
    add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/tests/main.c
            COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_SOURCE_DIR}/tests/main.c
            COMMAND python ${CMAKE_SOURCE_DIR}/tests/gen_tests.py
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            COMMENT "Generating test main")

    add_custom_target(gen_test_main ALL
        DEPENDS ${CMAKE_SOURCE_DIR}/tests/main.c)

    add_custom_target(copy_templates_to_build ALL
            COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/templates
            ${CMAKE_CURRENT_BINARY_DIR}/templates
            COMMENT "Copying templates to build")

    add_executable(bhex_tests
        ${common_src}
        ${bhengine_src}
        ${command_src}
        tests/dummy_filebuffer.c
        ${CMAKE_SOURCE_DIR}/tests/main.c)

    add_dependencies(bhex_tests gen_test_main)
    add_dependencies(bhex_tests copy_templates_to_build)
endif()

if (ENABLE_FUZZ_TESTS)
    if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
        add_custom_target(copy_corpus ALL
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_SOURCE_DIR}/templates
                ${CMAKE_CURRENT_BINARY_DIR}/corpus
                COMMENT "Copying templates to corpus")

        add_executable(bhex_fuzz_tengine
            ${common_src}
            ${bhengine_src}
            ${CMAKE_SOURCE_DIR}/tests/fuzz_test_tengine.c)

        target_compile_options(bhex_fuzz_tengine PRIVATE -fsanitize=address,fuzzer,undefined)
        target_link_libraries(bhex_fuzz_tengine PRIVATE -fsanitize=address,fuzzer,undefined)
        add_dependencies(bhex_fuzz_tengine copy_corpus)
    else()
        message(FATAL_ERROR "You must use CLANG to compile fuzz tests")
    endif()
endif()

# Main executable
add_executable(bhex
    ${common_src}
    ${command_src}
    ${bhengine_src}
    linenoise/linenoise.c
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

install(TARGETS bhex RUNTIME DESTINATION bin)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/bin/bdiff DESTINATION bin)
install(PROGRAMS ${CMAKE_SOURCE_DIR}/bin/bhengine DESTINATION bin)
install(DIRECTORY templates/
        DESTINATION share/bhex/templates
        FILES_MATCHING PATTERN "*.bhe")
